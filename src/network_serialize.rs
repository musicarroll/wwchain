#[cfg(feature = "sync")]
use std::io::{Read, Write};
#[cfg(feature = "sync")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "sync")]
use std::thread;

#[cfg(not(feature = "sync"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(feature = "sync"))]
use tokio::net::{TcpListener, TcpStream};
#[cfg(not(feature = "sync"))]
use tokio::task;

use crate::block::Block;
use crate::blockchain::{Blockchain, DIFFICULTY_PREFIX};
use crate::peer::PeerList;
use crate::transaction::Transaction;

/// Current protocol version understood by this node
pub const PROTOCOL_VERSION: u8 = 1;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    Text(String),
    ChainRequest(String),      // requesting node's address
    ChainResponse(Vec<Block>), // the entire chain
    Handshake(String),         // peer introduction
    PeerList(Vec<String>),     // returned during handshake
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionedMessage {
    pub version: u8,
    pub payload: NetworkMessage,
}

impl VersionedMessage {
    pub fn new(payload: NetworkMessage) -> Self {
        VersionedMessage {
            version: PROTOCOL_VERSION,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match serde_json::to_vec(self) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to serialize versioned message: {}", e);
                Vec::new()
            }
        }
    }
}

impl NetworkMessage {
    pub fn serialize(&self) -> Vec<u8> {
        match serde_json::to_vec(self) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to serialize network message: {}", e);
                Vec::new()
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedMessage {
    pub message: VersionedMessage,
    pub signature: String,
    pub pubkey: String,
}

impl SignedMessage {
    pub fn new(message: NetworkMessage, sk: &SecretKey) -> Self {
        let versioned = VersionedMessage::new(message);
        let secp = Secp256k1::new();
        let serialized = serde_json::to_vec(&versioned).expect("serialize");
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let digest = hasher.finalize();
        let msg = Message::from_slice(&digest).expect("32 bytes");
        let sig = secp.sign_ecdsa(&msg, sk);
        let pubkey = PublicKey::from_secret_key(&secp, sk);
        SignedMessage {
            message: versioned,
            signature: hex::encode(sig.serialize_compact()),
            pubkey: hex::encode(pubkey.serialize()),
        }
    }

    pub fn verify(&self) -> bool {
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match Signature::from_compact(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pub_bytes = match hex::decode(&self.pubkey) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pubkey = match PublicKey::from_slice(&pub_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let secp = Secp256k1::verification_only();
        let serialized = self.message.serialize();
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let digest = hasher.finalize();
        let msg = match Message::from_slice(&digest) {
            Ok(m) => m,
            Err(_) => return false,
        };
        secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok()
    }
}

// ---- Chain reconciliation helper ----
pub fn handle_chain_response(local_chain: &mut Blockchain, their_chain: Vec<Block>) {
    if Blockchain::chain_work(&their_chain) > local_chain.total_work() {
        // Validate new chain
        let mut valid = true;
        for i in 1..their_chain.len() {
            let prev = &their_chain[i - 1];
            let curr = &their_chain[i];
            if curr.prev_hash != prev.hash
                || curr.hash != curr.calculate_hash()
                || !curr.hash.starts_with(DIFFICULTY_PREFIX)
            {
                valid = false;
                break;
            }
        }
        if valid {
            if their_chain[0].hash != their_chain[0].calculate_hash()
                || !their_chain[0].hash.starts_with(DIFFICULTY_PREFIX)
            {
                valid = false;
            }
        }
        if valid {
            local_chain.chain = their_chain;
            println!("[RECONCILE] Local chain updated from peer!");
        } else {
            println!("[RECONCILE] Received invalid chain, ignoring.");
        }
    }
}

// ---- Handler expects Arc<Mutex<Blockchain>> and Arc<PeerList> ----
#[cfg(feature = "sync")]
pub fn handle_client_with_chain(
    mut stream: TcpStream,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    my_addr: String,
    sk: Arc<SecretKey>,
) {
    let mut buffer = [0; 4096];
    match stream.read(&mut buffer) {
        Ok(size) => {
            if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer[..size]) {
                if signed.message.version != PROTOCOL_VERSION {
                    eprintln!(
                        "[PROTO] Unsupported protocol version {}",
                        signed.message.version
                    );
                    return;
                }
                if !signed.verify() {
                    eprintln!("[AUTH] Invalid signature from peer");
                    return;
                }
                let msg = signed.message.payload;
                match msg {
                    NetworkMessage::Handshake(addr) => {
                        println!("[SERIALIZED] Received Handshake from {}", addr);
                        peers.add_peer(&addr);
                        let known = peers.all();
                        let resp = SignedMessage::new(NetworkMessage::PeerList(known), &sk);
                        let resp_buf = serde_json::to_vec(&resp).expect("serialize");
                        if let Err(e) = stream.write_all(&resp_buf) {
                            eprintln!("Failed to write handshake response: {}", e);
                        }
                        return;
                    }
                    NetworkMessage::Transaction(tx) => {
                        println!("[SERIALIZED] Received Transaction: {:?}", tx);
                        if !tx.verify() {
                            eprintln!("[SERIALIZED] Invalid transaction signature");
                        } else {
                            // You may wish to add to mempool here
                        }
                    }
                    NetworkMessage::Block(block) => {
                        println!("[SERIALIZED] Received Block: {:?}", block);
                        if !block.transactions.iter().all(|tx| tx.verify()) {
                            eprintln!("[SERIALIZED] Block contains invalid transaction");
                            return;
                        }
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        let local_tip = match chain.chain.last() {
                            Some(b) => b.index,
                            None => {
                                eprintln!("Received block but local chain empty");
                                return;
                            }
                        };
                        if block.index > local_tip {
                            if let Some(sender_addr) = block.sender_addr.clone() {
                                println!(
                                    "[RECONCILE] Attempting to reconcile with block sender: {}",
                                    sender_addr
                                );
                                drop(chain); // unlock before net IO
                                request_chain_and_reconcile(
                                    &sender_addr,
                                    blockchain.clone(),
                                    &my_addr,
                                    &sk,
                                );
                            } else {
                                println!("[RECONCILE] Received block with no sender_addr!");
                            }
                            return;
                        }
                        // Optionally: append if valid and next block
                    }
                    NetworkMessage::ChainRequest(requestor_addr) => {
                        println!("[SERIALIZED] Received ChainRequest from {}", requestor_addr);
                        let chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        let response = NetworkMessage::ChainResponse(chain.chain.clone());
                        let _ = send_message(&requestor_addr, &response, &sk);
                    }
                    NetworkMessage::ChainResponse(their_chain) => {
                        println!(
                            "[SERIALIZED] Received ChainResponse: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    }
                    NetworkMessage::PeerList(list) => {
                        println!("[SERIALIZED] Received PeerList: {:?}", list);
                        peers.merge(&list);
                    }
                    NetworkMessage::Text(s) => println!("[SERIALIZED] Received Text: {}", s),
                }
                let response = b"OK (parsed NetworkMessage)\n";
                if let Err(e) = stream.write_all(response) {
                    eprintln!("Failed to write response: {}", e);
                }
            } else {
                println!(
                    "[SERIALIZED] Received (unparsed): {}",
                    String::from_utf8_lossy(&buffer[..size])
                );
                let response = b"Unrecognized data\n";
                if let Err(e) = stream.write_all(response) {
                    eprintln!("Failed to write response: {}", e);
                }
            }
        }
        Err(e) => eprintln!("Error reading stream: {}", e),
    }
}

#[cfg(not(feature = "sync"))]
pub async fn handle_client_with_chain(
    mut stream: TcpStream,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    my_addr: String,
    sk: Arc<SecretKey>,
) {
    let mut buffer = [0u8; 4096];
    match stream.read(&mut buffer).await {
        Ok(size) => {
            if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer[..size]) {
                if signed.message.version != PROTOCOL_VERSION {
                    eprintln!(
                        "[PROTO] Unsupported protocol version {}",
                        signed.message.version
                    );
                    return;
                }
                if !signed.verify() {
                    eprintln!("[AUTH] Invalid signature from peer");
                    return;
                }
                let msg = signed.message.payload;
                match msg {
                    NetworkMessage::Handshake(addr) => {
                        println!("[SERIALIZED] Received Handshake from {}", addr);
                        peers.add_peer(&addr);
                        let known = peers.all();
                        let resp = SignedMessage::new(NetworkMessage::PeerList(known), &sk);
                        let resp_buf = serde_json::to_vec(&resp).expect("serialize");
                        let _ = stream.write_all(&resp_buf).await;
                        return;
                    }
                    NetworkMessage::Transaction(tx) => {
                        println!("[SERIALIZED] Received Transaction: {:?}", tx);
                        if !tx.verify() {
                            eprintln!("[SERIALIZED] Invalid transaction signature");
                        }
                    }
                    NetworkMessage::Block(block) => {
                        println!("[SERIALIZED] Received Block: {:?}", block);
                        if !block.transactions.iter().all(|tx| tx.verify()) {
                            eprintln!("[SERIALIZED] Block contains invalid transaction");
                            return;
                        }
                        let local_tip = {
                            let chain = match blockchain.lock() {
                                Ok(c) => c,
                                Err(e) => {
                                    eprintln!("Blockchain lock poisoned: {}", e);
                                    e.into_inner()
                                }
                            };
                            match chain.chain.last() {
                                Some(b) => b.index,
                                None => {
                                    eprintln!("Received block but local chain empty");
                                    return;
                                }
                            }
                        };
                        if block.index > local_tip {
                            if let Some(sender_addr) = block.sender_addr.clone() {
                                println!(
                                    "[RECONCILE] Attempting to reconcile with block sender: {}",
                                    sender_addr
                                );
                                request_chain_and_reconcile(
                                    &sender_addr,
                                    blockchain.clone(),
                                    &my_addr,
                                    &sk,
                                )
                                .await;
                            } else {
                                println!("[RECONCILE] Received block with no sender_addr!");
                            }
                            return;
                        }
                    }
                    NetworkMessage::ChainRequest(requestor_addr) => {
                        println!("[SERIALIZED] Received ChainRequest from {}", requestor_addr);
                        let chain_blocks = {
                            let chain = match blockchain.lock() {
                                Ok(c) => c,
                                Err(e) => {
                                    eprintln!("Blockchain lock poisoned: {}", e);
                                    e.into_inner()
                                }
                            };
                            chain.chain.clone()
                        };
                        let response = NetworkMessage::ChainResponse(chain_blocks);
                        let _ = send_message(&requestor_addr, &response, &sk).await;
                    }
                    NetworkMessage::ChainResponse(their_chain) => {
                        println!(
                            "[SERIALIZED] Received ChainResponse: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    }
                    NetworkMessage::PeerList(list) => {
                        println!("[SERIALIZED] Received PeerList: {:?}", list);
                        peers.merge(&list);
                    }
                    NetworkMessage::Text(s) => println!("[SERIALIZED] Received Text: {}", s),
                }
                let response = b"OK (parsed NetworkMessage)\n";
                let _ = stream.write_all(response).await;
            } else {
                println!(
                    "[SERIALIZED] Received (unparsed): {}",
                    String::from_utf8_lossy(&buffer[..size])
                );
                let response = b"Unrecognized data\n";
                let _ = stream.write_all(response).await;
            }
        }
        Err(e) => eprintln!("Error reading stream: {}", e),
    }
}

#[cfg(feature = "sync")]
pub fn start_server_with_chain(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    my_addr: String,
    sk: Arc<SecretKey>,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("[SERIALIZED] Server listening on {}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let bc = blockchain.clone();
                let p = peers.clone();
                let me = my_addr.clone();
                let sk_clone = sk.clone();
                thread::spawn(|| handle_client_with_chain(stream, bc, p, me, sk_clone));
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
    Ok(())
}

#[cfg(not(feature = "sync"))]
pub async fn start_server_with_chain(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    my_addr: String,
    sk: Arc<SecretKey>,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[SERIALIZED] Server listening on {}", addr);
    loop {
        let (stream, _) = listener.accept().await?;
        let bc = blockchain.clone();
        let p = peers.clone();
        let me = my_addr.clone();
        let sk_clone = sk.clone();
        task::spawn(async move {
            handle_client_with_chain(stream, bc, p, me, sk_clone).await;
        });
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(feature = "sync")]
pub fn send_message(addr: &str, msg: &NetworkMessage, sk: &SecretKey) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    let signed = SignedMessage::new(msg.clone(), sk);
    let buf = serde_json::to_vec(&signed)?;
    stream.write_all(&buf)?;
    let mut buffer = [0; 4096];
    let size = stream.read(&mut buffer)?;
    println!(
        "[SERIALIZED] Server responded: {}",
        String::from_utf8_lossy(&buffer[..size])
    );
    Ok(())
}

#[cfg(not(feature = "sync"))]
pub async fn send_message(addr: &str, msg: &NetworkMessage, sk: &SecretKey) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    let signed = SignedMessage::new(msg.clone(), sk);
    let buf = serde_json::to_vec(&signed)?;
    stream.write_all(&buf).await?;
    let mut buffer = [0u8; 4096];
    let size = stream.read(&mut buffer).await?;
    println!(
        "[SERIALIZED] Server responded: {}",
        String::from_utf8_lossy(&buffer[..size])
    );
    Ok(())
}

#[cfg(feature = "sync")]
pub fn broadcast_message(peers: Arc<PeerList>, msg: &NetworkMessage, sk: &SecretKey) {
    for peer_addr in peers.all() {
        if let Err(e) = send_message(&peer_addr, msg, sk) {
            eprintln!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}

#[cfg(not(feature = "sync"))]
pub async fn broadcast_message(peers: Arc<PeerList>, msg: &NetworkMessage, sk: &SecretKey) {
    for peer_addr in peers.all() {
        if let Err(e) = send_message(&peer_addr, msg, sk).await {
            eprintln!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}

/// Perform a handshake with `addr` exchanging peer lists.
#[cfg(feature = "sync")]
pub fn perform_handshake(addr: &str, my_addr: &str, peers: Arc<PeerList>, sk: &SecretKey) {
    if let Ok(mut stream) = TcpStream::connect(addr) {
        let signed = SignedMessage::new(NetworkMessage::Handshake(my_addr.to_string()), sk);
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        if stream.write_all(&req_buf).is_err() {
            return;
        }
        let mut buffer = [0; 65536];
        if let Ok(size) = stream.read(&mut buffer) {
            if let Ok(resp) = serde_json::from_slice::<SignedMessage>(&buffer[..size]) {
                if resp.message.version == PROTOCOL_VERSION && resp.verify() {
                    if let NetworkMessage::PeerList(list) = resp.message.payload {
                        peers.merge(&list);
                    }
                }
            }
        }
    }
}

#[cfg(not(feature = "sync"))]
pub async fn perform_handshake(addr: &str, my_addr: &str, peers: Arc<PeerList>, sk: &SecretKey) {
    if let Ok(mut stream) = TcpStream::connect(addr).await {
        let signed = SignedMessage::new(NetworkMessage::Handshake(my_addr.to_string()), sk);
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        if stream.write_all(&req_buf).await.is_err() {
            return;
        }
        let mut buffer = [0u8; 65536];
        if let Ok(size) = stream.read(&mut buffer).await {
            if let Ok(resp) = serde_json::from_slice::<SignedMessage>(&buffer[..size]) {
                if resp.message.version == PROTOCOL_VERSION && resp.verify() {
                    if let NetworkMessage::PeerList(list) = resp.message.payload {
                        peers.merge(&list);
                    }
                }
            }
        }
    }
}

/// Sends a ChainRequest to `addr` and waits for a ChainResponse.
/// If a longer chain is received and valid, replaces `blockchain`.
#[cfg(feature = "sync")]
pub fn request_chain_and_reconcile(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    my_addr: &str,
    sk: &SecretKey,
) {
    // Send a ChainRequest
    println!("[RECONCILE] Trying to connect to >{}<", addr); // Diagnostic print
    let req = NetworkMessage::ChainRequest(my_addr.to_string());
    if let Ok(mut stream) = TcpStream::connect(addr.trim()) {
        let signed = SignedMessage::new(req, sk);
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        if let Err(e) = stream.write_all(&req_buf) {
            eprintln!("[RECONCILE] Failed to send chain request: {}", e);
            return;
        }
        // Wait for a response (should be a ChainResponse)
        let mut buffer = [0; 65536];
        match stream.read(&mut buffer) {
            Ok(size) => {
                if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer[..size]) {
                    if signed.message.version != PROTOCOL_VERSION {
                        eprintln!(
                            "[RECONCILE] Unsupported protocol version {}",
                            signed.message.version
                        );
                        return;
                    }
                    if !signed.verify() {
                        eprintln!("[RECONCILE] Invalid signature in chain response");
                        return;
                    }
                    if let NetworkMessage::ChainResponse(their_chain) = signed.message.payload {
                        println!(
                            "[RECONCILE] Received chain from peer: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    } else {
                        eprintln!("[RECONCILE] Did not receive a ChainResponse message");
                    }
                } else {
                    eprintln!("[RECONCILE] Failed to parse signed message");
                }
            }
            Err(e) => eprintln!("[RECONCILE] Failed to read chain response: {}", e),
        }
    } else {
        eprintln!("[RECONCILE] Failed to connect to peer for chain request.");
    }
}

#[cfg(not(feature = "sync"))]
pub async fn request_chain_and_reconcile(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    my_addr: &str,
    sk: &SecretKey,
) {
    println!("[RECONCILE] Trying to connect to >{}<", addr);
    let req = NetworkMessage::ChainRequest(my_addr.to_string());
    if let Ok(mut stream) = TcpStream::connect(addr.trim()).await {
        let signed = SignedMessage::new(req, sk);
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        if let Err(e) = stream.write_all(&req_buf).await {
            eprintln!("[RECONCILE] Failed to send chain request: {}", e);
            return;
        }
        let mut buffer = [0u8; 65536];
        match stream.read(&mut buffer).await {
            Ok(size) => {
                if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer[..size]) {
                    if signed.message.version != PROTOCOL_VERSION {
                        eprintln!(
                            "[RECONCILE] Unsupported protocol version {}",
                            signed.message.version
                        );
                        return;
                    }
                    if !signed.verify() {
                        eprintln!("[RECONCILE] Invalid signature in chain response");
                        return;
                    }
                    if let NetworkMessage::ChainResponse(their_chain) = signed.message.payload {
                        println!(
                            "[RECONCILE] Received chain from peer: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    } else {
                        eprintln!("[RECONCILE] Did not receive a ChainResponse message");
                    }
                } else {
                    eprintln!("[RECONCILE] Failed to parse signed message");
                }
            }
            Err(e) => eprintln!("[RECONCILE] Failed to read chain response: {}", e),
        }
    } else {
        eprintln!("[RECONCILE] Failed to connect to peer for chain request.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_network_message_serialize_roundtrip() {
        let msg = NetworkMessage::Text("hello".into());
        let data = msg.serialize();
        let de: NetworkMessage = serde_json::from_slice(&data).unwrap();
        match de {
            NetworkMessage::Text(s) => assert_eq!(s, "hello"),
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_handle_chain_response_replaces_chain() {
        let mut local = Blockchain::new();
        let mut their = Blockchain::new();
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "b".into(),
            amount: 1,
            signature: None,
        };
        tx.sign(&sk);
        their.balances.insert(tx.sender.clone(), 1);
        their.add_block(vec![tx], Some("addr".into()));
        handle_chain_response(&mut local, their.chain.clone());
        assert_eq!(local.chain.len(), 2);
    }

    #[tokio::test]
    async fn test_send_and_broadcast_message() {
        let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));

        let c1 = counter.clone();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener1.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await.unwrap();
                c1.fetch_add(1, Ordering::SeqCst);
                stream.write_all(b"ok").await.unwrap();
            }
        });

        let c2 = counter.clone();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener2.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await.unwrap();
                c2.fetch_add(1, Ordering::SeqCst);
                stream.write_all(b"ok").await.unwrap();
            }
        });

        let peers = Arc::new(PeerList::new());
        peers.add_peer(&addr1.to_string());
        peers.add_peer(&addr2.to_string());

        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();

        broadcast_message(peers, &NetworkMessage::Text("hi".into()), &sk).await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_request_chain_and_reconcile() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut their_chain = Blockchain::new();
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "y".into(),
            amount: 5,
            signature: None,
        };
        tx.sign(&sk);
        their_chain.balances.insert(tx.sender.clone(), 5);
        their_chain.add_block(vec![tx], Some("addr".into()));
        let sk_clone = sk.clone();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 65536];
                let size = stream.read(&mut buf).await.unwrap();
                let signed_req: SignedMessage = serde_json::from_slice(&buf[..size]).unwrap();
                assert_eq!(signed_req.message.version, PROTOCOL_VERSION);
                let _req = signed_req.message.payload;
                let resp = NetworkMessage::ChainResponse(their_chain.chain.clone());
                let signed_resp = SignedMessage::new(resp, &sk_clone);
                let resp_buf = serde_json::to_vec(&signed_resp).unwrap();
                stream.write_all(&resp_buf).await.unwrap();
            }
        });

        let local = Arc::new(Mutex::new(Blockchain::new()));
        let client_sk = SecretKey::from_slice(&sk_bytes).unwrap();
        request_chain_and_reconcile(&addr.to_string(), local.clone(), "client", &client_sk).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(local.lock().unwrap().chain.len(), 2);
    }

    #[tokio::test]
    async fn test_block_propagation_between_servers() {
        // Acquire two ephemeral ports then drop the listeners so the ports can be reused
        let temp1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = temp1.local_addr().unwrap();
        drop(temp1);
        let temp2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = temp2.local_addr().unwrap();
        drop(temp2);

        let bc1 = Arc::new(Mutex::new(Blockchain::new()));
        let bc2 = Arc::new(Mutex::new(Blockchain::new()));
        let peers1 = Arc::new(PeerList::new());
        let peers2 = Arc::new(PeerList::new());
        peers1.add_peer(&addr2.to_string());
        peers2.add_peer(&addr1.to_string());

        // Spawn the two servers in background tasks. The address strings
        // must be owned and moved into the async blocks so the references
        // used by `start_server_with_chain` live for the `'static` lifetime
        // required by `tokio::spawn`.
        let addr1_str = addr1.to_string();
        let server1_bc = bc1.clone();
        let server1_peers = peers1.clone();
        let addr1_my = addr1_str.clone();
        let node1_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk1_arc = Arc::new(node1_sk);
        let server1_sk = sk1_arc.clone();
        let server1 = tokio::spawn(async move {
            start_server_with_chain(&addr1_str, server1_bc, server1_peers, addr1_my, server1_sk)
                .await
                .unwrap();
        });

        let addr2_str = addr2.to_string();
        let server2_bc = bc2.clone();
        let server2_peers = peers2.clone();
        let addr2_my = addr2_str.clone();
        let node2_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let sk2_arc = Arc::new(node2_sk);
        let server2_sk = sk2_arc.clone();
        let server2 = tokio::spawn(async move {
            start_server_with_chain(&addr2_str, server2_bc, server2_peers, addr2_my, server2_sk)
                .await
                .unwrap();
        });

        // Give the servers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create a signed transaction and add a block on node1
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "b".into(),
            amount: 3,
            signature: None,
        };
        tx.sign(&sk);

        {
            let mut chain1 = bc1.lock().unwrap();
            chain1.balances.insert(tx.sender.clone(), 3);
            chain1.add_block(vec![tx.clone()], Some(addr1.to_string()));
        }

        let block = {
            let chain1 = bc1.lock().unwrap();
            chain1.chain.last().unwrap().clone()
        };

        // Send the new block to node2
        send_message(&addr2.to_string(), &NetworkMessage::Block(block), &sk1_arc)
            .await
            .unwrap();

        // Wait until node2 has reconciled and has two blocks
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if bc2.lock().unwrap().chain.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(bc2.lock().unwrap().chain.len(), 2);

        // Stop servers
        server1.abort();
        server2.abort();
    }
}
