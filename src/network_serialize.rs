#[cfg(feature = "sync")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "sync")]
use std::io::{Read, Write};
#[cfg(feature = "sync")]
use std::thread;

#[cfg(not(feature = "sync"))]
use tokio::net::{TcpListener, TcpStream};
#[cfg(not(feature = "sync"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(feature = "sync"))]
use tokio::task;

use std::io;
use serde::{Serialize, Deserialize};
use crate::transaction::Transaction;
use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::peer::PeerList;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    Text(String),
    ChainRequest(String),         // requesting node's address
    ChainResponse(Vec<Block>),    // the entire chain
}

impl NetworkMessage {
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

// ---- Chain reconciliation helper ----
pub fn handle_chain_response(local_chain: &mut Blockchain, their_chain: Vec<Block>) {
    if their_chain.len() > local_chain.chain.len() {
        // Validate new chain
        let mut valid = true;
        for i in 1..their_chain.len() {
            let prev = &their_chain[i - 1];
            let curr = &their_chain[i];
            if curr.prev_hash != prev.hash || curr.hash != curr.calculate_hash() {
                valid = false;
                break;
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
pub fn handle_client_with_chain(mut stream: TcpStream, blockchain: Arc<Mutex<Blockchain>>, peers: Arc<PeerList>, my_addr: String) {
    let mut buffer = [0; 4096];
    match stream.read(&mut buffer) {
        Ok(size) => {
            if let Ok(msg) = serde_json::from_slice::<NetworkMessage>(&buffer[..size]) {
                match msg {
                    NetworkMessage::Transaction(tx) => {
                        println!("[SERIALIZED] Received Transaction: {:?}", tx);
                        if !tx.verify() {
                            eprintln!("[SERIALIZED] Invalid transaction signature");
                        } else {
                            // You may wish to add to mempool here
                        }
                    },
                    NetworkMessage::Block(block) => {
                        println!("[SERIALIZED] Received Block: {:?}", block);
                        if !block.transactions.iter().all(|tx| tx.verify()) {
                            eprintln!("[SERIALIZED] Block contains invalid transaction");
                            return;
                        }
                        let mut chain = blockchain.lock().unwrap();
                        let local_tip = chain.chain.last().unwrap().index;
                        if block.index > local_tip {
                            if let Some(sender_addr) = block.sender_addr.clone() {
                                println!("[RECONCILE] Attempting to reconcile with block sender: {}", sender_addr);
                                drop(chain); // unlock before net IO
                                request_chain_and_reconcile(&sender_addr, blockchain.clone(), &my_addr);
                            } else {
                                println!("[RECONCILE] Received block with no sender_addr!");
                            }
                            return;
                        }
                        // Optionally: append if valid and next block
                    },
                    NetworkMessage::ChainRequest(requestor_addr) => {
                        println!("[SERIALIZED] Received ChainRequest from {}", requestor_addr);
                        let chain = blockchain.lock().unwrap();
                        let response = NetworkMessage::ChainResponse(chain.chain.clone());
                        let _ = send_message(&requestor_addr, &response);
                    },
                    NetworkMessage::ChainResponse(their_chain) => {
                        println!("[SERIALIZED] Received ChainResponse: {} blocks", their_chain.len());
                        let mut chain = blockchain.lock().unwrap();
                        handle_chain_response(&mut chain, their_chain);
                    },
                    NetworkMessage::Text(s) => println!("[SERIALIZED] Received Text: {}", s),
                }
                let response = b"OK (parsed NetworkMessage)\n";
                stream.write_all(response).unwrap();
            } else {
                println!("[SERIALIZED] Received (unparsed): {}", String::from_utf8_lossy(&buffer[..size]));
                let response = b"Unrecognized data\n";
                stream.write_all(response).unwrap();
            }
        }
        Err(e) => eprintln!("Error reading stream: {}", e),
    }
}

#[cfg(not(feature = "sync"))]
pub async fn handle_client_with_chain(mut stream: TcpStream, blockchain: Arc<Mutex<Blockchain>>, peers: Arc<PeerList>, my_addr: String) {
    let mut buffer = [0u8; 4096];
    match stream.read(&mut buffer).await {
        Ok(size) => {
            if let Ok(msg) = serde_json::from_slice::<NetworkMessage>(&buffer[..size]) {
                match msg {
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
                            let chain = blockchain.lock().unwrap();
                            chain.chain.last().unwrap().index
                        };
                        if block.index > local_tip {
                            if let Some(sender_addr) = block.sender_addr.clone() {
                                println!("[RECONCILE] Attempting to reconcile with block sender: {}", sender_addr);
                                request_chain_and_reconcile(&sender_addr, blockchain.clone(), &my_addr).await;
                            } else {
                                println!("[RECONCILE] Received block with no sender_addr!");
                            }
                            return;
                        }
                    }
                    NetworkMessage::ChainRequest(requestor_addr) => {
                        println!("[SERIALIZED] Received ChainRequest from {}", requestor_addr);
                        let chain_blocks = {
                            let chain = blockchain.lock().unwrap();
                            chain.chain.clone()
                        };
                        let response = NetworkMessage::ChainResponse(chain_blocks);
                        let _ = send_message(&requestor_addr, &response).await;
                    }
                    NetworkMessage::ChainResponse(their_chain) => {
                        println!("[SERIALIZED] Received ChainResponse: {} blocks", their_chain.len());
                        let mut chain = blockchain.lock().unwrap();
                        handle_chain_response(&mut chain, their_chain);
                    }
                    NetworkMessage::Text(s) => println!("[SERIALIZED] Received Text: {}", s),
                }
                let response = b"OK (parsed NetworkMessage)\n";
                let _ = stream.write_all(response).await;
            } else {
                println!("[SERIALIZED] Received (unparsed): {}", String::from_utf8_lossy(&buffer[..size]));
                let response = b"Unrecognized data\n";
                let _ = stream.write_all(response).await;
            }
        }
        Err(e) => eprintln!("Error reading stream: {}", e),
    }
}

#[cfg(feature = "sync")]
pub fn start_server_with_chain(addr: &str, blockchain: Arc<Mutex<Blockchain>>, peers: Arc<PeerList>, my_addr: String) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("[SERIALIZED] Server listening on {}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let bc = blockchain.clone();
                let p = peers.clone();
                let me = my_addr.clone();
                thread::spawn(|| handle_client_with_chain(stream, bc, p, me));
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
    Ok(())
}

#[cfg(not(feature = "sync"))]
pub async fn start_server_with_chain(addr: &str, blockchain: Arc<Mutex<Blockchain>>, peers: Arc<PeerList>, my_addr: String) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[SERIALIZED] Server listening on {}", addr);
    loop {
        let (stream, _) = listener.accept().await?;
        let bc = blockchain.clone();
        let p = peers.clone();
        let me = my_addr.clone();
        task::spawn(async move {
            handle_client_with_chain(stream, bc, p, me).await;
        });
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(feature = "sync")]
pub fn send_message(addr: &str, msg: &NetworkMessage) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    let buf = msg.serialize();
    stream.write_all(&buf)?;
    let mut buffer = [0; 4096];
    let size = stream.read(&mut buffer)?;
    println!("[SERIALIZED] Server responded: {}", String::from_utf8_lossy(&buffer[..size]));
    Ok(())
}

#[cfg(not(feature = "sync"))]
pub async fn send_message(addr: &str, msg: &NetworkMessage) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    let buf = msg.serialize();
    stream.write_all(&buf).await?;
    let mut buffer = [0u8; 4096];
    let size = stream.read(&mut buffer).await?;
    println!("[SERIALIZED] Server responded: {}", String::from_utf8_lossy(&buffer[..size]));
    Ok(())
}

#[cfg(feature = "sync")]
pub fn broadcast_message(peers: Arc<PeerList>, msg: &NetworkMessage) {
    for peer_addr in peers.all() {
        if let Err(e) = send_message(&peer_addr, msg) {
            eprintln!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}

#[cfg(not(feature = "sync"))]
pub async fn broadcast_message(peers: Arc<PeerList>, msg: &NetworkMessage) {
    for peer_addr in peers.all() {
        if let Err(e) = send_message(&peer_addr, msg).await {
            eprintln!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}


/// Sends a ChainRequest to `addr` and waits for a ChainResponse.
/// If a longer chain is received and valid, replaces `blockchain`.
#[cfg(feature = "sync")]
pub fn request_chain_and_reconcile(addr: &str, blockchain: Arc<Mutex<Blockchain>>, my_addr: &str) {
    // Send a ChainRequest
    println!("[RECONCILE] Trying to connect to >{}<", addr); // Diagnostic print
    let req = NetworkMessage::ChainRequest(my_addr.to_string());
    if let Ok(mut stream) = TcpStream::connect(addr.trim()) {
        let req_buf = req.serialize();
        if let Err(e) = stream.write_all(&req_buf) {
            eprintln!("[RECONCILE] Failed to send chain request: {}", e);
            return;
        }
        // Wait for a response (should be a ChainResponse)
        let mut buffer = [0; 65536];
        match stream.read(&mut buffer) {
            Ok(size) => {
                if let Ok(NetworkMessage::ChainResponse(their_chain)) =
                    serde_json::from_slice::<NetworkMessage>(&buffer[..size])
                {
                    println!("[RECONCILE] Received chain from peer: {} blocks", their_chain.len());
                    let mut chain = blockchain.lock().unwrap();
                    // super::handle_chain_response(&mut chain, their_chain);
                    handle_chain_response(&mut chain, their_chain);

                } else {
                    eprintln!("[RECONCILE] Did not receive a valid ChainResponse.");
                }
            }
            Err(e) => eprintln!("[RECONCILE] Failed to read chain response: {}", e),
        }
    } else {
        eprintln!("[RECONCILE] Failed to connect to peer for chain request.");
    }
}

#[cfg(not(feature = "sync"))]
pub async fn request_chain_and_reconcile(addr: &str, blockchain: Arc<Mutex<Blockchain>>, my_addr: &str) {
    println!("[RECONCILE] Trying to connect to >{}<", addr);
    let req = NetworkMessage::ChainRequest(my_addr.to_string());
    if let Ok(mut stream) = TcpStream::connect(addr.trim()).await {
        let req_buf = req.serialize();
        if let Err(e) = stream.write_all(&req_buf).await {
            eprintln!("[RECONCILE] Failed to send chain request: {}", e);
            return;
        }
        let mut buffer = [0u8; 65536];
        match stream.read(&mut buffer).await {
            Ok(size) => {
                if let Ok(NetworkMessage::ChainResponse(their_chain)) =
                    serde_json::from_slice::<NetworkMessage>(&buffer[..size])
                {
                    println!("[RECONCILE] Received chain from peer: {} blocks", their_chain.len());
                    let mut chain = blockchain.lock().unwrap();
                    handle_chain_response(&mut chain, their_chain);
                } else {
                    eprintln!("[RECONCILE] Did not receive a valid ChainResponse.");
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use secp256k1::{Secp256k1, SecretKey, PublicKey};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use hex;

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
        let mut tx = Transaction { sender: hex::encode(pk.serialize()), recipient: "b".into(), amount: 1, signature: None };
        tx.sign(&sk);
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
        broadcast_message(peers, &NetworkMessage::Text("hi".into())).await;

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
        let mut tx = Transaction { sender: hex::encode(pk.serialize()), recipient: "y".into(), amount: 5, signature: None };
        tx.sign(&sk);
        their_chain.add_block(vec![tx], Some("addr".into()));
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 65536];
                let size = stream.read(&mut buf).await.unwrap();
                let _req: NetworkMessage = serde_json::from_slice(&buf[..size]).unwrap();
                let resp = NetworkMessage::ChainResponse(their_chain.chain.clone());
                let resp_buf = resp.serialize();
                stream.write_all(&resp_buf).await.unwrap();
            }
        });

        let local = Arc::new(Mutex::new(Blockchain::new()));
        request_chain_and_reconcile(&addr.to_string(), local.clone(), "client").await;
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
        let server1 = tokio::spawn(async move {
            start_server_with_chain(&addr1_str, server1_bc, server1_peers, addr1_my)
                .await
                .unwrap();
        });

        let addr2_str = addr2.to_string();
        let server2_bc = bc2.clone();
        let server2_peers = peers2.clone();
        let addr2_my = addr2_str.clone();
        let server2 = tokio::spawn(async move {
            start_server_with_chain(&addr2_str, server2_bc, server2_peers, addr2_my)
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
            chain1.add_block(vec![tx.clone()], Some(addr1.to_string()));
        }

        let block = {
            let chain1 = bc1.lock().unwrap();
            chain1.chain.last().unwrap().clone()
        };

        // Send the new block to node2
        send_message(&addr2.to_string(), &NetworkMessage::Block(block))
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

