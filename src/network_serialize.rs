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

#[cfg(feature = "tls")]
use rustls::{
    self, client::ServerCertVerified, client::ServerCertVerifier, Certificate, PrivateKey,
};
#[cfg(feature = "tls")]
use rustls_pemfile::{certs, pkcs8_private_keys};
#[cfg(feature = "tls")]
use std::fs::File;
#[cfg(feature = "tls")]
use std::io::BufReader;
#[cfg(feature = "tls")]
use std::sync::Arc as StdArc;
#[cfg(feature = "tls")]
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::block::Block;
use crate::blockchain::{Blockchain, DIFFICULTY_PREFIX, MINT_ADDRESS};
use crate::mempool::Mempool;
use crate::peer::PeerList;
use crate::transaction::Transaction;

/// Current protocol version understood by this node
pub const PROTOCOL_VERSION: u8 = 1;

/// Network identifiers to segregate main and test nets
pub const NETWORK_MAINNET: u8 = 1;
pub const NETWORK_TESTNET: u8 = 2;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::{Arc, Mutex};

/// Maximum size of a single serialized network message in bytes
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB

fn prefix_with_length(mut data: Vec<u8>) -> Vec<u8> {
    let len = data.len() as u32;
    let mut out = len.to_be_bytes().to_vec();
    out.append(&mut data);
    out
}

#[cfg(feature = "tls")]
struct NoVerifier;
#[cfg(feature = "tls")]
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::client::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(feature = "tls")]
fn load_tls_acceptor(cert: &str, key: &str) -> io::Result<TlsAcceptor> {
    let cert_file = &mut BufReader::new(File::open(cert)?);
    let key_file = &mut BufReader::new(File::open(key)?);
    let cert_chain = certs(cert_file)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cert"))?
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys = pkcs8_private_keys(key_file)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key"))?;
    let key = PrivateKey(keys.remove(0));
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
    Ok(TlsAcceptor::from(StdArc::new(config)))
}

#[cfg(feature = "tls")]
pub fn create_tls_connector() -> TlsConnector {
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(StdArc::new(NoVerifier))
        .with_no_client_auth();
    TlsConnector::from(StdArc::new(config))
}

#[cfg(not(feature = "sync"))]
async fn read_length_prefixed<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(feature = "sync")]
fn read_length_prefixed(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    Text(String),
    ChainRequest(String),                    // requesting node's address
    ChainResponse(Vec<Block>),               // the entire chain
    Handshake { addr: String, network: u8 }, // peer introduction with network id
    PeerList(Vec<String>),                   // returned during handshake
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
                tracing::error!("Failed to serialize versioned message: {}", e);
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
                tracing::error!("Failed to serialize network message: {}", e);
                Vec::new()
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
                || !curr.is_puzzle_valid(DIFFICULTY_PREFIX)
            {
                valid = false;
                break;
            }
        }
        if valid {
            if their_chain[0].hash != their_chain[0].calculate_hash()
                || !their_chain[0].is_puzzle_valid(DIFFICULTY_PREFIX)
            {
                valid = false;
            }
        }
        if valid {
            local_chain.chain = their_chain;
            local_chain.recompute_balances();
            local_chain.recompute_difficulty();
            tracing::info!("[RECONCILE] Local chain updated from peer!");
        } else {
            tracing::info!("[RECONCILE] Received invalid chain, ignoring.");
        }
    }
}

// ---- Handler expects Arc<Mutex<Blockchain>>, Arc<PeerList> and Arc<Mutex<Mempool>> ----
#[cfg(feature = "sync")]
pub fn handle_client_with_chain(
    mut stream: TcpStream,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    mempool: Arc<Mutex<Mempool>>,
    my_addr: String,
    sk: Arc<SecretKey>,
    network: u8,
) {
    match read_length_prefixed(&mut stream) {
        Ok(buffer) => {
            if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer) {
                if signed.message.version != PROTOCOL_VERSION {
                    tracing::error!(
                        "[PROTO] Unsupported protocol version {}",
                        signed.message.version
                    );
                    return;
                }
                if !signed.verify() {
                    tracing::error!("[AUTH] Invalid signature from peer");
                    return;
                }
                let msg = signed.message.payload;
                match msg {
                    NetworkMessage::Handshake {
                        addr,
                        network: peer_net,
                    } => {
                        if peer_net != network {
                            tracing::info!(
                                "[SERIALIZED] Ignoring handshake from {} on network {}",
                                addr,
                                peer_net
                            );
                            return;
                        }
                        tracing::info!("[SERIALIZED] Received Handshake from {}", addr);
                        peers.add_peer(&addr);
                        let known = peers.all();
                        let resp = SignedMessage::new(NetworkMessage::PeerList(known), &sk);
                        let resp_buf = serde_json::to_vec(&resp).expect("serialize");
                        let resp_buf = prefix_with_length(resp_buf);
                        if let Err(e) = stream.write_all(&resp_buf) {
                            tracing::error!("Failed to write handshake response: {}", e);
                        }
                        return;
                    }
                    NetworkMessage::Transaction(tx) => {
                        tracing::info!("[SERIALIZED] Received Transaction: {:?}", tx);
                        if !tx.verify() {
                            tracing::error!("[SERIALIZED] Invalid transaction signature");
                        } else {
                            let mut mp = mempool.lock().unwrap();
                            mp.add_tx(tx);
                        }
                    }
                    NetworkMessage::Block(block) => {
                        tracing::info!("[SERIALIZED] Received Block: {:?}", block);
                        if !block
                            .transactions
                            .iter()
                            .all(|tx| tx.sender == MINT_ADDRESS || tx.verify())
                        {
                            tracing::error!("[SERIALIZED] Block contains invalid transaction");
                            return;
                        }
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        let local_tip = match chain.chain.last() {
                            Some(b) => b.index,
                            None => {
                                tracing::error!("Received block but local chain empty");
                                return;
                            }
                        };
                        if block.index > local_tip {
                            if let Some(sender_addr) = block.sender_addr.clone() {
                                tracing::info!(
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
                                tracing::info!("[RECONCILE] Received block with no sender_addr!");
                            }
                            return;
                        }
                        // Optionally: append if valid and next block
                    }
                    NetworkMessage::ChainRequest(requestor_addr) => {
                        tracing::info!(
                            "[SERIALIZED] Received ChainRequest from {}",
                            requestor_addr
                        );
                        let chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        let response = NetworkMessage::ChainResponse(chain.chain.clone());
                        let _ = send_message(&requestor_addr, &response, &sk);
                    }
                    NetworkMessage::ChainResponse(their_chain) => {
                        tracing::info!(
                            "[SERIALIZED] Received ChainResponse: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    }
                    NetworkMessage::PeerList(list) => {
                        tracing::info!("[SERIALIZED] Received PeerList: {:?}", list);
                        peers.merge(&list);
                    }
                    NetworkMessage::Text(s) => tracing::info!("[SERIALIZED] Received Text: {}", s),
                }
                let response = b"OK (parsed NetworkMessage)\n";
                if let Err(e) = stream.write_all(response) {
                    tracing::error!("Failed to write response: {}", e);
                }
            } else {
                tracing::info!("[SERIALIZED] Received unrecognized data");
                let response = b"Unrecognized data\n";
                if let Err(e) = stream.write_all(response) {
                    tracing::error!("Failed to write response: {}", e);
                }
            }
        }
        Err(e) => {
            tracing::error!("Error reading stream: {}", e);
            let _ = stream.write_all(b"Unrecognized data\n");
        }
    }
}

#[cfg(not(feature = "sync"))]
pub async fn handle_client_with_chain<S>(
    mut stream: S,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    mempool: Arc<Mutex<Mempool>>,
    my_addr: String,
    sk: Arc<SecretKey>,
    network: u8,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    match read_length_prefixed(&mut stream).await {
        Ok(buffer) => {
            if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer) {
                if signed.message.version != PROTOCOL_VERSION {
                    tracing::error!(
                        "[PROTO] Unsupported protocol version {}",
                        signed.message.version
                    );
                    return;
                }
                if !signed.verify() {
                    tracing::error!("[AUTH] Invalid signature from peer");
                    return;
                }
                let msg = signed.message.payload;
                match msg {
                    NetworkMessage::Handshake {
                        addr,
                        network: peer_net,
                    } => {
                        if peer_net != network {
                            tracing::info!(
                                "[SERIALIZED] Ignoring handshake from {} on network {}",
                                addr,
                                peer_net
                            );
                            return;
                        }
                        tracing::info!("[SERIALIZED] Received Handshake from {}", addr);
                        peers.add_peer(&addr);
                        let known = peers.all();
                        let resp = SignedMessage::new(NetworkMessage::PeerList(known), &sk);
                        let resp_buf = serde_json::to_vec(&resp).expect("serialize");
                        let resp_buf = prefix_with_length(resp_buf);
                        let _ = stream.write_all(&resp_buf).await;
                        return;
                    }
                    NetworkMessage::Transaction(tx) => {
                        tracing::info!("[SERIALIZED] Received Transaction: {:?}", tx);
                        if !tx.verify() {
                            tracing::error!("[SERIALIZED] Invalid transaction signature");
                        } else {
                            let mut mp = mempool.lock().unwrap();
                            mp.add_tx(tx);
                        }
                    }
                    NetworkMessage::Block(block) => {
                        tracing::info!("[SERIALIZED] Received Block: {:?}", block);
                        if !block
                            .transactions
                            .iter()
                            .all(|tx| tx.sender == MINT_ADDRESS || tx.verify())
                        {
                            tracing::error!("[SERIALIZED] Block contains invalid transaction");
                            return;
                        }
                        let local_tip = {
                            let chain = match blockchain.lock() {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::error!("Blockchain lock poisoned: {}", e);
                                    e.into_inner()
                                }
                            };
                            match chain.chain.last() {
                                Some(b) => b.index,
                                None => {
                                    tracing::error!("Received block but local chain empty");
                                    return;
                                }
                            }
                        };
                        if block.index > local_tip {
                            if let Some(sender_addr) = block.sender_addr.clone() {
                                tracing::info!(
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
                                tracing::info!("[RECONCILE] Received block with no sender_addr!");
                            }
                            return;
                        }
                    }
                    NetworkMessage::ChainRequest(requestor_addr) => {
                        tracing::info!(
                            "[SERIALIZED] Received ChainRequest from {}",
                            requestor_addr
                        );
                        let chain_blocks = {
                            let chain = match blockchain.lock() {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::error!("Blockchain lock poisoned: {}", e);
                                    e.into_inner()
                                }
                            };
                            chain.chain.clone()
                        };
                        let response = NetworkMessage::ChainResponse(chain_blocks);
                        let _ = send_message(&requestor_addr, &response, &sk).await;
                    }
                    NetworkMessage::ChainResponse(their_chain) => {
                        tracing::info!(
                            "[SERIALIZED] Received ChainResponse: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    }
                    NetworkMessage::PeerList(list) => {
                        tracing::info!("[SERIALIZED] Received PeerList: {:?}", list);
                        peers.merge(&list);
                    }
                    NetworkMessage::Text(s) => tracing::info!("[SERIALIZED] Received Text: {}", s),
                }
                let response = b"OK (parsed NetworkMessage)\n";
                let _ = stream.write_all(response).await;
            } else {
                tracing::info!("[SERIALIZED] Received unrecognized data");
                let response = b"Unrecognized data\n";
                let _ = stream.write_all(response).await;
            }
        }
        Err(e) => {
            tracing::error!("Error reading stream: {}", e);
            let _ = stream.write_all(b"Unrecognized data\n").await;
        }
    }
}

#[cfg(feature = "sync")]
pub fn start_server_with_chain(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    mempool: Arc<Mutex<Mempool>>,
    my_addr: String,
    sk: Arc<SecretKey>,
    network: u8,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    tracing::info!("[SERIALIZED] Server listening on {}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let bc = blockchain.clone();
                let p = peers.clone();
                let me = my_addr.clone();
                let mp = mempool.clone();
                let sk_clone = sk.clone();
                let n = network;
                thread::spawn(|| handle_client_with_chain(stream, bc, p, mp, me, sk_clone, n));
            }
            Err(e) => tracing::error!("Connection failed: {}", e),
        }
    }
    Ok(())
}

#[cfg(not(feature = "sync"))]
pub async fn start_server_with_chain(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    mempool: Arc<Mutex<Mempool>>,
    my_addr: String,
    sk: Arc<SecretKey>,
    network: u8,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("[SERIALIZED] Server listening on {}", addr);
    loop {
        let (stream, _) = listener.accept().await?;
        let bc = blockchain.clone();
        let p = peers.clone();
        let me = my_addr.clone();
        let mp = mempool.clone();
        let sk_clone = sk.clone();
        let n = network;
        task::spawn(async move {
            handle_client_with_chain(stream, bc, p, mp, me, sk_clone, n).await;
        });
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(all(not(feature = "sync"), feature = "tls"))]
pub async fn start_tls_server_with_chain(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<PeerList>,
    mempool: Arc<Mutex<Mempool>>,
    my_addr: String,
    sk: Arc<SecretKey>,
    cert_path: &str,
    key_path: &str,
    network: u8,
) -> io::Result<()> {
    let acceptor = load_tls_acceptor(cert_path, key_path)?;
    let acceptor = StdArc::new(acceptor);
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("[SERIALIZED] TLS server listening on {}", addr);
    loop {
        let (stream, _) = listener.accept().await?;
        let bc = blockchain.clone();
        let p = peers.clone();
        let me = my_addr.clone();
        let mp = mempool.clone();
        let sk_clone = sk.clone();
        let acceptor = acceptor.clone();
        let n = network;
        task::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    handle_client_with_chain(tls_stream, bc, p, mp, me, sk_clone, n).await;
                }
                Err(e) => tracing::error!("TLS accept error: {}", e),
            }
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
    let buf = prefix_with_length(buf);
    stream.write_all(&buf)?;
    let mut buffer = [0; 4096];
    let size = stream.read(&mut buffer)?;
    tracing::info!(
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
    let buf = prefix_with_length(buf);
    stream.write_all(&buf).await?;
    let mut buffer = [0u8; 4096];
    let size = stream.read(&mut buffer).await?;
    tracing::info!(
        "[SERIALIZED] Server responded: {}",
        String::from_utf8_lossy(&buffer[..size])
    );
    Ok(())
}

#[cfg(all(not(feature = "sync"), feature = "tls"))]
pub async fn send_tls_message(
    addr: &str,
    msg: &NetworkMessage,
    sk: &SecretKey,
    connector: &TlsConnector,
) -> io::Result<()> {
    let host = addr.split(':').next().unwrap_or("localhost");
    let server_name = rustls::ServerName::try_from(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid host"))?;
    let stream = TcpStream::connect(addr).await?;
    let mut stream = connector.connect(server_name, stream).await?;
    let signed = SignedMessage::new(msg.clone(), sk);
    let buf = serde_json::to_vec(&signed)?;
    let buf = prefix_with_length(buf);
    stream.write_all(&buf).await?;
    let mut buffer = [0u8; 4096];
    let size = stream.read(&mut buffer).await?;
    tracing::info!(
        "[SERIALIZED] Server responded: {}",
        String::from_utf8_lossy(&buffer[..size])
    );
    Ok(())
}

#[cfg(feature = "sync")]
pub fn broadcast_message(peers: Arc<PeerList>, msg: &NetworkMessage, sk: &SecretKey) {
    for peer_addr in peers.all() {
        if let Err(e) = send_message(&peer_addr, msg, sk) {
            tracing::error!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}

#[cfg(not(feature = "sync"))]
pub async fn broadcast_message(peers: Arc<PeerList>, msg: &NetworkMessage, sk: &SecretKey) {
    for peer_addr in peers.all() {
        if let Err(e) = send_message(&peer_addr, msg, sk).await {
            tracing::error!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}

#[cfg(all(not(feature = "sync"), feature = "tls"))]
pub async fn broadcast_tls_message(
    peers: Arc<PeerList>,
    msg: &NetworkMessage,
    sk: &SecretKey,
    connector: &TlsConnector,
) {
    for peer_addr in peers.all() {
        if let Err(e) = send_tls_message(&peer_addr, msg, sk, connector).await {
            tracing::error!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}

/// Perform a handshake with `addr` exchanging peer lists.
#[cfg(feature = "sync")]
pub fn perform_handshake(
    addr: &str,
    my_addr: &str,
    peers: Arc<PeerList>,
    sk: &SecretKey,
    network: u8,
) {
    if let Ok(mut stream) = TcpStream::connect(addr) {
        let signed = SignedMessage::new(
            NetworkMessage::Handshake {
                addr: my_addr.to_string(),
                network,
            },
            sk,
        );
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        let req_buf = prefix_with_length(req_buf);
        if stream.write_all(&req_buf).is_err() {
            return;
        }
        if let Ok(buffer) = read_length_prefixed(&mut stream) {
            if let Ok(resp) = serde_json::from_slice::<SignedMessage>(&buffer) {
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
pub async fn perform_handshake(
    addr: &str,
    my_addr: &str,
    peers: Arc<PeerList>,
    sk: &SecretKey,
    network: u8,
) {
    if let Ok(mut stream) = TcpStream::connect(addr).await {
        let signed = SignedMessage::new(
            NetworkMessage::Handshake {
                addr: my_addr.to_string(),
                network,
            },
            sk,
        );
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        let req_buf = prefix_with_length(req_buf);
        if stream.write_all(&req_buf).await.is_err() {
            return;
        }
        if let Ok(buffer) = read_length_prefixed(&mut stream).await {
            if let Ok(resp) = serde_json::from_slice::<SignedMessage>(&buffer) {
                if resp.message.version == PROTOCOL_VERSION && resp.verify() {
                    if let NetworkMessage::PeerList(list) = resp.message.payload {
                        peers.merge(&list);
                    }
                }
            }
        }
    }
}

#[cfg(all(not(feature = "sync"), feature = "tls"))]
pub async fn perform_tls_handshake(
    addr: &str,
    my_addr: &str,
    peers: Arc<PeerList>,
    sk: &SecretKey,
    connector: &TlsConnector,
    network: u8,
) {
    if let Ok(stream) = TcpStream::connect(addr).await {
        let host = addr.split(':').next().unwrap_or("localhost");
        let server_name = match rustls::ServerName::try_from(host) {
            Ok(n) => n,
            Err(_) => return,
        };
        if let Ok(mut stream) = connector.connect(server_name, stream).await {
            let signed = SignedMessage::new(
                NetworkMessage::Handshake {
                    addr: my_addr.to_string(),
                    network,
                },
                sk,
            );
            let req_buf = serde_json::to_vec(&signed).expect("serialize");
            let req_buf = prefix_with_length(req_buf);
            if stream.write_all(&req_buf).await.is_err() {
                return;
            }
            if let Ok(buffer) = read_length_prefixed(&mut stream).await {
                if let Ok(resp) = serde_json::from_slice::<SignedMessage>(&buffer) {
                    if resp.message.version == PROTOCOL_VERSION && resp.verify() {
                        if let NetworkMessage::PeerList(list) = resp.message.payload {
                            peers.merge(&list);
                        }
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
    tracing::info!("[RECONCILE] Trying to connect to >{}<", addr); // Diagnostic print
    let req = NetworkMessage::ChainRequest(my_addr.to_string());
    if let Ok(mut stream) = TcpStream::connect(addr.trim()) {
        let signed = SignedMessage::new(req, sk);
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        let req_buf = prefix_with_length(req_buf);
        if let Err(e) = stream.write_all(&req_buf) {
            tracing::error!("[RECONCILE] Failed to send chain request: {}", e);
            return;
        }
        // Wait for a response (should be a ChainResponse)
        match read_length_prefixed(&mut stream) {
            Ok(buffer) => {
                if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer) {
                    if signed.message.version != PROTOCOL_VERSION {
                        tracing::error!(
                            "[RECONCILE] Unsupported protocol version {}",
                            signed.message.version
                        );
                        return;
                    }
                    if !signed.verify() {
                        tracing::error!("[RECONCILE] Invalid signature in chain response");
                        return;
                    }
                    if let NetworkMessage::ChainResponse(their_chain) = signed.message.payload {
                        tracing::info!(
                            "[RECONCILE] Received chain from peer: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    } else {
                        tracing::error!("[RECONCILE] Did not receive a ChainResponse message");
                    }
                } else {
                    tracing::error!("[RECONCILE] Failed to parse signed message");
                }
            }
            Err(e) => tracing::error!("[RECONCILE] Failed to read chain response: {}", e),
        }
    } else {
        tracing::error!("[RECONCILE] Failed to connect to peer for chain request.");
    }
}

#[cfg(not(feature = "sync"))]
pub async fn request_chain_and_reconcile(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    my_addr: &str,
    sk: &SecretKey,
) {
    tracing::info!("[RECONCILE] Trying to connect to >{}<", addr);
    let req = NetworkMessage::ChainRequest(my_addr.to_string());
    if let Ok(mut stream) = TcpStream::connect(addr.trim()).await {
        let signed = SignedMessage::new(req, sk);
        let req_buf = serde_json::to_vec(&signed).expect("serialize");
        let req_buf = prefix_with_length(req_buf);
        if let Err(e) = stream.write_all(&req_buf).await {
            tracing::error!("[RECONCILE] Failed to send chain request: {}", e);
            return;
        }
        match read_length_prefixed(&mut stream).await {
            Ok(buffer) => {
                if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer) {
                    if signed.message.version != PROTOCOL_VERSION {
                        tracing::error!(
                            "[RECONCILE] Unsupported protocol version {}",
                            signed.message.version
                        );
                        return;
                    }
                    if !signed.verify() {
                        tracing::error!("[RECONCILE] Invalid signature in chain response");
                        return;
                    }
                    if let NetworkMessage::ChainResponse(their_chain) = signed.message.payload {
                        tracing::info!(
                            "[RECONCILE] Received chain from peer: {} blocks",
                            their_chain.len()
                        );
                        let mut chain = match blockchain.lock() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!("Blockchain lock poisoned: {}", e);
                                e.into_inner()
                            }
                        };
                        handle_chain_response(&mut chain, their_chain);
                    } else {
                        tracing::error!("[RECONCILE] Did not receive a ChainResponse message");
                    }
                } else {
                    tracing::error!("[RECONCILE] Failed to parse signed message");
                }
            }
            Err(e) => tracing::error!("[RECONCILE] Failed to read chain response: {}", e),
        }
    } else {
        tracing::error!("[RECONCILE] Failed to connect to peer for chain request.");
    }
}

#[cfg(all(not(feature = "sync"), feature = "tls"))]
pub async fn request_chain_and_reconcile_tls(
    addr: &str,
    blockchain: Arc<Mutex<Blockchain>>,
    my_addr: &str,
    sk: &SecretKey,
    connector: &TlsConnector,
) {
    tracing::info!("[RECONCILE] Trying to connect to >{}<", addr);
    let req = NetworkMessage::ChainRequest(my_addr.to_string());
    if let Ok(stream) = TcpStream::connect(addr.trim()).await {
        let host = addr.split(':').next().unwrap_or("localhost");
        let server_name = match rustls::ServerName::try_from(host) {
            Ok(n) => n,
            Err(_) => return,
        };
        if let Ok(mut stream) = connector.connect(server_name, stream).await {
            let signed = SignedMessage::new(req, sk);
            let req_buf = serde_json::to_vec(&signed).expect("serialize");
            let req_buf = prefix_with_length(req_buf);
            if let Err(e) = stream.write_all(&req_buf).await {
                tracing::error!("[RECONCILE] Failed to send chain request: {}", e);
                return;
            }
            match read_length_prefixed(&mut stream).await {
                Ok(buffer) => {
                    if let Ok(signed) = serde_json::from_slice::<SignedMessage>(&buffer) {
                        if signed.message.version != PROTOCOL_VERSION {
                            tracing::error!(
                                "[RECONCILE] Unsupported protocol version {}",
                                signed.message.version
                            );
                            return;
                        }
                        if !signed.verify() {
                            tracing::error!("[RECONCILE] Invalid signature in chain response");
                            return;
                        }
                        if let NetworkMessage::ChainResponse(their_chain) = signed.message.payload {
                            tracing::info!(
                                "[RECONCILE] Received chain from peer: {} blocks",
                                their_chain.len()
                            );
                            let mut chain = match blockchain.lock() {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::error!("Blockchain lock poisoned: {}", e);
                                    e.into_inner()
                                }
                            };
                            handle_chain_response(&mut chain, their_chain);
                        } else {
                            tracing::error!("[RECONCILE] Did not receive a ChainResponse message");
                        }
                    } else {
                        tracing::error!("[RECONCILE] Failed to parse signed message");
                    }
                }
                Err(e) => tracing::error!("[RECONCILE] Failed to read chain response: {}", e),
            }
        }
    } else {
        tracing::error!("[RECONCILE] Failed to connect to peer for chain request.");
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
        let mut local = Blockchain::new(None);
        let mut their = Blockchain::new(None);
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
            nonce: 0,
            signature: None,
        };
        tx.sign(&sk);
        their.balances.insert(tx.sender.clone(), 1);
        let _ = their.add_block(vec![tx], Some("addr".into()));
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

        let mut their_chain = Blockchain::new(None);
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
            nonce: 0,
            signature: None,
        };
        tx.sign(&sk);
        their_chain.balances.insert(tx.sender.clone(), 5);
        let _ = their_chain.add_block(vec![tx], Some("addr".into()));
        let sk_clone = sk.clone();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf).await.unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await.unwrap();
                let signed_req: SignedMessage = serde_json::from_slice(&buf).unwrap();
                assert_eq!(signed_req.message.version, PROTOCOL_VERSION);
                let _req = signed_req.message.payload;
                let resp = NetworkMessage::ChainResponse(their_chain.chain.clone());
                let signed_resp = SignedMessage::new(resp, &sk_clone);
                let resp_buf = serde_json::to_vec(&signed_resp).unwrap();
                let resp_buf = prefix_with_length(resp_buf);
                stream.write_all(&resp_buf).await.unwrap();
            }
        });

        let local = Arc::new(Mutex::new(Blockchain::new(None)));
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

        let bc1 = Arc::new(Mutex::new(Blockchain::new(None)));
        let bc2 = Arc::new(Mutex::new(Blockchain::new(None)));
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
        let server1_mp = Arc::new(Mutex::new(Mempool::new()));
        let server1_mp_clone = server1_mp.clone();
        let addr1_my = addr1_str.clone();
        let node1_sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk1_arc = Arc::new(node1_sk);
        let server1_sk = sk1_arc.clone();
        let server1 = tokio::spawn(async move {
            start_server_with_chain(
                &addr1_str,
                server1_bc,
                server1_peers,
                server1_mp_clone,
                addr1_my,
                server1_sk,
                NETWORK_MAINNET,
            )
            .await
            .unwrap();
        });

        let addr2_str = addr2.to_string();
        let server2_bc = bc2.clone();
        let server2_peers = peers2.clone();
        let server2_mp = Arc::new(Mutex::new(Mempool::new()));
        let server2_mp_clone = server2_mp.clone();
        let addr2_my = addr2_str.clone();
        let node2_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let sk2_arc = Arc::new(node2_sk);
        let server2_sk = sk2_arc.clone();
        let server2 = tokio::spawn(async move {
            start_server_with_chain(
                &addr2_str,
                server2_bc,
                server2_peers,
                server2_mp_clone,
                addr2_my,
                server2_sk,
                NETWORK_MAINNET,
            )
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
            nonce: 0,
            signature: None,
        };
        tx.sign(&sk);

        {
            let mut chain1 = bc1.lock().unwrap();
            chain1.balances.insert(tx.sender.clone(), 3);
            let _ = chain1.add_block(vec![tx.clone()], Some(addr1.to_string()));
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

    #[test]
    fn test_handle_chain_response_rejects_invalid_chain() {
        let mut local = Blockchain::new(None);
        let mut their = Blockchain::new(None);
        // create a valid extra block then corrupt it
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
            nonce: 0,
            signature: None,
        };
        tx.sign(&sk);
        their.balances.insert(tx.sender.clone(), 1);
        let _ = their.add_block(vec![tx], Some("addr".into()));
        // tamper block hash
        their.chain[1].hash = "00bad".into();
        handle_chain_response(&mut local, their.chain.clone());
        assert_eq!(local.chain.len(), 1); // chain not replaced
    }

    #[tokio::test]
    async fn test_handle_malformed_network_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let bc = Arc::new(Mutex::new(Blockchain::new(None)));
        let peers = Arc::new(PeerList::new());
        let sk = Arc::new(SecretKey::from_slice(&[1u8; 32]).unwrap());

        let bc_clone = bc.clone();
        let peers_clone = peers.clone();
        let mp = Arc::new(Mutex::new(Mempool::new()));
        let mp_clone = mp.clone();
        let addr_str = addr.to_string();
        let sk_clone = sk.clone();
        let server = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                handle_client_with_chain(
                    stream,
                    bc_clone,
                    peers_clone,
                    mp_clone,
                    addr_str,
                    sk_clone,
                    NETWORK_MAINNET,
                )
                .await;
            }
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"notjson").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Unrecognized data\n");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_transaction_added_to_mempool() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let bc = Arc::new(Mutex::new(Blockchain::new(None)));
        let peers = Arc::new(PeerList::new());
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let sk = Arc::new(SecretKey::from_slice(&[1u8; 32]).unwrap());

        let bc_clone = bc.clone();
        let peers_clone = peers.clone();
        let mp_clone = mempool.clone();
        let addr_str = addr.to_string();
        let sk_clone = sk.clone();
        let server = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                handle_client_with_chain(
                    stream,
                    bc_clone,
                    peers_clone,
                    mp_clone,
                    addr_str,
                    sk_clone,
                    NETWORK_MAINNET,
                )
                .await;
            }
        });

        // create a signed transaction
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let tx_sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &tx_sk);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "bob".into(),
            amount: 1,
            nonce: 0,
            signature: None,
        };
        tx.sign(&tx_sk);

        send_message(
            &addr.to_string(),
            &NetworkMessage::Transaction(tx.clone()),
            &sk,
        )
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(mempool.lock().unwrap().pending, vec![tx]);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_large_transaction_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let bc = Arc::new(Mutex::new(Blockchain::new(None)));
        let peers = Arc::new(PeerList::new());
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let sk = Arc::new(SecretKey::from_slice(&[1u8; 32]).unwrap());

        let bc_clone = bc.clone();
        let peers_clone = peers.clone();
        let mp_clone = mempool.clone();
        let addr_str = addr.to_string();
        let sk_clone = sk.clone();
        let server = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                handle_client_with_chain(
                    stream,
                    bc_clone,
                    peers_clone,
                    mp_clone,
                    addr_str,
                    sk_clone,
                    NETWORK_MAINNET,
                )
                .await;
            }
        });

        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let tx_sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &tx_sk);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "x".repeat(5000),
            amount: 1,
            nonce: 0,
            signature: None,
        };
        tx.sign(&tx_sk);

        send_message(
            &addr.to_string(),
            &NetworkMessage::Transaction(tx.clone()),
            &sk,
        )
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(mempool.lock().unwrap().pending, vec![tx]);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_large_peerlist() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let sk_server = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk_client = SecretKey::from_slice(&[2u8; 32]).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // read handshake request
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf).await.unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await.unwrap();
                let _req: SignedMessage = serde_json::from_slice(&buf).unwrap();

                // prepare large peer list
                let mut peers = Vec::new();
                for i in 0..200 {
                    peers.push(format!("peer{}", i));
                }
                let resp = SignedMessage::new(NetworkMessage::PeerList(peers), &sk_server);
                let resp_buf = serde_json::to_vec(&resp).unwrap();
                let resp_buf = prefix_with_length(resp_buf);
                stream.write_all(&resp_buf).await.unwrap();
            }
        });

        let peerlist = Arc::new(PeerList::new());
        perform_handshake(
            &addr.to_string(),
            "me",
            peerlist.clone(),
            &sk_client,
            NETWORK_MAINNET,
        )
        .await;
        assert!(peerlist.all().len() >= 200);
    }

    #[test]
    fn signed_message_verify_roundtrip() {
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let msg = NetworkMessage::Text("hello".into());
        let signed = SignedMessage::new(msg.clone(), &sk);
        assert!(signed.verify());

        let mut tampered = signed.clone();
        tampered.message = VersionedMessage::new(NetworkMessage::Text("bye".into()));
        assert!(!tampered.verify());
    }
}
