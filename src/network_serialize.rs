use std::net::{TcpListener, TcpStream};
use std::io::{self, Read, Write};
use std::thread;
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
pub fn handle_client_with_chain(mut stream: TcpStream, blockchain: Arc<Mutex<Blockchain>>, peers: Arc<PeerList>, my_addr: String) {
    let mut buffer = [0; 4096];
    match stream.read(&mut buffer) {
        Ok(size) => {
            if let Ok(msg) = serde_json::from_slice::<NetworkMessage>(&buffer[..size]) {
                match msg {
                    NetworkMessage::Transaction(tx) => {
                        println!("[SERIALIZED] Received Transaction: {:?}", tx);
                        // You may wish to add to mempool here
                    },
                    NetworkMessage::Block(block) => {
                        println!("[SERIALIZED] Received Block: {:?}", block);
                        let mut chain = blockchain.lock().unwrap();
                        let local_tip = chain.chain.last().unwrap().index;
                        if block.index > local_tip {
                            if let Some(sender_addr) = block.sender_addr.clone() {
                                println!("[RECONCILE] Attempting to reconcile with block sender: {}", sender_addr);
                                drop(chain); // unlock before net IO
                                request_chain_and_reconcile(&sender_addr, blockchain.clone());
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

pub fn send_message(addr: &str, msg: &NetworkMessage) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    let buf = msg.serialize();
    stream.write_all(&buf)?;
    let mut buffer = [0; 4096];
    let size = stream.read(&mut buffer)?;
    println!("[SERIALIZED] Server responded: {}", String::from_utf8_lossy(&buffer[..size]));
    Ok(())
}

pub fn broadcast_message(peers: Arc<PeerList>, msg: &NetworkMessage) {
    for peer_addr in peers.all() {
        if let Err(e) = send_message(&peer_addr, msg) {
            eprintln!("Failed to send to {}: {}", peer_addr, e);
        }
    }
}


/// Sends a ChainRequest to `addr` and waits for a ChainResponse.
/// If a longer chain is received and valid, replaces `blockchain`.
pub fn request_chain_and_reconcile(addr: &str, blockchain: Arc<Mutex<Blockchain>>) {
    // Send a ChainRequest
    println!("[RECONCILE] Trying to connect to >{}<", addr); // Diagnostic print
    let req = NetworkMessage::ChainRequest(addr.to_string());
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

