mod block;
mod blockchain;
mod mempool;
mod network_serialize;
mod peer;
mod storage;
mod transaction;

use blockchain::Blockchain;
use clap::Parser;
use mempool::Mempool;
use network_serialize::{broadcast_message, start_server_with_chain, NetworkMessage};
use peer::PeerList;
use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use storage::{load_chain, save_chain};
use transaction::Transaction;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// TCP port to listen on
    #[arg(long, default_value = "6001")]
    port: String,

    /// Friendly node name for prompts
    #[arg(long, default_value = "node1")]
    node_name: String,

    /// Comma separated peer addresses
    #[arg(long, default_value = "")]
    peers: String,

    /// Path to the blockchain file
    #[arg(long, default_value = "chain.json")]
    chain_file: String,
}
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    // --- Command-line argument parsing using clap ---
    let cli = Cli::parse();
    let port = cli.port;
    let node_name = cli.node_name;
    let peers_csv = cli.peers;
    let chain_file = cli.chain_file;
    let server_addr = format!("127.0.0.1:{}", port);

    // --- Generate keypair for signing ---
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let secret_key = match SecretKey::from_slice(&sk_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            eprintln!("Failed to create secret key: {}", e);
            return;
        }
    };
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let my_address = hex::encode(public_key.serialize());

    // --- Initialize peer list ---
    let peers = Arc::new(PeerList::new());
    for peer_addr in peers_csv.split(',') {
        if !peer_addr.trim().is_empty() {
            peers.add_peer(peer_addr.trim());
        }
    }

    // --- Blockchain: shared (Arc<Mutex<_>> for reconciliation) ---
    let initial_chain = match load_chain(&chain_file) {
        Ok(chain) => {
            println!("[STORAGE] Loaded chain from {}", chain_file);
            chain
        }
        Err(_) => {
            println!("[STORAGE] Starting new chain");
            Blockchain::new()
        }
    };
    let blockchain = Arc::new(Mutex::new(initial_chain));

    // --- Start server in a background task ---
    {
        let bc = blockchain.clone();
        let p = peers.clone();
        let addr = server_addr.clone();
        let me = server_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = start_server_with_chain(&addr, bc, p, me).await {
                eprintln!("Server error: {}", e);
            }
        });
    }

    println!("{} listening on {}", node_name, server_addr);
    println!("{} knows peers: {:?}", node_name, peers.all());

    // --- Mempool demo logic (per node, not shared) ---
    let mut mempool = Mempool::new();
    let mut demo_tx = Transaction {
        sender: my_address.clone(),
        recipient: format!("{}_second_user", node_name),
        amount: 25,
        signature: None,
    };
    demo_tx.sign(&secret_key);
    mempool.add_tx(demo_tx);
    let txs_to_commit = mempool.drain();
    {
        let mut bc = match blockchain.lock() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Blockchain lock poisoned: {}", e);
                e.into_inner()
            }
        };
        bc.add_block(txs_to_commit, Some(server_addr.clone()));
        if let Err(e) = save_chain(&bc, &chain_file) {
            eprintln!("[STORAGE] Failed to save chain: {}", e);
        }
    }

    // --- Broadcast a greeting and a transaction to all peers ---
    broadcast_message(
        peers.clone(),
        &NetworkMessage::Text(format!("Hello from {}!", node_name)),
    )
    .await;
    let mut tx = Transaction {
        sender: my_address.clone(),
        recipient: "bob".to_string(),
        amount: 42,
        signature: None,
    };
    tx.sign(&secret_key);
    broadcast_message(peers.clone(), &NetworkMessage::Transaction(tx)).await;

    use std::io::{self, Write};

    println!("Type: tx <recipient> <amount>  |  add <peer_addr>  |  remove <peer_addr>  |  list  |  quit");
    println!("Example: tx alice 5");
    println!("Example: add 127.0.0.1:6004");

    loop {
        print!("{}> ", node_name);
        if let Err(e) = io::stdout().flush() {
            eprintln!("Failed to flush stdout: {}", e);
        }
        let mut line = String::new();
        if let Err(e) = io::stdin().read_line(&mut line) {
            eprintln!("Failed to read line: {}", e);
            continue;
        }
        let parts: Vec<_> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "tx" if parts.len() == 3 => {
                let recipient = parts[1].to_string();
                let amount: u64 = parts[2].parse().unwrap_or(0);
                let mut tx = Transaction { sender: my_address.clone(), recipient, amount, signature: None };
                tx.sign(&secret_key);
                let mut bc = match blockchain.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("Blockchain lock poisoned: {}", e);
                        e.into_inner()
                    }
                };
                bc.add_block(vec![tx.clone()], Some(server_addr.clone()));
                if let Err(e) = save_chain(&bc, &chain_file) {
                    eprintln!("[STORAGE] Failed to save chain: {}", e);
                }

                let last_block = match bc.chain.last() {
                    Some(b) => b.clone(),
                    None => {
                        eprintln!("Blockchain empty when broadcasting");
                        continue;
                    }
                };
                drop(bc); // unlock before broadcast
                broadcast_message(peers.clone(), &NetworkMessage::Block(last_block)).await;
            }
            "add" if parts.len() == 2 => {
                let peer_addr = parts[1];
                if !peers.contains(peer_addr) {
                    peers.add_peer(peer_addr);
                    println!("Added peer: {}. Peers now: {:?}", peer_addr, peers.all());
                } else {
                    println!("Peer {} already present.", peer_addr);
                }
            }
            "remove" if parts.len() == 2 => {
                let peer_addr = parts[1];
                peers.remove_peer(peer_addr);
                println!("Removed peer: {}. Remaining peers: {:?}", peer_addr, peers.all());
            }
            "list" => {
                println!("Peers: {:?}", peers.all());
            }
            "quit" | "exit" => {
                println!("Node shutting down.");
                break;
            }
            _ => println!("Unrecognized. Use: tx <recipient> <amount> | add <peer_addr> | remove <peer_addr> | list | quit"),
        }
    }
}
