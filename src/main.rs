mod block;
mod blockchain;
mod mempool;
mod network_serialize;
mod peer;
mod storage;
mod transaction;
mod wallet;

use blockchain::Blockchain;
use clap::Parser;
use mempool::Mempool;
use network_serialize::{
    broadcast_message, perform_handshake, start_server_with_chain, NetworkMessage,
};
use peer::PeerList;
use storage::{load_chain, save_chain};
use transaction::Transaction;
use wallet::Wallet;
use tokio::time::{sleep, Duration};

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

    /// Directory for the blockchain database
    #[arg(long, default_value = "chain_db")]
    chain_dir: String,
}
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // --- Command-line argument parsing using clap ---
    let cli = Cli::parse();
    let port = cli.port;
    let node_name = cli.node_name;
    let peers_csv = cli.peers;
    let chain_dir = cli.chain_dir;
    let server_addr = format!("127.0.0.1:{}", port);

    // --- Load or create wallet ---
    let wallet_path = std::path::Path::new(&chain_dir).join("wallet.key");
    let wallet = match Wallet::load_or_create(&wallet_path) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to load wallet: {}", e);
            return;
        }
    };
    let secret_key = wallet.secret_key().clone();
    let my_address = wallet.address().to_string();

    // --- Initialize peer list ---
    let peers_file = std::path::Path::new(&chain_dir).join("peers.json");
    let peers = Arc::new(PeerList::load_from_file(&peers_file).unwrap_or_else(|_| PeerList::new()));
    for peer_addr in peers_csv.split(',') {
        if !peer_addr.trim().is_empty() {
            peers.add_peer(peer_addr.trim());
        }
    }
    let _ = peers.save_to_file(&peers_file);

    // --- Blockchain: shared (Arc<Mutex<_>> for reconciliation) ---
    let mut initial_chain = match load_chain(&chain_dir) {
        Ok(chain) => {
            tracing::info!("[STORAGE] Loaded chain from {}", chain_dir);
            chain
        }
        Err(_) => {
            tracing::info!("[STORAGE] Starting new chain");
            Blockchain::new(Some((my_address.clone(), 100)))
        }
    };
    let starting_balance = initial_chain
        .balances
        .get(&my_address)
        .copied()
        .unwrap_or(0);
    tracing::info!(
        "Wallet address {} starting balance {}",
        my_address,
        starting_balance
    );
    let blockchain = Arc::new(Mutex::new(initial_chain));
    // --- Shared mempool ---
    let mempool = Arc::new(Mutex::new(Mempool::new()));

    // --- Start server in a background task ---
    {
        let bc = blockchain.clone();
        let p = peers.clone();
        let mp = mempool.clone();
        let addr = server_addr.clone();
        let me = server_addr.clone();
        let sk = secret_key.clone();
        tokio::spawn(async move {
            if let Err(e) = start_server_with_chain(&addr, bc, p, mp, me, Arc::new(sk)).await {
                tracing::error!("Server error: {}", e);
            }
        });
    }

    // Perform handshake with known peers
    for peer_addr in peers.all() {
        perform_handshake(&peer_addr, &server_addr, peers.clone(), &secret_key).await;
    }
    let _ = peers.save_to_file(&peers_file);

    tracing::info!("{} listening on {}", node_name, server_addr);
    tracing::info!("{} knows peers: {:?}", node_name, peers.all());

    // --- Periodically mine or broadcast pending transactions ---
    {
        let bc = blockchain.clone();
        let mp = mempool.clone();
        let peers_clone = peers.clone();
        let addr = server_addr.clone();
        let sk = secret_key.clone();
        let chain_dir = chain_dir.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                let txs = {
                    let mut m = mp.lock().unwrap();
                    if m.pending.is_empty() {
                        continue;
                    }
                    m.drain()
                };
                let mut chain = bc.lock().unwrap();
                if chain.add_block(txs, Some(addr.clone())) {
                    if let Err(e) = save_chain(&chain, &chain_dir) {
                        tracing::error!("[STORAGE] Failed to save chain: {}", e);
                    }
                    let block = chain.chain.last().unwrap().clone();
                    drop(chain);
                    broadcast_message(peers_clone.clone(), &NetworkMessage::Block(block), &sk).await;
                }
            }
        });
    }


    // --- Broadcast a greeting and a transaction to all peers ---
    broadcast_message(
        peers.clone(),
        &NetworkMessage::Text(format!("Hello from {}!", node_name)),
        &secret_key,
    )
    .await;
    let mut tx = Transaction {
        sender: my_address.clone(),
        recipient: "bob".to_string(),
        amount: 42,
        signature: None,
    };
    tx.sign(&secret_key);
    broadcast_message(peers.clone(), &NetworkMessage::Transaction(tx), &secret_key).await;

    use std::io::{self, Write};

    tracing::info!("Type: tx <recipient> <amount>  |  add <peer_addr>  |  remove <peer_addr>  |  list  |  balance  |  quit");
    tracing::info!("Example: tx alice 5");
    tracing::info!("Example: add 127.0.0.1:6004");

    loop {
        print!("{}> ", node_name);
        if let Err(e) = io::stdout().flush() {
            tracing::error!("Failed to flush stdout: {}", e);
        }
        let mut line = String::new();
        if let Err(e) = io::stdin().read_line(&mut line) {
            tracing::error!("Failed to read line: {}", e);
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
                        tracing::error!("Blockchain lock poisoned: {}", e);
                        e.into_inner()
                    }
                };
                let added = bc.add_block(vec![tx.clone()], Some(server_addr.clone()));
                if added {
                    if let Err(e) = save_chain(&bc, &chain_dir) {
                        tracing::error!("[STORAGE] Failed to save chain: {}", e);
                    }

                    let last_block = match bc.chain.last() {
                        Some(b) => b.clone(),
                        None => {
                            tracing::error!("Blockchain empty when broadcasting");
                            continue;
                        }
                    };
                    drop(bc); // unlock before broadcast
                    broadcast_message(peers.clone(), &NetworkMessage::Block(last_block), &secret_key).await;
                } else {
                    tracing::error!("Failed to add block. Possibly insufficient funds.");
                }
            }
            "add" if parts.len() == 2 => {
                let peer_addr = parts[1];
                if !peers.contains(peer_addr) {
                    peers.add_peer(peer_addr);
                    let _ = peers.save_to_file(&peers_file);
                    tracing::info!("Added peer: {}. Peers now: {:?}", peer_addr, peers.all());
                } else {
                    tracing::info!("Peer {} already present.", peer_addr);
                }
            }
            "remove" if parts.len() == 2 => {
                let peer_addr = parts[1];
                peers.remove_peer(peer_addr);
                let _ = peers.save_to_file(&peers_file);
                tracing::info!("Removed peer: {}. Remaining peers: {:?}", peer_addr, peers.all());
            }
            "list" => {
                tracing::info!("Peers: {:?}", peers.all());
            }
            "balance" => {
                let bc = match blockchain.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!("Blockchain lock poisoned: {}", e);
                        e.into_inner()
                    }
                };
                let bal = bc.balances.get(&my_address).copied().unwrap_or(0);
                tracing::info!("Balance for {}: {}", my_address, bal);
            }
            "quit" | "exit" => {
                tracing::info!("Node shutting down.");
                let _ = peers.save_to_file(&peers_file);
                break;
            }
            _ => tracing::info!("Unrecognized. Use: tx <recipient> <amount> | add <peer_addr> | remove <peer_addr> | list | balance | quit"),
        }
    }
}
