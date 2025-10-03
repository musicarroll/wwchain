use wwchain::blockchain::Blockchain;
use clap::{Parser, ValueEnum};
use wwchain::mempool::Mempool;
use wwchain::network_serialize::{
    broadcast_message, perform_handshake, start_server_with_chain, NetworkMessage, NETWORK_MAINNET,
    NETWORK_TESTNET,
};
#[cfg(feature = "tls")]
use wwchain::network_serialize::{
    broadcast_tls_message, create_tls_connector, perform_tls_handshake,
    request_chain_and_reconcile_tls, start_tls_server_with_chain,
};
use wwchain::peer::PeerList;
use regex::Regex;
use wwchain::storage::{load_chain, save_chain};
use tokio::time::{sleep, Duration};
use wwchain::transaction::Transaction;
use wwchain::wallet::Wallet;

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

    /// Network to connect to (mainnet or testnet)
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network,

    /// TLS certificate for secure connections
    #[cfg(feature = "tls")]
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS private key for secure connections
    #[cfg(feature = "tls")]
    #[arg(long)]
    tls_key: Option<String>,
}
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    fn id(&self) -> u8 {
        match self {
            Network::Mainnet => NETWORK_MAINNET,
            Network::Testnet => NETWORK_TESTNET,
        }
    }
}

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
    let mut chain_dir = cli.chain_dir;
    let network = cli.network;
    if matches!(network, Network::Testnet) && chain_dir == "chain_db" {
        chain_dir = "test_chain_db".to_string();
    }
    #[cfg(feature = "tls")]
    let tls_cert = cli.tls_cert.clone();
    #[cfg(feature = "tls")]
    let tls_key = cli.tls_key.clone();
    let network_id = network.id();
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
            let mut chain = Blockchain::new(Some((my_address.clone(), 100)));
            if matches!(network, Network::Testnet) {
                chain.difficulty_prefix = "00".into();
            }
            chain
        }
    };
    let starting_balance = wallet.balance(&initial_chain);
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
        #[cfg(feature = "tls")]
        let cert_opt = tls_cert.clone();
        #[cfg(feature = "tls")]
        let key_opt = tls_key.clone();
        tokio::spawn(async move {
            #[cfg(feature = "tls")]
            if let (Some(cert), Some(key)) = (cert_opt, key_opt) {
                if let Err(e) = start_tls_server_with_chain(
                    &addr,
                    bc,
                    p,
                    mp,
                    me,
                    Arc::new(sk),
                    &cert,
                    &key,
                    network_id,
                )
                .await
                {
                    tracing::error!("Server error: {}", e);
                }
                return;
            }
            if let Err(e) =
                start_server_with_chain(&addr, bc, p, mp, me, Arc::new(sk), network_id).await
            {
                tracing::error!("Server error: {}", e);
            }
        });
    }

    // Perform handshake with known peers
    #[cfg(feature = "tls")]
    let connector = create_tls_connector();
    for peer_addr in peers.all() {
        #[cfg(feature = "tls")]
        {
            if tls_cert.is_some() && tls_key.is_some() {
                perform_tls_handshake(
                    &peer_addr,
                    &server_addr,
                    peers.clone(),
                    &secret_key,
                    &connector,
                    network_id,
                )
                .await;
                continue;
            }
        }
        perform_handshake(
            &peer_addr,
            &server_addr,
            peers.clone(),
            &secret_key,
            network_id,
        )
        .await;
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
        #[cfg(feature = "tls")]
        let cert_opt = tls_cert.clone();
        #[cfg(feature = "tls")]
        let key_opt = tls_key.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                let txs_opt = {
                    let mut m = mp.lock().unwrap();
                    if m.pending.is_empty() {
                        None
                    } else {
                        Some(m.drain())
                    }
                };
                let Some(txs) = txs_opt else {
                    continue;
                };
                let block_opt = {
                    let mut chain = bc.lock().unwrap();
                    if chain.add_block(txs, Some(addr.clone())) {
                        if let Err(e) = save_chain(&chain, &chain_dir) {
                            tracing::error!("[STORAGE] Failed to save chain: {}", e);
                        }
                        Some(chain.chain.last().unwrap().clone())
                    } else {
                        None
                    }
                };
                if let Some(block) = block_opt {
                    #[cfg(feature = "tls")]
                    if let (Some(cert), Some(key)) = (cert_opt.clone(), key_opt.clone()) {
                        let connector = create_tls_connector();
                        broadcast_tls_message(
                            peers_clone.clone(),
                            &NetworkMessage::Block(block),
                            &sk,
                            &connector,
                        )
                        .await;
                    } else {
                        broadcast_message(peers_clone.clone(), &NetworkMessage::Block(block), &sk)
                            .await;
                    }
                    #[cfg(not(feature = "tls"))]
                    broadcast_message(peers_clone.clone(), &NetworkMessage::Block(block), &sk)
                        .await;
                }
            }
        });
    }

    // --- Broadcast a greeting and a transaction to all peers ---
    #[cfg(feature = "tls")]
    if let (Some(_), Some(_)) = (tls_cert.as_ref(), tls_key.as_ref()) {
        let connector = create_tls_connector();
        broadcast_tls_message(
            peers.clone(),
            &NetworkMessage::Text(format!("Hello from {}!", node_name)),
            &secret_key,
            &connector,
        )
        .await;
    } else {
        broadcast_message(
            peers.clone(),
            &NetworkMessage::Text(format!("Hello from {}!", node_name)),
            &secret_key,
        )
        .await;
    }
    #[cfg(not(feature = "tls"))]
    broadcast_message(
        peers.clone(),
        &NetworkMessage::Text(format!("Hello from {}!", node_name)),
        &secret_key,
    )
    .await;
    if let Some(tx) = {
        let bc = match blockchain.lock() {
            Ok(b) => b,
            Err(e) => e.into_inner(),
        };
        wallet.create_transaction("bob".to_string(), 42, &bc)
    } {
        #[cfg(feature = "tls")]
        if let (Some(_), Some(_)) = (tls_cert.as_ref(), tls_key.as_ref()) {
            let connector = create_tls_connector();
            broadcast_tls_message(
                peers.clone(),
                &NetworkMessage::Transaction(tx),
                &secret_key,
                &connector,
            )
            .await;
        } else {
            broadcast_message(peers.clone(), &NetworkMessage::Transaction(tx), &secret_key).await;
        }
        #[cfg(not(feature = "tls"))]
        broadcast_message(peers.clone(), &NetworkMessage::Transaction(tx), &secret_key).await;
    }

    use std::io::{self, Write};

    if matches!(network, Network::Testnet) {
        tracing::info!(
            "Type: tx <recipient> <amount>  |  add <peer_addr>  |  remove <peer_addr>  |  list  |  balance  |  puzzle-stats [<address>]  |  search <regex>  |  quit"
        );
    } else {
        tracing::info!(
            "Type: tx <recipient> <amount>  |  add <peer_addr>  |  remove <peer_addr>  |  list  |  balance  |  search <regex>  |  quit"
        );
    }
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
                let tx_opt = {
                    let bc = match blockchain.lock() {
                        Ok(b) => b,
                        Err(e) => e.into_inner(),
                    };
                    wallet.create_transaction(recipient, amount, &bc)
                };
                let Some(tx) = tx_opt else {
                    tracing::error!("Failed to create transaction. Possibly insufficient funds.");
                    continue;
                };
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
                    #[cfg(feature = "tls")]
                    if let (Some(_), Some(_)) = (tls_cert.as_ref(), tls_key.as_ref()) {
                        let connector = create_tls_connector();
                        broadcast_tls_message(
                            peers.clone(),
                            &NetworkMessage::Block(last_block),
                            &secret_key,
                            &connector,
                        )
                        .await;
                    } else {
                        broadcast_message(peers.clone(), &NetworkMessage::Block(last_block), &secret_key)
                            .await;
                    }
                    #[cfg(not(feature = "tls"))]
                    broadcast_message(peers.clone(), &NetworkMessage::Block(last_block), &secret_key)
                        .await;
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
                if parts.len() == 2 {
                    let addr = parts[1];
                    let bal = bc.balances.get(addr).copied().unwrap_or(0);
                    tracing::info!("Balance for {}: {}", addr, bal);
                } else {
                    let bal = wallet.balance(&bc);
                    tracing::info!("Balance for {}: {}", my_address, bal);
                }
            }
            "puzzle-stats" if matches!(network, Network::Testnet) => {
                let bc = match blockchain.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!("Blockchain lock poisoned: {}", e);
                        e.into_inner()
                    }
                };
                if parts.len() == 2 {
                    let addr = parts[1];
                    let owned = bc.puzzle_ownership.get(addr).copied().unwrap_or(0);
                    let attempts = bc.puzzle_attempts.get(addr).copied().unwrap_or(0);
                    tracing::info!(
                        "Puzzle stats for {}: ownership {} attempts {}",
                        addr,
                        owned,
                        attempts
                    );
                } else {
                    use std::collections::BTreeSet;
                    let mut addrs = BTreeSet::new();
                    addrs.extend(bc.puzzle_ownership.keys().cloned());
                    addrs.extend(bc.puzzle_attempts.keys().cloned());
                    for addr in addrs {
                        let owned = bc.puzzle_ownership.get(&addr).copied().unwrap_or(0);
                        let attempts = bc.puzzle_attempts.get(&addr).copied().unwrap_or(0);
                        tracing::info!(
                            "{}: ownership {} attempts {}",
                            addr,
                            owned,
                            attempts
                        );
                    }
                }
            }
            "search" if parts.len() >= 2 => {
                let pattern = parts[1..].join(" ");
                let re = match Regex::new(&pattern) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("Invalid regex: {}", e);
                        continue;
                    }
                };
                let bc = match blockchain.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!("Blockchain lock poisoned: {}", e);
                        e.into_inner()
                    }
                };
                let matches = bc.search(&re);
                if matches.is_empty() {
                    tracing::info!("No matches found for {}", pattern);
                } else {
                    for m in matches {
                        tracing::info!("{}", m);
                    }
                }
            }
            "quit" | "exit" => {
                tracing::info!("Node shutting down.");
                let _ = peers.save_to_file(&peers_file);
                break;
            }
            _ => tracing::info!("Unrecognized. Use: tx <recipient> <amount> | add <peer_addr> | remove <peer_addr> | list | balance | search <regex> | quit"),
        }
    }
}
