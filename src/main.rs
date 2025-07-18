mod transaction;
mod block;
mod blockchain;
mod mempool;
mod network_serialize;
mod peer;

use transaction::Transaction;
use blockchain::Blockchain;
use mempool::Mempool;
use network_serialize::{NetworkMessage, start_server_with_chain, broadcast_message};
use peer::PeerList;
use clap::Parser;

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
}
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    // --- Command-line argument parsing using clap ---
    let cli = Cli::parse();
    let port = cli.port;
    let node_name = cli.node_name;
    let peers_csv = cli.peers;
    let server_addr = format!("127.0.0.1:{}", port);

    // --- Initialize peer list ---
    let peers = Arc::new(PeerList::new());
    for peer_addr in peers_csv.split(',') {
        if !peer_addr.trim().is_empty() {
            peers.add_peer(peer_addr.trim());
        }
    }

    // --- Blockchain: shared (Arc<Mutex<_>> for reconciliation) ---
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));

    // --- Start server in a background task ---
    {
        let bc = blockchain.clone();
        let p = peers.clone();
        let addr = server_addr.clone();
        let me = server_addr.clone();
        tokio::spawn(async move {
            start_server_with_chain(&addr, bc, p, me).await.unwrap();
        });
    }

    println!("{} listening on {}", node_name, server_addr);
    println!("{} knows peers: {:?}", node_name, peers.all());

    // --- Mempool demo logic (per node, not shared) ---
    let mut mempool = Mempool::new();
    mempool.add_tx(Transaction {
        sender: format!("{}_first_user", node_name),
        recipient: format!("{}_second_user", node_name),
        amount: 25,
    });
    let txs_to_commit = mempool.drain();
    {
        let mut bc = blockchain.lock().unwrap();
        bc.add_block(txs_to_commit, Some(server_addr.clone()));

    }

    // --- Broadcast a greeting and a transaction to all peers ---
    broadcast_message(peers.clone(), &NetworkMessage::Text(format!("Hello from {}!", node_name))).await;
    let tx = Transaction {
        sender: node_name.clone(),
        recipient: "bob".to_string(),
        amount: 42,
    };
    broadcast_message(peers.clone(), &NetworkMessage::Transaction(tx)).await;

    use std::io::{self, Write};

    println!("Type: tx <recipient> <amount>  |  add <peer_addr>  |  remove <peer_addr>  |  list  |  quit");
    println!("Example: tx alice 5");
    println!("Example: add 127.0.0.1:6004");

    loop {
        print!("{}> ", node_name);
        io::stdout().flush().unwrap();
        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
        let parts: Vec<_> = line.trim().split_whitespace().collect();
        if parts.is_empty() { continue; }
        match parts[0] {
            "tx" if parts.len() == 3 => {
                let recipient = parts[1].to_string();
                let amount: u64 = parts[2].parse().unwrap_or(0);
                let tx = Transaction { sender: node_name.clone(), recipient, amount };
                let mut bc = blockchain.lock().unwrap();
                bc.add_block(vec![tx.clone()], Some(server_addr.clone()));

                let last_block = bc.chain.last().unwrap().clone();
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
