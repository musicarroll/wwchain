use crate::block::Block;
use crate::transaction::Transaction;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DIFFICULTY_PREFIX: &str = "0000";

#[derive(Clone)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub balances: HashMap<String, u64>,
}

impl Blockchain {
    pub fn new() -> Self {
        let genesis_tx = Transaction {
            sender: "genesis_address".to_string(),
            recipient: "first_user".to_string(),
            amount: 100,
            signature: None,
        };
        let mut genesis_block = Block::new(
            0,
            0,
            vec![genesis_tx],
            "0".to_string(),
            None, // <-- Genesis block has no sender_addr
        );
        genesis_block.mine(DIFFICULTY_PREFIX);
        let mut bc = Blockchain {
            chain: vec![genesis_block],
            balances: HashMap::new(),
        };
        bc.recompute_balances();
        bc
    }

    pub fn recompute_balances(&mut self) -> bool {
        let mut bals = HashMap::new();
        for (idx, block) in self.chain.iter().enumerate() {
            for tx in &block.transactions {
                if idx != 0 && !tx.verify() {
                    println!("[VALIDATION] Invalid tx signature in block {}", idx);
                    return false;
                }
                if idx == 0 {
                    let rbal = bals.get(&tx.recipient).copied().unwrap_or(0);
                    bals.insert(tx.recipient.clone(), rbal + tx.amount);
                    continue;
                }
                let sbal = bals.get(&tx.sender).copied().unwrap_or(0);
                if sbal < tx.amount {
                    println!("[VALIDATION] Overspend in block {}", idx);
                }
                bals.insert(tx.sender.clone(), sbal.saturating_sub(tx.amount));
                let rbal = bals.get(&tx.recipient).copied().unwrap_or(0);
                bals.insert(tx.recipient.clone(), rbal + tx.amount);
            }
        }
        self.balances = bals;
        true
    }

    pub(crate) fn chain_work(chain: &[Block]) -> usize {
        chain
            .iter()
            .map(|b| b.hash.chars().take_while(|c| *c == '0').count())
            .sum()
    }

    pub fn total_work(&self) -> usize {
        Self::chain_work(&self.chain)
    }

    // Make this function accept sender_addr:
    pub fn add_block(&mut self, transactions: Vec<Transaction>, sender_addr: Option<String>) {
        if !transactions.iter().all(|tx| tx.verify()) {
            println!("[BLOCKCHAIN] Rejected block with invalid transaction signature");
            return;
        }
        let mut temp_balances = self.balances.clone();
        for tx in &transactions {
            let sbal = temp_balances.get(&tx.sender).copied().unwrap_or(0);
            if sbal < tx.amount {
                println!("[BLOCKCHAIN] Rejected block - overspend by {}", tx.sender);
                return;
            }
            temp_balances.insert(tx.sender.clone(), sbal - tx.amount);
            let rbal = temp_balances.get(&tx.recipient).copied().unwrap_or(0);
            temp_balances.insert(tx.recipient.clone(), rbal + tx.amount);
        }
        let last_block = self.chain.last().unwrap();
        let index = last_block.index + 1;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let prev_hash = last_block.hash.clone();
        let mut new_block = Block::new(index, timestamp, transactions, prev_hash, sender_addr);
        new_block.mine(DIFFICULTY_PREFIX);
        self.chain.push(new_block);
        self.balances = temp_balances;
    }

    pub fn is_valid_chain(&self) -> bool {
        if self.chain.is_empty() {
            return false;
        }
        let genesis = &self.chain[0];
        if genesis.hash != genesis.calculate_hash() || !genesis.hash.starts_with(DIFFICULTY_PREFIX)
        {
            println!("Genesis block invalid");
            return false;
        }
        for i in 1..self.chain.len() {
            let prev = &self.chain[i - 1];
            let curr = &self.chain[i];
            if curr.index != prev.index + 1 {
                println!("Invalid index at block {}", i);
                return false;
            }
            if curr.prev_hash != prev.hash {
                println!("Broken hash link at block {}", i);
                return false;
            }
            if curr.hash != curr.calculate_hash() {
                println!("Block {} has invalid hash!", i);
                return false;
            }
            if !curr.hash.starts_with(DIFFICULTY_PREFIX) {
                println!("Block {} does not satisfy PoW", i);
                return false;
            }
        }
        let mut tmp = self.clone();
        tmp.recompute_balances()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_blockchain_new_creates_genesis() {
        let bc = Blockchain::new();
        assert_eq!(bc.chain.len(), 1);
        assert_eq!(bc.chain[0].index, 0);
    }

    #[test]
    fn test_add_block() {
        let mut bc = Blockchain::new();
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
        bc.balances.insert(tx.sender.clone(), 1);
        bc.add_block(vec![tx.clone()], Some("addr".into()));
        assert_eq!(bc.chain.len(), 2);
        let last = bc.chain.last().unwrap();
        assert_eq!(last.index, 1);
        assert_eq!(last.transactions, vec![tx.clone()]);
        assert_eq!(last.prev_hash, bc.chain[0].hash);
        assert_eq!(bc.balances.get(&tx.sender).copied(), Some(0));
        assert_eq!(bc.balances.get(&"b".to_string()).copied(), Some(1));
    }

    #[test]
    fn test_reject_overspend() {
        let mut bc = Blockchain::new();
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "b".into(),
            amount: 50,
            signature: None,
        };
        tx.sign(&sk);
        bc.add_block(vec![tx], Some("addr".into()));
        assert_eq!(bc.chain.len(), 1); // rejected
    }

    #[test]
    fn test_reject_double_spend_in_block() {
        let mut bc = Blockchain::new();
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut tx1 = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "b".into(),
            amount: 60,
            signature: None,
        };
        tx1.sign(&sk);
        let mut tx2 = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "c".into(),
            amount: 60,
            signature: None,
        };
        tx2.sign(&sk);
        bc.add_block(vec![tx1, tx2], Some("addr".into()));
        assert_eq!(bc.chain.len(), 1); // rejected
    }

    #[test]
    fn test_is_valid_chain_detection() {
        let mut bc = Blockchain::new();
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "b".into(),
            amount: 2,
            signature: None,
        };
        tx.sign(&sk);
        bc.balances.insert(tx.sender.clone(), 2);
        bc.add_block(vec![tx], Some("addr".into()));
        assert!(bc.is_valid_chain());
        bc.chain[1].prev_hash = "bad".into();
        assert!(!bc.is_valid_chain());
    }
}
