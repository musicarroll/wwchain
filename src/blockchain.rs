use crate::block::Block;
use crate::transaction::Transaction;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Blockchain {
    pub chain: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Self {
        let genesis_tx = Transaction {
            sender: "genesis_address".to_string(),
            recipient: "first_user".to_string(),
            amount: 100,
        };
        let genesis_block = Block::new(
            0,
            0,
            vec![genesis_tx],
            "0".to_string(),
            None, // <-- Genesis block has no sender_addr
        );
        Blockchain { chain: vec![genesis_block] }
    }

    // Make this function accept sender_addr:
    pub fn add_block(&mut self, transactions: Vec<Transaction>, sender_addr: Option<String>) {
        let last_block = self.chain.last().unwrap();
        let index = last_block.index + 1;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let prev_hash = last_block.hash.clone();
        let new_block = Block::new(index, timestamp, transactions, prev_hash, sender_addr);
        self.chain.push(new_block);
    }

    pub fn is_valid_chain(&self) -> bool {
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
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_new_creates_genesis() {
        let bc = Blockchain::new();
        assert_eq!(bc.chain.len(), 1);
        assert_eq!(bc.chain[0].index, 0);
    }

    #[test]
    fn test_add_block() {
        let mut bc = Blockchain::new();
        let tx = Transaction { sender: "a".into(), recipient: "b".into(), amount: 1 };
        bc.add_block(vec![tx.clone()], Some("addr".into()));
        assert_eq!(bc.chain.len(), 2);
        let last = bc.chain.last().unwrap();
        assert_eq!(last.index, 1);
        assert_eq!(last.transactions, vec![tx]);
        assert_eq!(last.prev_hash, bc.chain[0].hash);
    }

    #[test]
    fn test_is_valid_chain_detection() {
        let mut bc = Blockchain::new();
        bc.add_block(
            vec![Transaction { sender: "a".into(), recipient: "b".into(), amount: 2 }],
            Some("addr".into()),
        );
        assert!(bc.is_valid_chain());
        bc.chain[1].prev_hash = "bad".into();
        assert!(!bc.is_valid_chain());
    }
}
