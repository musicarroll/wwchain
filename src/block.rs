use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::transaction::Transaction;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub prev_hash: String,
    pub hash: String,
    pub sender_addr: Option<String>,
}

impl Block {
    pub fn new(
        index: u64,
        timestamp: u128,
        transactions: Vec<Transaction>,
        prev_hash: String,
        sender_addr: Option<String>, // <-- Add this argument
    ) -> Self {
        let mut block = Block {
            index,
            timestamp,
            transactions,
            prev_hash,
            hash: String::new(),
            sender_addr, // <-- Use the argument
        };
        block.hash = block.calculate_hash();
        block
    }

    pub fn calculate_hash(&self) -> String {
        let mut block_for_hash = self.clone();
        block_for_hash.hash = String::new();
        let serialized = serde_json::to_string(&block_for_hash).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        let result = hasher.finalize();
        hex::encode(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_new_sets_fields() {
        let tx = Transaction {
            sender: "a".into(),
            recipient: "b".into(),
            amount: 10,
        };
        let block = Block::new(1, 123, vec![tx.clone()], "prev".into(), Some("me".into()));
        assert_eq!(block.index, 1);
        assert_eq!(block.timestamp, 123);
        assert_eq!(block.transactions, vec![tx]);
        assert_eq!(block.prev_hash, "prev");
        assert_eq!(block.sender_addr, Some("me".into()));
        assert_eq!(block.hash, block.calculate_hash());
    }

    #[test]
    fn test_calculate_hash_consistency() {
        let tx = Transaction {
            sender: "x".into(),
            recipient: "y".into(),
            amount: 5,
        };
        let block = Block::new(2, 456, vec![tx], "prevhash".into(), None);
        let h1 = block.hash.clone();
        let h2 = block.calculate_hash();
        assert_eq!(h1, h2);
    }
}
