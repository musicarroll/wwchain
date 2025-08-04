use crate::block::Block;
use crate::transaction::Transaction;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DIFFICULTY_PREFIX: &str = "0000";
const DIFFICULTY_ADJUSTMENT_INTERVAL: usize = 10;
const TARGET_BLOCK_TIME_MS: u128 = 10_000;

/// Address used to mint new tokens as rewards.
pub const MINT_ADDRESS: &str = "mint";
/// Number of tokens awarded for solving a puzzle.
pub const REWARD_AMOUNT: u64 = 50;
/// Maximum number of tokens that can ever exist.
pub const MAX_SUPPLY: u64 = 21_000_000;

#[derive(Clone)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub balances: HashMap<String, u64>,
    pub puzzle_ownership: HashMap<String, u64>,
    pub puzzle_attempts: HashMap<String, u64>,
    pub total_supply: u64,
    pub difficulty_prefix: String,
}

impl Blockchain {
    pub fn new(genesis: Option<(String, u64)>) -> Self {
        let txs = match genesis {
            Some((recipient, amount)) => vec![Transaction {
                sender: "genesis_address".to_string(),
                recipient,
                amount,
                signature: None,
            }],
            None => Vec::new(),
        };
        let mut genesis_block = Block::new(
            0,
            0,
            txs,
            "0".to_string(),
            None, // <-- Genesis block has no sender_addr
            0,
        );
        genesis_block.mine(DIFFICULTY_PREFIX);
        let mut bc = Blockchain {
            chain: vec![genesis_block],
            balances: HashMap::new(),
            puzzle_ownership: HashMap::new(),
            puzzle_attempts: HashMap::new(),
            total_supply: 0,
            difficulty_prefix: DIFFICULTY_PREFIX.to_string(),
        };
        bc.recompute_balances();
        bc
    }

    pub fn recompute_balances(&mut self) -> bool {
        let mut bals = HashMap::new();
        let mut ownership = HashMap::new();
        let mut attempts = HashMap::new();
        let mut supply = 0u64;

        for (idx, block) in self.chain.iter().enumerate() {
            if idx != 0 {
                if let Some(addr) = &block.sender_addr {
                    *ownership.entry(addr.clone()).or_insert(0) += 1;
                    *attempts.entry(addr.clone()).or_insert(0) += 1;
                }
            }

            for tx in &block.transactions {
                if idx != 0
                    && tx.sender != "genesis_address"
                    && tx.sender != MINT_ADDRESS
                    && !tx.verify()
                {
                    tracing::info!("[VALIDATION] Invalid tx signature in block {}", idx);
                    return false;
                }

                if tx.sender == "genesis_address" || tx.sender == MINT_ADDRESS {
                    let rbal = bals.get(&tx.recipient).copied().unwrap_or(0);
                    bals.insert(tx.recipient.clone(), rbal + tx.amount);
                    supply += tx.amount;
                    continue;
                }

                let sbal = bals.get(&tx.sender).copied().unwrap_or(0);
                if sbal < tx.amount {
                    tracing::info!("[VALIDATION] Overspend in block {}", idx);
                }
                bals.insert(tx.sender.clone(), sbal.saturating_sub(tx.amount));
                let rbal = bals.get(&tx.recipient).copied().unwrap_or(0);
                bals.insert(tx.recipient.clone(), rbal + tx.amount);
            }
        }

        self.balances = bals;
        self.puzzle_ownership = ownership;
        self.puzzle_attempts = attempts;
        self.total_supply = supply;
        true
    }

    pub(crate) fn chain_work(chain: &[Block]) -> usize {
        chain
            .iter()
            .map(|b| {
                let mut hasher = Sha256::new();
                hasher.update(b.puzzle_id.to_be_bytes());
                hasher.update(b.puzzle_solution.to_le_bytes());
                let result = hasher.finalize();
                hex::encode(result)
                    .chars()
                    .take_while(|c| *c == '0')
                    .count()
            })
            .sum()
    }

    pub fn total_work(&self) -> usize {
        Self::chain_work(&self.chain)
    }

    pub fn add_block(
        &mut self,
        mut transactions: Vec<Transaction>,
        sender_addr: Option<String>,
    ) -> bool {
        if !transactions.iter().all(|tx| tx.verify()) {
            tracing::info!("[BLOCKCHAIN] Rejected block with invalid transaction signature");
            return false;
        }

        // Mint reward if under cap
        let mut minted = 0u64;
        if let Some(addr) = &sender_addr {
            if self.total_supply + REWARD_AMOUNT <= MAX_SUPPLY {
                transactions.insert(
                    0,
                    Transaction {
                        sender: MINT_ADDRESS.to_string(),
                        recipient: addr.clone(),
                        amount: REWARD_AMOUNT,
                        signature: None,
                    },
                );
                minted = REWARD_AMOUNT;
            }
        }

        let mut temp_balances = self.balances.clone();
        for tx in &transactions {
            if tx.sender == MINT_ADDRESS {
                let rbal = temp_balances.get(&tx.recipient).copied().unwrap_or(0);
                temp_balances.insert(tx.recipient.clone(), rbal + tx.amount);
                continue;
            }
            let sbal = temp_balances.get(&tx.sender).copied().unwrap_or(0);
            if sbal < tx.amount {
                tracing::info!("[BLOCKCHAIN] Rejected block - overspend by {}", tx.sender);
                return false;
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
        let mut new_block = Block::new(
            index,
            timestamp,
            transactions,
            prev_hash,
            sender_addr.clone(),
            index,
        );
        new_block.mine(&self.difficulty_prefix);
        self.chain.push(new_block);
        self.balances = temp_balances;

        if let Some(addr) = sender_addr {
            *self.puzzle_ownership.entry(addr.clone()).or_insert(0) += 1;
            *self.puzzle_attempts.entry(addr).or_insert(0) += 1;
        }
        self.total_supply += minted;
        self.adjust_difficulty();
        true
    }

    fn adjust_difficulty(&mut self) {
        let len = self.chain.len();
        if len <= DIFFICULTY_ADJUSTMENT_INTERVAL {
            return;
        }
        if (len - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
            return;
        }
        let last = &self.chain[len - 1];
        let prev = &self.chain[len - 1 - DIFFICULTY_ADJUSTMENT_INTERVAL];
        let actual_time = last.timestamp.saturating_sub(prev.timestamp);
        let expected_time = TARGET_BLOCK_TIME_MS * DIFFICULTY_ADJUSTMENT_INTERVAL as u128;
        if actual_time < expected_time / 2 {
            self.difficulty_prefix.push('0');
        } else if actual_time > expected_time * 2 && self.difficulty_prefix.len() > 1 {
            self.difficulty_prefix.pop();
        }
    }

    pub fn recompute_difficulty(&mut self) {
        self.difficulty_prefix = DIFFICULTY_PREFIX.to_string();
        for i in 1..self.chain.len() {
            if i % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                let last = &self.chain[i];
                let prev = &self.chain[i - DIFFICULTY_ADJUSTMENT_INTERVAL];
                let actual_time = last.timestamp.saturating_sub(prev.timestamp);
                let expected_time = TARGET_BLOCK_TIME_MS * DIFFICULTY_ADJUSTMENT_INTERVAL as u128;
                if actual_time < expected_time / 2 {
                    self.difficulty_prefix.push('0');
                } else if actual_time > expected_time * 2 && self.difficulty_prefix.len() > 1 {
                    self.difficulty_prefix.pop();
                }
            }
        }
    }

    pub fn is_valid_chain(&self) -> bool {
        if self.chain.is_empty() {
            return false;
        }
        let genesis = &self.chain[0];
        if genesis.hash != genesis.calculate_hash() || !genesis.is_puzzle_valid(DIFFICULTY_PREFIX) {
            tracing::info!("Genesis block invalid");
            return false;
        }
        for i in 1..self.chain.len() {
            let prev = &self.chain[i - 1];
            let curr = &self.chain[i];
            if curr.index != prev.index + 1 {
                tracing::info!("Invalid index at block {}", i);
                return false;
            }
            if curr.prev_hash != prev.hash {
                tracing::info!("Broken hash link at block {}", i);
                return false;
            }
            if curr.hash != curr.calculate_hash() {
                tracing::info!("Block {} has invalid hash!", i);
                return false;
            }
            if !curr.is_puzzle_valid(DIFFICULTY_PREFIX) {
                tracing::info!("Block {} does not satisfy PoW", i);
                return false;
            }
        }
        let mut tmp = self.clone();
        tmp.recompute_balances()
    }

    pub fn voting_power(&self, addr: &str) -> u64 {
        let bal = self.balances.get(addr).copied().unwrap_or(0);
        let owned = self.puzzle_ownership.get(addr).copied().unwrap_or(0);
        let attempted = self.puzzle_attempts.get(addr).copied().unwrap_or(0);
        bal + owned + attempted
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
        let bc = Blockchain::new(None);
        assert_eq!(bc.chain.len(), 1);
        assert_eq!(bc.chain[0].index, 0);
    }

    #[test]
    fn test_add_block() {
        let mut bc = Blockchain::new(None);
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
        assert!(bc.add_block(vec![tx.clone()], Some("addr".into())));
        assert_eq!(bc.chain.len(), 2);
        let last = bc.chain.last().unwrap();
        assert_eq!(last.index, 1);
        assert_eq!(last.transactions.len(), 2); // reward + tx
        assert_eq!(last.prev_hash, bc.chain[0].hash);
        assert_eq!(bc.balances.get(&tx.sender).copied(), Some(0));
        assert_eq!(bc.balances.get(&"b".to_string()).copied(), Some(1));
        assert_eq!(
            bc.balances.get(&"addr".to_string()).copied(),
            Some(REWARD_AMOUNT)
        );
        assert_eq!(bc.puzzle_ownership.get("addr"), Some(&1));
        assert_eq!(bc.puzzle_attempts.get("addr"), Some(&1));
    }

    #[test]
    fn test_reject_overspend() {
        let mut bc = Blockchain::new(None);
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
        assert!(!bc.add_block(vec![tx], Some("addr".into())));
        assert_eq!(bc.chain.len(), 1); // rejected
    }

    #[test]
    fn test_reject_double_spend_in_block() {
        let mut bc = Blockchain::new(None);
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
        assert!(!bc.add_block(vec![tx1, tx2], Some("addr".into())));
        assert_eq!(bc.chain.len(), 1); // rejected
    }

    #[test]
    fn test_is_valid_chain_detection() {
        let mut bc = Blockchain::new(None);
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
        assert!(bc.add_block(vec![tx], Some("addr".into())));
        assert!(bc.is_valid_chain());
        bc.chain[1].prev_hash = "bad".into();
        assert!(!bc.is_valid_chain());
    }

    #[test]
    fn test_invalid_block_hash_detected() {
        let mut bc = Blockchain::new(None);
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
        assert!(bc.add_block(vec![tx], Some("addr".into())));
        assert!(bc.is_valid_chain());
        // Corrupt the stored hash so PoW and hash check fail
        bc.chain[1].hash = "1234".into();
        assert!(!bc.is_valid_chain());
    }

    #[test]
    fn test_reject_replayed_transaction() {
        let mut bc = Blockchain::new(None);
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
        assert!(bc.add_block(vec![tx.clone()], Some("addr".into())));
        assert_eq!(bc.chain.len(), 2);
        // Replay the same transaction which should now overspend
        assert!(!bc.add_block(vec![tx], Some("addr".into())));
        assert_eq!(bc.chain.len(), 2); // second block rejected
    }

    #[test]
    fn test_voting_power_calculation() {
        let mut bc = Blockchain::new(None);
        bc.balances.insert("alice".into(), 10);
        bc.puzzle_ownership.insert("alice".into(), 2);
        bc.puzzle_attempts.insert("alice".into(), 3);
        assert_eq!(bc.voting_power("alice"), 15);
    }

    #[test]
    fn test_difficulty_adjustment() {
        let mut bc = Blockchain::new(None);
        let initial = bc.difficulty_prefix.clone();
        for i in 1..=super::DIFFICULTY_ADJUSTMENT_INTERVAL {
            let prev_hash = bc.chain.last().unwrap().hash.clone();
            let block = Block {
                index: i as u64,
                timestamp: i as u128, // very fast blocks
                transactions: vec![],
                prev_hash,
                hash: String::new(),
                sender_addr: None,
                puzzle_id: i as u64,
                puzzle_solution: 0,
            };
            bc.chain.push(block);
        }
        bc.adjust_difficulty();
        assert!(bc.difficulty_prefix.len() > initial.len());
    }
}
