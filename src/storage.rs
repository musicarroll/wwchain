use rocksdb::{Options, WriteBatch, DB};
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use crate::block::Block;
use crate::blockchain::Blockchain;

/// Load the blockchain from a RocksDB database.
/// Each block is stored under its index key and serialized as JSON.
pub fn load_chain(path: &str) -> io::Result<Blockchain> {
    let mut opts = Options::default();
    opts.create_if_missing(false);
    let db = DB::open(&opts, path).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    let mut blocks = Vec::new();
    let mut index = 0u64;
    loop {
        let key = index.to_le_bytes();
        match db
            .get(&key)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?
        {
            Some(bytes) => {
                let block: Block = serde_json::from_slice(&bytes)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                blocks.push(block);
                index += 1;
            }
            None => break,
        }
    }
    if blocks.is_empty() {
        return Err(io::Error::new(ErrorKind::NotFound, "no chain data"));
    }
    let mut chain = Blockchain {
        chain: blocks,
        balances: HashMap::new(),
        puzzle_ownership: HashMap::new(),
        puzzle_attempts: HashMap::new(),
        total_supply: 0,
        difficulty_prefix: crate::blockchain::DIFFICULTY_PREFIX.to_string(),
    };
    if !chain.is_valid_chain() {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid blockchain"));
    }
    chain.recompute_balances();
    chain.recompute_difficulty();
    Ok(chain)
}

/// Append new blocks to the RocksDB database atomically.
/// Existing blocks are left untouched, ensuring durability.
pub fn save_chain(chain: &Blockchain, path: &str) -> io::Result<()> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open(&opts, path).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    // Find current highest index stored
    let mut index = 0u64;
    loop {
        let key = index.to_le_bytes();
        match db
            .get(&key)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?
        {
            Some(_) => index += 1,
            None => break,
        }
    }
    let mut batch = WriteBatch::default();
    for block in chain.chain.iter().skip(index as usize) {
        let key = block.index.to_le_bytes();
        let value = serde_json::to_vec(block)?;
        batch.put(key, value);
    }
    db.write(batch)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;
    use hex;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_chain_rejects_invalid() {
        let dir = std::env::temp_dir().join(format!(
            "invalid_chain_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, &dir).unwrap();
        let genesis = Block::new(0, 0, vec![], "0".into(), None, 0);
        let bad_block = Block::new(1, 0, vec![], "wrong".into(), None, 1);
        db.put(0u64.to_le_bytes(), serde_json::to_vec(&genesis).unwrap())
            .unwrap();
        db.put(1u64.to_le_bytes(), serde_json::to_vec(&bad_block).unwrap())
            .unwrap();
        let res = load_chain(dir.to_str().unwrap());
        fs::remove_dir_all(&dir).unwrap();
        assert!(res.is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "chain_roundtrip_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();

        // Generate a key pair for the sender
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let sender = hex::encode(pk.serialize());

        // Build a short blockchain with one funded genesis address
        let mut bc = Blockchain::new(Some((sender.clone(), 100)));

        // Add a single transaction spending some funds
        let mut tx = Transaction {
            sender: sender.clone(),
            recipient: "bob".into(),
            amount: 25,
            signature: None,
        };
        tx.sign(&sk);
        assert!(bc.add_block(vec![tx], Some(sender.clone())));

        // Persist and reload the chain
        save_chain(&bc, dir.to_str().unwrap()).unwrap();
        let loaded = load_chain(dir.to_str().unwrap()).unwrap();

        // Clean up temporary directory
        fs::remove_dir_all(&dir).unwrap();

        // The reloaded chain should match the original, including balances
        assert_eq!(
            serde_json::to_string(&loaded.chain).unwrap(),
            serde_json::to_string(&bc.chain).unwrap()
        );
        assert_eq!(loaded.balances, bc.balances);
    }
}
