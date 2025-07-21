use parity_db::{Db, Options, Transaction};
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use crate::block::Block;
use crate::blockchain::Blockchain;

/// Load the blockchain from a parity-db database.
/// Each block is stored under its index key and serialized as JSON.
pub fn load_chain(path: &str) -> io::Result<Blockchain> {
    let mut opts = Options::with_columns(Path::new(path), 1);
    let db = Db::open_or_create(&opts).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    let mut blocks = Vec::new();
    let mut index = 0u64;
    loop {
        let key = index.to_le_bytes();
        match db.get(0, &key).map_err(|e| io::Error::new(ErrorKind::Other, e))? {
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
    };
    if !chain.is_valid_chain() {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid blockchain"));
    }
    chain.recompute_balances();
    Ok(chain)
}

/// Append new blocks to the parity-db database atomically.
/// Existing blocks are left untouched, ensuring durability.
pub fn save_chain(chain: &Blockchain, path: &str) -> io::Result<()> {
    let mut opts = Options::with_columns(Path::new(path), 1);
    let db = Db::open_or_create(&opts).map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    // Find current highest index stored
    let mut index = 0u64;
    loop {
        let key = index.to_le_bytes();
        match db.get(0, &key).map_err(|e| io::Error::new(ErrorKind::Other, e))? {
            Some(_) => index += 1,
            None => break,
        }
    }
    for block in chain.chain.iter().skip(index as usize) {
        let key = block.index.to_le_bytes();
        let value = serde_json::to_vec(block)?;
        let mut tx = Transaction::new();
        tx.put(0, key.to_vec(), value);
        db.commit(tx)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut opts = Options::with_columns(dir.as_path(), 1);
        let db = Db::open_or_create(&opts).unwrap();
        let genesis = Block::new(0, 0, vec![], "0".into(), None);
        let bad_block = Block::new(1, 0, vec![], "wrong".into(), None);
        let mut tx = Transaction::new();
        tx.put(0, 0u64.to_le_bytes().to_vec(), serde_json::to_vec(&genesis).unwrap());
        tx.put(0, 1u64.to_le_bytes().to_vec(), serde_json::to_vec(&bad_block).unwrap());
        db.commit(tx).unwrap();
        let res = load_chain(dir.to_str().unwrap());
        fs::remove_dir_all(&dir).unwrap();
        assert!(res.is_err());
    }
}
