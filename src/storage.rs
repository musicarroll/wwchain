use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};

use crate::block::Block;
use crate::blockchain::Blockchain;

pub fn load_chain(path: &str) -> io::Result<Blockchain> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let blocks: Vec<Block> = serde_json::from_str(&data)?;
    let chain = Blockchain { chain: blocks };
    if !chain.is_valid_chain() {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid blockchain"));
    }
    Ok(chain)
}

pub fn save_chain(chain: &Blockchain, path: &str) -> io::Result<()> {
    let serialized = serde_json::to_string_pretty(&chain.chain)?;
    let mut file = File::create(path)?;
    file.write_all(serialized.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_chain_rejects_invalid() {
        let genesis = Block::new(0, 0, vec![], "0".into(), None);
        let bad_block = Block::new(1, 0, vec![], "wrong".into(), None);
        let blocks = vec![genesis, bad_block];
        let json = serde_json::to_string_pretty(&blocks).unwrap();
        let path = std::env::temp_dir().join(format!(
            "invalid_chain_{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, json).unwrap();
        let res = load_chain(path.to_str().unwrap());
        fs::remove_file(&path).unwrap();
        assert!(res.is_err());
    }
}
