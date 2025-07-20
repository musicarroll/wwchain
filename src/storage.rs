use std::fs::File;
use std::io::{self, Read, Write};

use crate::block::{Block};
use crate::blockchain::Blockchain;

pub fn load_chain(path: &str) -> io::Result<Blockchain> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let blocks: Vec<Block> = serde_json::from_str(&data)?;
    Ok(Blockchain { chain: blocks })
}

pub fn save_chain(chain: &Blockchain, path: &str) -> io::Result<()> {
    let serialized = serde_json::to_string_pretty(&chain.chain)?;
    let mut file = File::create(path)?;
    file.write_all(serialized.as_bytes())?;
    Ok(())
}
