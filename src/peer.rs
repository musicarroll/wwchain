use std::sync::{Arc, Mutex};
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;
#[cfg(not(feature = "sync"))]
use tokio::net::lookup_host;
#[cfg(feature = "sync")]
use std::net::ToSocketAddrs;

#[derive(Debug, Clone)]
pub struct PeerList {
    pub peers: Arc<Mutex<Vec<String>>>,
}

impl PeerList {
    pub fn new() -> Self {
        PeerList {
            peers: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn add_peer(&self, addr: &str) {
        let mut peers = self.peers.lock().unwrap();
        if !peers.contains(&addr.to_string()) {
            peers.push(addr.to_string());
        }
    }
    pub fn all(&self) -> Vec<String> {
        self.peers.lock().unwrap().clone()
    }
    pub fn remove_peer(&self, addr: &str) {
        let mut peers = self.peers.lock().unwrap();
        if let Some(idx) = peers.iter().position(|x| x == addr) {
            peers.remove(idx);
        }
    }
    pub fn contains(&self, addr: &str) -> bool {
        self.peers.lock().unwrap().contains(&addr.to_string())
    }

    /// Load peers from a JSON file. If the file does not exist an empty list is returned.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(PeerList::new());
        }
        let data = fs::read_to_string(path)?;
        let peers: Vec<String> = serde_json::from_str(&data)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        Ok(PeerList {
            peers: Arc::new(Mutex::new(peers)),
        })
    }

    /// Persist peers to a JSON file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let peers = self.all();
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string(&peers)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Merge the given peers into the list, ignoring duplicates.
    pub fn merge(&self, addrs: &[String]) {
        for a in addrs {
            self.add_peer(a);
        }
    }

    /// Resolve peers from a DNS seed hostname.
    #[cfg(not(feature = "sync"))]
    pub async fn add_seed_peers(&self, host: &str, port: u16) -> io::Result<()> {
        let mut addrs = Vec::new();
        for addr in lookup_host((host, port)).await? {
            addrs.push(addr.to_string());
        }
        self.merge(&addrs);
        Ok(())
    }

    #[cfg(feature = "sync")]
    pub fn add_seed_peers(&self, host: &str, port: u16) -> io::Result<()> {
        let mut addrs = Vec::new();
        for addr in (host, port).to_socket_addrs()? {
            addrs.push(addr.to_string());
        }
        self.merge(&addrs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_peerlist_add_remove_contains() {
        let peers = PeerList::new();
        peers.add_peer("peer1");
        assert!(peers.contains("peer1"));
        peers.add_peer("peer1");
        assert_eq!(peers.all().len(), 1); // no duplicates
        peers.remove_peer("peer1");
        assert!(!peers.contains("peer1"));
    }

    #[test]
    fn test_peerlist_persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "peers_{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");
        let peers = PeerList::new();
        peers.add_peer("a:1");
        peers.add_peer("b:2");
        peers.save_to_file(&path).unwrap();

        let loaded = PeerList::load_from_file(&path).unwrap();
        assert!(loaded.contains("a:1"));
        assert!(loaded.contains("b:2"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
