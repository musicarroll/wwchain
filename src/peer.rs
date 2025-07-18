use std::sync::{Arc, Mutex};

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
