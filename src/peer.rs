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
