use crate::transaction::Transaction;

pub struct Mempool {
    pub pending: Vec<Transaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool { pending: Vec::new() }
    }

    pub fn add_tx(&mut self, tx: Transaction) {
        self.pending.push(tx);
    }

    pub fn drain(&mut self) -> Vec<Transaction> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mempool_add_and_drain() {
        let mut mp = Mempool::new();
        let tx = Transaction { sender: "a".into(), recipient: "b".into(), amount: 2 };
        mp.add_tx(tx.clone());
        assert_eq!(mp.pending.len(), 1);
        let drained = mp.drain();
        assert_eq!(drained, vec![tx]);
        assert!(mp.pending.is_empty());
    }
}
