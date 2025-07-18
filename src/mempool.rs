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
