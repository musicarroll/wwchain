use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, ecdsa::Signature};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub signature: Option<String>,
}

impl Transaction {
    fn message_bytes(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.sender);
        hasher.update(&self.recipient);
        hasher.update(self.amount.to_be_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    pub fn sign(&mut self, sk: &SecretKey) {
        let secp = Secp256k1::new();
        let msg = Message::from_slice(&self.message_bytes()).expect("32 bytes");
        let sig = secp.sign_ecdsa(&msg, sk);
        self.signature = Some(hex::encode(sig.serialize_compact()));
    }

    pub fn verify(&self) -> bool {
        let sig_hex = match &self.signature {
            Some(s) => s,
            None => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match Signature::from_compact(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pub_bytes = match hex::decode(&self.sender) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pubkey = match PublicKey::from_slice(&pub_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let secp = Secp256k1::verification_only();
        let msg = Message::from_slice(&self.message_bytes()).expect("32 bytes");
        secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify_roundtrip() {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "bob".into(),
            amount: 5,
            signature: None,
        };
        tx.sign(&sk);
        assert!(tx.verify());
    }

    #[test]
    fn verify_fails_when_modified() {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let mut tx = Transaction {
            sender: hex::encode(pk.serialize()),
            recipient: "alice".into(),
            amount: 1,
            signature: None,
        };
        tx.sign(&sk);
        tx.amount = 2;
        assert!(!tx.verify());
    }
}
