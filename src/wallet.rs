use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

#[derive(Clone)]
pub struct Wallet {
    secret_key: SecretKey,
    pub address: String,
}

impl Wallet {
    /// Load an existing wallet from `path`, or generate a new one and persist it.
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path_ref = path.as_ref();
        if path_ref.exists() {
            let hex_key = fs::read_to_string(path_ref)?;
            let key_bytes = hex::decode(hex_key.trim())
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            let secret_key = SecretKey::from_slice(&key_bytes)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            let secp = Secp256k1::new();
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let address = hex::encode(public_key.serialize());
            Ok(Wallet {
                secret_key,
                address,
            })
        } else {
            if let Some(parent) = path_ref.parent() {
                fs::create_dir_all(parent)?;
            }
            let secp = Secp256k1::new();
            let mut rng = OsRng;
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);
            let secret_key = SecretKey::from_slice(&sk_bytes)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
            fs::write(path_ref, hex::encode(sk_bytes))?;
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let address = hex::encode(public_key.serialize());
            Ok(Wallet {
                secret_key,
                address,
            })
        }
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn address(&self) -> &str {
        &self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn wallet_persists_key() {
        let dir = std::env::temp_dir().join(format!(
            "wallet_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.key");
        let w1 = Wallet::load_or_create(&path).unwrap();
        let addr1 = w1.address.clone();
        let sk1 = w1.secret_key.secret_bytes();
        let w2 = Wallet::load_or_create(&path).unwrap();
        assert_eq!(addr1, w2.address);
        assert_eq!(sk1, w2.secret_key.secret_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn address_matches_public_key() {
        let dir = std::env::temp_dir().join(format!(
            "wallet_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.key");
        let wallet = Wallet::load_or_create(&path).unwrap();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, wallet.secret_key());
        assert_eq!(wallet.address(), hex::encode(pk.serialize()));
        fs::remove_dir_all(&dir).unwrap();
    }
}
