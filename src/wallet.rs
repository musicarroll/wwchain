use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

#[derive(Clone)]
pub struct Wallet {
    secret_key: SecretKey,
    pub address: String,
}

impl Wallet {
    fn xor_with_password(data: &[u8], password: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        data.iter()
            .zip(hash.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect()
    }

    /// Load an existing wallet from `path`, or generate a new one and persist it.
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path_ref = path.as_ref();
        if path_ref.exists() {
            let contents = fs::read_to_string(path_ref)?;
            let key_bytes = if let Some(enc) = contents.strip_prefix("enc:") {
                let encrypted = hex::decode(enc.trim())
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                let pass = std::env::var("WALLET_PASSWORD").map_err(|_| {
                    io::Error::new(
                        ErrorKind::Other,
                        "WALLET_PASSWORD not set for encrypted wallet",
                    )
                })?;
                Self::xor_with_password(&encrypted, &pass)
            } else {
                hex::decode(contents.trim())
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
            };
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
            if let Ok(pass) = std::env::var("WALLET_PASSWORD") {
                let encrypted = Self::xor_with_password(&sk_bytes, &pass);
                fs::write(path_ref, format!("enc:{}", hex::encode(encrypted)))?;
            } else {
                fs::write(path_ref, hex::encode(sk_bytes))?;
            }
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
        std::env::set_var("WALLET_PASSWORD", "testpass");
        let w1 = Wallet::load_or_create(&path).unwrap();
        let addr1 = w1.address.clone();
        let sk1 = w1.secret_key.secret_bytes();
        let w2 = Wallet::load_or_create(&path).unwrap();
        assert_eq!(addr1, w2.address);
        assert_eq!(sk1, w2.secret_key.secret_bytes());
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("enc:"));
        fs::remove_dir_all(&dir).unwrap();
        std::env::remove_var("WALLET_PASSWORD");
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
        std::env::set_var("WALLET_PASSWORD", "testpass");
        let wallet = Wallet::load_or_create(&path).unwrap();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, wallet.secret_key());
        assert_eq!(wallet.address(), hex::encode(pk.serialize()));
        fs::remove_dir_all(&dir).unwrap();
        std::env::remove_var("WALLET_PASSWORD");
    }
}
