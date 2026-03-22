extern crate pqcrypto;
extern crate pqcrypto_traits;

use std::io::ErrorKind;
use std::path::Path;
use std::{fs, io};

use pqcrypto::kem::mlkem1024::{self};

use crate::asymetric::kem::public_key::PublicKey;
use crate::asymetric::kem::secret_key::SecretKey;

#[derive(Clone)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = mlkem1024::keypair();
        KeyPair {
            pk: PublicKey(pk),
            sk: SecretKey(sk),
        }
    }

    pub fn pk_bytes(&self) -> &[u8] {
        self.pk.to_bytes()
    }

    pub fn sk_bytes(&self) -> &[u8] {
        self.sk.to_bytes()
    }

    pub fn from_files(priv_path: &Path, pub_path: &Path) -> io::Result<Self> {
        // Read private key bytes
        let sk_bytes = fs::read(priv_path)?;
        let sk = SecretKey::from_bytes(&sk_bytes)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid private key bytes"))?;

        // Read public key bytes
        let pk_bytes = fs::read(pub_path)?;
        let pk = PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid public key bytes"))?;

        Ok(Self { pk, sk })
    }
}
