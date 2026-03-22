extern crate pqcrypto;
extern crate pqcrypto_traits;

use std::io::ErrorKind;
use std::{fmt, io};

use pqcrypto::kem::mlkem1024::{self, SharedSecret as MlSharedSecret};

use pqcrypto_traits::kem::SharedSecret as SharedSecretTrait;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct SharedSecret(pub MlSharedSecret);

impl SharedSecret {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, io::Error> {
        let ss_inner = <mlkem1024::SharedSecret as SharedSecretTrait>::from_bytes(bytes)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid SharedSecret bytes"))?;
        Ok(SharedSecret(ss_inner))
    }
}

impl SharedSecret {
    pub fn to_bytes(&self) -> &[u8] {
        SharedSecretTrait::as_bytes(&self.0)
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = Sha256::digest(self.to_bytes());

        f.debug_struct("Ciphertext")
            .field("sha256", &hex::encode(hash))
            .finish()
    }
}
