extern crate pqcrypto;
extern crate pqcrypto_traits;

use core::fmt;
use std::io;
use std::io::ErrorKind;

use pqcrypto::kem::mlkem1024::{self, Ciphertext as MlCiphertext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use pqcrypto_traits::kem::Ciphertext as CiphertextTrait;

#[derive(Serialize, Deserialize)]
pub struct Ciphertext(pub MlCiphertext);

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, io::Error> {
        let ct_inner = <mlkem1024::Ciphertext as CiphertextTrait>::from_bytes(bytes)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid Ciphertext bytes"))?;
        Ok(Ciphertext(ct_inner))
    }

    pub fn to_bytes(&self) -> &[u8] {
        CiphertextTrait::as_bytes(&self.0)
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = Sha256::digest(self.to_bytes());

        f.debug_struct("Ciphertext")
            .field("sha256", &hex::encode(hash))
            .finish()
    }
}

impl Zeroize for Ciphertext {
    fn zeroize(&mut self) {
        let mut bytes = self.0.as_bytes().to_vec();
        bytes.zeroize();
    }
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        self.zeroize();
    }
}
