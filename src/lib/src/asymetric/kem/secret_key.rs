extern crate pqcrypto;
extern crate pqcrypto_traits;

use std::io;
use std::io::ErrorKind;

use pqcrypto::kem::mlkem1024::{self, SecretKey as MlSecretKey};

use pqcrypto_traits::kem::SecretKey as SecretKeyTrait;

use crate::asymetric::kem::{Ciphertext, SharedSecret};

#[derive(Clone, Debug)]
pub struct SecretKey(pub MlSecretKey);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, io::Error> {
        let sk_inner = <mlkem1024::SecretKey as SecretKeyTrait>::from_bytes(bytes)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid SecretKey bytes"))?;
        Ok(SecretKey(sk_inner))
    }

    pub fn decapsulate(&self, ct: &Ciphertext) -> SharedSecret {
        let ss = mlkem1024::decapsulate(&ct.0, &self.0);
        SharedSecret(ss)
    }

    pub fn to_bytes(&self) -> &[u8] {
        SecretKeyTrait::as_bytes(&self.0)
    }
}
