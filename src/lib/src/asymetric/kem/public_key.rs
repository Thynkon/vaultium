extern crate pqcrypto;
extern crate pqcrypto_traits;

use pqcrypto::kem::mlkem1024::{self, PublicKey as MlPublicKey};

use pqcrypto_traits::kem::PublicKey as PublicKeyTrait;
use pqcrypto_traits::Error;

use crate::asymetric::kem::ciphertext::Ciphertext;
use crate::asymetric::kem::kem_encapsulation::KemEncapsulation;
use crate::asymetric::kem::shared_secret::SharedSecret;

#[derive(Clone, Debug)]
pub struct PublicKey(pub MlPublicKey);

impl PublicKey {
    pub fn encapsulate(&self) -> KemEncapsulation {
        let (ss, ct) = mlkem1024::encapsulate(&self.0);
        KemEncapsulation {
            ss: SharedSecret(ss),
            ct: Ciphertext(ct),
        }
    }

    pub fn to_bytes(&self) -> &[u8] {
        PublicKeyTrait::as_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let pk_inner = <mlkem1024::PublicKey as PublicKeyTrait>::from_bytes(bytes)?;
        Ok(PublicKey(pk_inner))
    }
}
