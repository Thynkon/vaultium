use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use aes_gcm_siv::Nonce as AesNonce;

use serde::{Deserialize, Serialize};

pub const NONCE_LENGTH: usize = 96 / 8;
pub type NonceData = [u8; NONCE_LENGTH];

#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Nonce(NonceData);

impl Nonce {
    pub fn new() -> Self {
        Self([0u8; NONCE_LENGTH])
    }

    pub fn into_aes_gcm(&self) -> AesNonce {
        let r: AesNonce = self.into();
        r
    }

    pub fn generate() -> Self {
        let mut nonce = Self::new();
        rand::rng().fill_bytes(nonce.0.as_mut());
        nonce
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce::new()
    }
}

impl From<Nonce> for NonceData {
    fn from(nonce: Nonce) -> NonceData {
        nonce.0
    }
}

impl From<AesNonce> for Nonce {
    fn from(n: AesNonce) -> Self {
        Nonce(n.into())
    }
}

impl From<Nonce> for AesNonce {
    fn from(n: Nonce) -> Self {
        *AesNonce::from_slice(&n.0)
    }
}

impl From<&Nonce> for AesNonce {
    fn from(n: &Nonce) -> Self {
        *AesNonce::from_slice(&n.0)
    }
}
