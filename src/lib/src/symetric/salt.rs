use zeroize::{Zeroize, ZeroizeOnDrop};

use serde::{Deserialize, Serialize};

use rand::RngCore;

pub const SALT_LENGTH: usize = 128 / 8;

#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop, Clone)]
pub struct Salt([u8; SALT_LENGTH]);

impl Salt {
    pub fn new() -> Self {
        Salt([0u8; SALT_LENGTH])
    }

    pub fn generate() -> Self {
        let mut salt = Self::new();
        rand::rng().fill_bytes(salt.as_mut());

        salt
    }
}

impl Default for Salt {
    fn default() -> Self {
        Salt::new()
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Salt> for [u8; SALT_LENGTH] {
    fn from(salt: Salt) -> [u8; SALT_LENGTH] {
        salt.0
    }
}

impl AsMut<[u8; SALT_LENGTH]> for Salt {
    fn as_mut(&mut self) -> &mut [u8; SALT_LENGTH] {
        &mut self.0
    }
}
