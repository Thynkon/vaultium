use anyhow::Result;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::asymetric::kem::Ciphertext;
use crate::dictionnary::Word;
use crate::key::{AsymetricDecryptable, AsymetricEncryptable};
use argon2::{Algorithm, Argon2, Params, Version};

use serde::{Deserialize, Serialize};

use crate::symetric::{Nonce, Salt, SymetricKey};

#[derive(Serialize, Deserialize)]
pub struct KeyEncryptionKey {
    pub data: SymetricKey,
    pub salt: Salt,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedKeyEncryptionKey {
    pub data: Vec<u8>,
    pub nonce: Nonce,
    pub kem_ct: Ciphertext,
}

impl KeyEncryptionKey {
    pub fn new() -> Self {
        KeyEncryptionKey {
            data: SymetricKey::new(),
            salt: Salt::new(),
        }
    }

    pub fn generate(word: &Word) -> Result<Self, argon2::Error> {
        use std::time::Instant;

        let salt = Salt::generate();
        let mut key = SymetricKey::new();
        // KiB definition: https://physics.nist.gov/cuu/Units/binary.html
        // 2 GiB in blocks of 1KiB: (2^30 * 2) / 2^10 = 2'097'152
        let params =
            Params::new(2_097_152, 2, 4, Some(256 / 8)).expect("Failed to create Argon2 params");

        println!(
            "Memory: {} KiB, Iterations: {}, Parallelism: {}",
            params.m_cost(),
            params.t_cost(),
            params.p_cost()
        );

        // let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let argon2 = Argon2::default();

        let start = Instant::now();
        argon2.hash_password_into(word.as_bytes(), salt.as_ref(), key.as_mut())?;
        println!("Hashing took: {:?}", start.elapsed());

        Ok(Self { data: key, salt })
    }
}

impl AsymetricEncryptable<EncryptedKeyEncryptionKey> for KeyEncryptionKey {}

impl Default for KeyEncryptionKey {
    fn default() -> Self {
        KeyEncryptionKey::new()
    }
}

impl crate::key::PersistentKey for KeyEncryptionKey {}

impl crate::key::DecryptedKey for KeyEncryptionKey {
    fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl From<&KeyEncryptionKey> for SymetricKey {
    fn from(kek: &KeyEncryptionKey) -> Self {
        // Copy the bytes from the KEK
        let bytes = kek.data.data;
        Self::from_bytes(bytes)
    }
}

impl AsRef<SymetricKey> for KeyEncryptionKey {
    fn as_ref(&self) -> &SymetricKey {
        &self.data
    }
}

impl crate::key::AsymetricEncryptedKey for EncryptedKeyEncryptionKey {
    fn new(data: Vec<u8>, nonce: Nonce, kem_ct: Ciphertext) -> Self {
        Self {
            data,
            nonce,
            kem_ct,
        }
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    fn kem_ct(&self) -> &Ciphertext {
        &self.kem_ct
    }
}

impl AsymetricDecryptable<KeyEncryptionKey> for EncryptedKeyEncryptionKey {}
