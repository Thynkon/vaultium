use std::fs;
use std::path::PathBuf;

use zeroize::{Zeroize, ZeroizeOnDrop};

extern crate zeroize;

use crate::key::{
    self, DecryptedKey, SymetricDecryptable, SymetricEncryptable, SymetricEncryptedKey,
};
use crate::symetric::key_encryption_key::KeyEncryptionKey;

use serde::{Deserialize, Serialize};

use crate::symetric::{Nonce, SymetricKey};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MasterEncryptionKey {
    pub data: SymetricKey,
}

impl MasterEncryptionKey {
    pub fn generate() -> Self {
        let key = SymetricKey::random();

        Self { data: key }
    }

    pub fn read_from_file(path: &PathBuf, kek: &KeyEncryptionKey) -> anyhow::Result<Self> {
        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return Err(key::Errors::NotFound.into()),
        };

        let encrypted_mek: EncryptedMasterEncryptionKey = match serde_json::from_reader(file) {
            Ok(m) => m,
            Err(_) => return Err(key::Errors::Invalid.into()),
        };

        let mek = match encrypted_mek.decrypt(kek.as_ref()) {
            Ok(mek) => mek,
            Err(e) => {
                eprintln!("Failed to decrypt MEK: {:?}", e);
                return Err(key::Errors::Invalid.into());
            }
        };

        Ok(mek)
    }
}

impl crate::key::PersistentKey for MasterEncryptionKey {}
impl SymetricEncryptable<EncryptedMasterEncryptionKey> for MasterEncryptionKey {}

impl DecryptedKey for MasterEncryptionKey {
    fn data(&self) -> &[u8] {
        &self.data.data
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedMasterEncryptionKey {
    pub data: Vec<u8>,
    pub nonce: Nonce,
}

impl crate::key::PersistentKey for EncryptedMasterEncryptionKey {}
impl SymetricEncryptedKey for EncryptedMasterEncryptionKey {
    fn new(data: Vec<u8>, nonce: Nonce) -> Self {
        Self { data, nonce }
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

impl SymetricDecryptable<MasterEncryptionKey> for EncryptedMasterEncryptionKey {}
