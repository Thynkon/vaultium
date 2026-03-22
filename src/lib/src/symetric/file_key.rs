use std::path::{Path, PathBuf};

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    aes::Aes256,
    Aes256GcmSiv, Key,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::symetric::master_encryption_key::MasterEncryptionKey;
use crate::symetric::{Nonce, SymetricKey};

// #[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[derive(Serialize, Deserialize, Clone)]
pub struct FileKey {
    pub data: SymetricKey,
    pub path: PathBuf,
}

impl Zeroize for FileKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FileKey {
    pub fn generate(path: &Path, mek: &MasterEncryptionKey, info: &[u8]) -> Self {
        let ikm = &mek.data;
        let path_str = path.to_str().unwrap();
        let info = [info, path_str.as_bytes()].concat();

        let data = SymetricKey::expand(ikm.as_ref(), info.as_ref());

        Self {
            data,
            path: path.to_path_buf(),
        }
    }

    pub fn as_aes_key(&self) -> Key<Aes256> {
        Key::<Aes256>::try_from(self.data.as_ref()).unwrap()
    }

    pub fn encrypt(&self, key: &SymetricKey) -> anyhow::Result<EncryptedFileKey> {
        log::debug!("SymetricKey from ss: {:?}", &key);
        let key = Key::<Aes256>::try_from(key.as_ref())?;

        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::new();

        // Serialize the entire FK to JSON first
        let file_key_json = serde_json::to_vec(self).map_err(|_| aes_gcm_siv::Error)?;

        let aes_gcm_nonce = &nonce.into_aes_gcm();
        let ct = cipher.encrypt(aes_gcm_nonce, file_key_json.as_ref())?;

        Ok(EncryptedFileKey { data: ct, nonce })
    }
}

impl From<&FileKey> for SymetricKey {
    fn from(key: &FileKey) -> Self {
        key.data.clone()
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedFileKey {
    pub data: Vec<u8>,
    pub nonce: Nonce,
}

impl EncryptedFileKey {
    pub fn decrypt(&self, key: &SymetricKey) -> anyhow::Result<FileKey> {
        let key = Key::<Aes256GcmSiv>::try_from(key.as_ref())?;

        let cipher = Aes256GcmSiv::new(&key);
        let nonce = &self.nonce;

        let pt = cipher
            .decrypt(&nonce.into(), self.data.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        let file_key: FileKey = serde_json::from_slice(&pt)?;
        Ok(file_key)
    }
}
