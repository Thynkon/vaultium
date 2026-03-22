use std::path::PathBuf;

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv,
};

use anyhow::Result;

use serde::{Deserialize, Serialize};

use crate::symetric::{FileKey, Nonce};

pub struct File {
    pub path: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub nonce: Nonce,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedFile {
    pub path: PathBuf,
    pub data: Vec<u8>,
}

impl File {
    pub fn encrypt(&self, key: &FileKey) -> Result<EncryptedFile> {
        let cipher = Aes256GcmSiv::new(&key.as_aes_key());
        let nonce = Nonce::new();

        let pt = std::fs::read(&self.path)?;

        let ct = cipher
            .encrypt(&nonce.into_aes_gcm(), pt.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        Ok(EncryptedFile {
            path: self.path.clone(),
            data: ct,
            nonce,
        })
    }

    pub fn decrypt(&self, key: &FileKey) -> Result<DecryptedFile> {
        let cipher = Aes256GcmSiv::new(&key.as_aes_key());

        let reader = std::fs::File::open(&self.path)?;
        let encrypted_file: EncryptedFile = serde_json::from_reader(reader)?;

        // let aes_nonce: AesNonce<U12> = (&encrypted_file.nonce).into();
        let pt = cipher
            .decrypt(&encrypted_file.nonce.into(), encrypted_file.data.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(DecryptedFile {
            data: pt,
            path: encrypted_file.path,
        })
    }
}
