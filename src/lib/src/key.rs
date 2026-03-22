use std::{fs, path::PathBuf};

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::aes::Aes256;
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit};

use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::asymetric::kem::{Ciphertext, PublicKey, SecretKey};

use serde::Serialize;

use crate::symetric::{Nonce, SymetricKey};
#[derive(Error, Debug)]
pub enum Errors {
    #[error("Invalid file")]
    Invalid,
    #[error("Not found")]
    NotFound,
}

pub trait DecryptedKey {
    fn data(&self) -> &[u8];
}

pub trait AsymetricEncryptedKey {
    fn data(&self) -> &[u8];
    fn nonce(&self) -> &Nonce;
    fn kem_ct(&self) -> &Ciphertext;

    fn new(data: Vec<u8>, nonce: Nonce, kem_ct: Ciphertext) -> Self;
}

pub trait SymetricEncryptedKey {
    fn data(&self) -> &[u8];
    fn nonce(&self) -> &Nonce;

    fn new(data: Vec<u8>, nonce: Nonce) -> Self;
}

pub trait PersistentKey {
    fn write_to_file(&self, path: &PathBuf) -> anyhow::Result<()>
    where
        Self: Serialize,
    {
        if let Err(e) = serde_json::to_writer(fs::File::create(path).unwrap(), &self) {
            eprintln!("Failed to write to file {:?}: {:?}", &path, e);
            return Err(Errors::Invalid.into());
        }

        Ok(())
    }

    fn read_from_file(path: &PathBuf) -> anyhow::Result<Self>
    where
        Self: Sized + DeserializeOwned,
    {
        match fs::File::open(path) {
            Ok(file) => match serde_json::from_reader::<_, Self>(file) {
                Ok(kek) => Ok(kek),
                Err(_) => Err(Errors::Invalid.into()),
            },
            Err(_) => Err(Errors::NotFound.into()),
        }
    }
}

pub trait AsymetricEncryptable<T>: Serialize
where
    T: AsymetricEncryptedKey + DeserializeOwned,
{
    fn encrypt(&self, pk: &PublicKey, info: &[u8]) -> anyhow::Result<T> {
        let kem_output = pk.encapsulate();

        log::debug!("KeyEncryptionKey.encrypt():");
        log::debug!("{:?}", &kem_output);

        let key = SymetricKey::from_shared_secret(&kem_output.ss, info);
        log::debug!("SymetricKey from ss: {:?}", &key);
        let key = Key::<Aes256>::try_from(key.as_ref())?;

        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::new();

        // Serialize the entire KEK to JSON first
        let kek_json = serde_json::to_vec(self).map_err(|_| aes_gcm_siv::Error)?;

        let aes_gcm_nonce = &nonce.into_aes_gcm();
        let ct = cipher.encrypt(aes_gcm_nonce, kek_json.as_ref())?;

        Ok(T::new(ct, nonce, kem_output.ct))
    }
}

pub trait AsymetricDecryptable<T>: Serialize
where
    T: DecryptedKey + DeserializeOwned,
{
    fn decrypt(&self, sk: &SecretKey, info: &[u8]) -> anyhow::Result<T>
    where
        Self: AsymetricEncryptedKey,
    {
        let ss = sk.decapsulate(self.kem_ct());

        log::debug!("KeyEncryptionKey.encrypt():");
        log::debug!("SS: {:?}", &ss);

        let key = SymetricKey::from_shared_secret(&ss, info);
        log::debug!("SymetricKey from ss: {:?}", &key);
        let key = Key::<Aes256GcmSiv>::try_from(key.as_ref())?;

        let cipher = Aes256GcmSiv::new(&key);
        let nonce = self.nonce();

        let pt = cipher
            .decrypt(&nonce.into(), self.data().as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        let kek: T = serde_json::from_slice(&pt)?;
        Ok(kek)
    }
}

pub trait SymetricEncryptable<T>: Serialize
where
    T: SymetricEncryptedKey + DeserializeOwned,
{
    fn encrypt(
        &self,
        // TODO: use generic type?
        key: &SymetricKey,
    ) -> anyhow::Result<T> {
        let key = Key::<Aes256>::try_from(key.as_ref())?;

        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::new();

        // Serialize the entire MEK to JSON first
        let mek_json = serde_json::to_vec(self).map_err(|_| aes_gcm_siv::Error)?;

        let aes_gcm_nonce = &nonce.into_aes_gcm();
        let ct = cipher.encrypt(aes_gcm_nonce, mek_json.as_ref())?;

        Ok(T::new(ct, nonce))
    }
}

pub trait SymetricDecryptable<T>: Serialize
where
    T: DecryptedKey + DeserializeOwned,
{
    // TODO: use generic type?
    fn decrypt(&self, key: &SymetricKey) -> anyhow::Result<T>
    where
        Self: SymetricEncryptedKey,
    {
        let key = Key::<Aes256GcmSiv>::try_from(key.as_ref())?;

        let cipher = Aes256GcmSiv::new(&key);
        let nonce = self.nonce();

        let pt = cipher
            .decrypt(&nonce.into_aes_gcm(), self.data().as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        let mek: T = serde_json::from_slice(&pt)?;
        Ok(mek)
    }
}
