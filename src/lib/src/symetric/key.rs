use std::fmt;

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::aes::Aes256;
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::asymetric::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use crate::symetric::{Nonce, Salt};

pub const SYMETRIC_KEY_LENGTH: usize = 256 / 8;
pub type KeyData = [u8; SYMETRIC_KEY_LENGTH];

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct SymetricKey {
    pub data: KeyData,
}

impl SymetricKey {
    pub fn new() -> Self {
        SymetricKey {
            data: Self::init_data(),
        }
    }

    fn init_data() -> KeyData {
        [0u8; SYMETRIC_KEY_LENGTH]
    }

    pub fn from_bytes(bytes: KeyData) -> Self {
        SymetricKey { data: bytes }
    }

    pub fn as_aes_key(&self) -> Key<Aes256> {
        Key::<Aes256>::try_from(self.data.as_ref()).unwrap()
    }

    pub fn from_shared_secret(ss: &SharedSecret, info: &[u8]) -> Self {
        Self::expand(ss.to_bytes(), [b"ml-kem-aes-key", info].concat().as_slice())
    }

    pub fn random() -> Self {
        let mut key = SymetricKey::new();
        rand::rng().fill_bytes(key.as_mut());

        key
    }

    pub fn expand(ikm: &[u8], info: &[u8]) -> Self {
        // Reference: https://blog.trailofbits.com/2025/01/28/best-practices-for-key-derivation/
        let info: Vec<u8> = [info].concat();

        // hardcoded salt of 128 bits of 0s => recommended by RFC 5869
        let salt = Salt::new();
        let hk = Hkdf::<Sha256>::new(Some(salt.as_ref()), ikm);

        let mut okm = SymetricKey::new();
        hk.expand(info.as_slice(), okm.as_mut())
            .expect("42 is a valid length for Sha256 to output");

        okm
    }

    pub fn encrypt(&self, pk: &PublicKey, info: &[u8]) -> anyhow::Result<EncryptedSymetricKey> {
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

        Ok(EncryptedSymetricKey {
            data: ct,
            nonce,
            kem_ct: kem_output.ct,
        })
    }
}

impl crate::key::PersistentKey for SymetricKey {}

impl Default for SymetricKey {
    fn default() -> Self {
        SymetricKey::new()
    }
}

impl AsMut<KeyData> for SymetricKey {
    fn as_mut(&mut self) -> &mut KeyData {
        &mut self.data
    }
}

impl AsRef<[u8]> for SymetricKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for SymetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = Sha256::digest(self.as_ref());

        f.debug_struct("SymetricKey")
            .field("sha256", &hex::encode(hash))
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedSymetricKey {
    pub data: Vec<u8>,
    pub nonce: Nonce,
    pub kem_ct: Ciphertext,
}

impl EncryptedSymetricKey {
    pub fn decrypt(&self, sk: &SecretKey, info: &[u8]) -> anyhow::Result<SymetricKey> {
        let ss = sk.decapsulate(&self.kem_ct);

        log::debug!("KeyEncryptionKey.encrypt():");
        log::debug!("SS: {:?}", &ss);

        let key = SymetricKey::from_shared_secret(&ss, info);
        log::debug!("SymetricKey from ss: {:?}", &key);
        let key = Key::<Aes256GcmSiv>::try_from(key.as_ref())?;

        let cipher = Aes256GcmSiv::new(&key);
        let nonce = &self.nonce;

        let pt = cipher
            .decrypt(&nonce.into(), self.data.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        let kek: SymetricKey = serde_json::from_slice(&pt)?;
        Ok(kek)
    }
}

impl crate::key::PersistentKey for EncryptedSymetricKey {}
