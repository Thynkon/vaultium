use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::asymetric::kem::Ciphertext;
use crate::key::{AsymetricDecryptable, AsymetricEncryptable};

use serde::{Deserialize, Serialize};

use crate::symetric::{Nonce, SymetricKey};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKey {
    pub data: SymetricKey,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedEphemeralKey {
    pub data: Vec<u8>,
    pub nonce: Nonce,
    pub kem_ct: Ciphertext,
}

impl EphemeralKey {
    pub fn new() -> Self {
        EphemeralKey {
            data: SymetricKey::new(),
        }
    }

    pub fn generate() -> Self {
        let key = SymetricKey::random();
        Self { data: key }
    }
}

impl AsymetricEncryptable<EncryptedEphemeralKey> for EphemeralKey {}

impl Default for EphemeralKey {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::key::PersistentKey for EphemeralKey {}

impl crate::key::DecryptedKey for EphemeralKey {
    fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl From<&EphemeralKey> for SymetricKey {
    fn from(kek: &EphemeralKey) -> Self {
        // Copy the bytes from the KEK
        let bytes = kek.data.data;
        Self::from_bytes(bytes)
    }
}

impl AsRef<SymetricKey> for EphemeralKey {
    fn as_ref(&self) -> &SymetricKey {
        &self.data
    }
}

impl crate::key::AsymetricEncryptedKey for EncryptedEphemeralKey {
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

impl AsymetricDecryptable<EphemeralKey> for EncryptedEphemeralKey {}
