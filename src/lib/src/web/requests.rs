use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::asymetric::sign::{self, key::DetachedSignature};
use crate::symetric::master_encryption_key::EncryptedMasterEncryptionKey;
use crate::symetric::EncryptedFileKey;

#[derive(Serialize, Deserialize)]
pub struct FileKeyResponse {
    pub key: EncryptedFileKey,
    pub signature: sign::key::DetachedSignature,
}

#[derive(Serialize, Deserialize)]
pub struct MekResponse {
    pub mek: EncryptedMasterEncryptionKey,
    pub signature: DetachedSignature,
}

#[derive(Serialize, Deserialize)]
pub struct FileKeyQuery {
    pub path: PathBuf,
}
