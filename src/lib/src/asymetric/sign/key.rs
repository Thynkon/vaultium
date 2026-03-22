use std::{fs, io, path::Path};

use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _, SignedMessage as _,
};

use pqcrypto::sign::falcon1024::{
    self, DetachedSignature as SphincsDetachedSignature, PublicKey as SphincsPublicKey,
    SecretKey as SphincsSecretKey, SignedMessage as SphincsSignedMessage,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

#[derive(Debug, Clone)]
pub enum Error {
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidSignature,
    SigningFailed,
    VerificationFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidSecretKey => write!(f, "Invalid secret key"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::SigningFailed => write!(f, "Signing failed"),
            Error::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKey(pub SphincsPublicKey);

impl PublicKey {
    pub fn to_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        SphincsPublicKey::from_bytes(bytes)
            .map(PublicKey)
            .map_err(|_| Error::InvalidPublicKey)
    }

    pub fn verify(&self, message: &[u8], signature: &DetachedSignature) -> Result<(), Error> {
        let sphincs_sig = SphincsDetachedSignature::from_bytes(&signature.bytes)
            .map_err(|_| Error::InvalidSignature)?;
        falcon1024::verify_detached_signature(&sphincs_sig, message, &self.0)
            .map_err(|_| Error::VerificationFailed)
    }

    pub fn open(&self, signed_message: &SignedMessage) -> Result<Vec<u8>, Error> {
        falcon1024::open(&signed_message.0, &self.0)
            .map(|msg| msg.to_vec())
            .map_err(|_| Error::VerificationFailed)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretKey(pub SphincsSecretKey);

impl SecretKey {
    pub fn to_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        SphincsSecretKey::from_bytes(bytes)
            .map(SecretKey)
            .map_err(|_| Error::InvalidSecretKey)
    }

    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        let signed = falcon1024::sign(message, &self.0);
        SignedMessage(signed)
    }

    pub fn sign_detached(&self, message: &[u8]) -> DetachedSignature {
        let signature = falcon1024::detached_sign(message, &self.0);
        DetachedSignature::new(signature)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DetachedSignature {
    #[serde_as(as = "Bytes")]
    bytes: Vec<u8>,
}

impl DetachedSignature {
    pub fn new(sig: SphincsDetachedSignature) -> Self {
        DetachedSignature {
            bytes: sig.as_bytes().to_vec(),
        }
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        DetachedSignature { bytes }
    }

    pub fn to_sphincs(&self) -> Result<SphincsDetachedSignature, Error> {
        SphincsDetachedSignature::from_bytes(&self.bytes).map_err(|_| Error::InvalidSignature)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedMessage(pub SphincsSignedMessage);

impl SignedMessage {
    pub fn to_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        SphincsSignedMessage::from_bytes(bytes)
            .map(SignedMessage)
            .map_err(|_| Error::InvalidSignature)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = falcon1024::keypair();
        KeyPair {
            pk: PublicKey(pk),
            sk: SecretKey(sk),
        }
    }

    pub fn from_files(priv_path: &Path, pub_path: &Path) -> io::Result<Self> {
        let sk_bytes = fs::read(priv_path)?;
        let sk = SecretKey::from_bytes(&sk_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid private key"))?;

        let pk_bytes = fs::read(pub_path)?;
        let pk = PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid public key"))?;

        Ok(Self { pk, sk })
    }

    pub fn pk_bytes(&self) -> &[u8] {
        self.pk.to_bytes()
    }

    pub fn sk_bytes(&self) -> &[u8] {
        self.sk.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        self.sk.sign(message)
    }

    pub fn sign_detached(&self, message: &[u8]) -> DetachedSignature {
        self.sk.sign_detached(message)
    }

    pub fn verify(&self, message: &[u8], signature: &DetachedSignature) -> Result<(), Error> {
        self.pk.verify(message, signature)
    }
}
