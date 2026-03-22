use aes_gcm_siv::{aead::Aead, aes::Aes256, Aes256GcmSiv, Key, KeyInit};
use lib::{
    obfuscated_key::ObfuscatedKey,
    symetric::{Nonce, SymetricKey},
};
use std::{fs, path::Path};

fn encrypt_code(key: &SymetricKey, input_path: &Path) -> anyhow::Result<(Vec<u8>, Nonce)> {
    let plaintext = fs::read(input_path)?;
    println!("STARTED TO ENCRYPT CODE!!!!!");
    let key_bytes = Key::<Aes256>::try_from(key.as_ref())?;
    let cipher = Aes256GcmSiv::new(&key_bytes);
    let nonce = Nonce::new();
    let aes_gcm_nonce = &nonce.into_aes_gcm();
    let ct = cipher.encrypt(aes_gcm_nonce, plaintext.as_ref())?;
    Ok((ct, nonce))
}

fn main() -> anyhow::Result<()> {
    let key = SymetricKey::random();
    let path = Path::new("../target/release/client");

    let (mut encrypted_code, _nonce) = encrypt_code(&key, path)?;
    println!("FINISHED ENCRYPTING CODE!!!!!");

    let obfuscated_key = ObfuscatedKey::obfuscate_const(&key.data);

    // Append obfuscated key
    encrypted_code.extend_from_slice(obfuscated_key.as_bytes());

    fs::write(format!("{}.enc", path.display()), encrypted_code)?;

    Ok(())
}
