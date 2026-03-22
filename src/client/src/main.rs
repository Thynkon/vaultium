use inquire::{validator::Validation, Password, PasswordDisplayMode, Select};
use lib::{
    asymetric::*,
    dictionnary::{Dictionnary, Word},
    file::File,
    key::{AsymetricEncryptable, SymetricDecryptable, SymetricEncryptable},
    symetric::{EphemeralKey, FileKey, SymetricKey},
    web::requests::{FileKeyQuery, FileKeyResponse, MekResponse},
};
use simple_logger::SimpleLogger;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use strum::VariantNames;
use strum_macros::EnumString;
use walkdir::WalkDir;

use anyhow::Result;

use crate::api::{ApiClient, ClientError};
use clap::Parser;
use lib::symetric::key_encryption_key::KeyEncryptionKey;
use lib::symetric::master_encryption_key::MasterEncryptionKey;

mod api;
mod errors;
mod types;

#[derive(PartialEq, Debug, EnumString, strum_macros::VariantNames, Clone)]
#[strum(serialize_all = "kebab-case")]
enum Modes {
    Encrypt,
    Decrypt,
    ChangePassword,
}

#[derive(PartialEq, Debug, EnumString, strum_macros::VariantNames, Clone)]
#[strum(serialize_all = "kebab-case")]
enum Targets {
    Directory,
    File,
}

// CLI args
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, requires = "random_password")]
    dictionnary: Option<String>,

    #[arg(long)]
    select_file: bool,

    #[arg(long)]
    random_password: bool,

    #[arg(long)]
    id: uuid::Uuid,

    #[arg(long)]
    work_dir: PathBuf,

    #[arg(long)]
    base_url: String,
}

pub async fn send_ephemeral_key(
    client: &ApiClient,
    pk: &kem::PublicKey,
    ephemeral_key: &EphemeralKey,
) -> anyhow::Result<()> {
    let encrypted_key = ephemeral_key.encrypt(pk, client.token.as_bytes()).unwrap();
    let response = client.post("/ephemeral_key", None, &encrypted_key).await?;

    log::info!(
        "EMEPHERAL KEY stored successfully. API response: {:?}",
        response.data
    );
    Ok(())
}

pub async fn send_kek(
    client: &ApiClient,
    pk: &kem::PublicKey,
    kek: &KeyEncryptionKey,
) -> anyhow::Result<()> {
    // TODO: TMP UNWRAP
    let encrypted_kek = kek.encrypt(pk, client.token.as_bytes()).unwrap();
    let response = client.post("/kek", None, &encrypted_kek).await?;

    log::info!("KEK stored successfully. API response: {:?}", response.data);
    Ok(())
}

pub async fn update_kek(
    client: &ApiClient,
    pk: &kem::PublicKey,
    kek: &KeyEncryptionKey,
) -> anyhow::Result<()> {
    // TODO: TMP UNWRAP
    let encrypted_kek = kek.encrypt(pk, client.token.as_bytes()).unwrap();
    let response = client.post("/kek/rotate", None, &encrypted_kek).await?;

    log::info!(
        "CHANGED KEK successfully. API response: {:?}",
        response.data
    );
    Ok(())
}

pub async fn send_mek(
    client: &ApiClient,
    mek: &MasterEncryptionKey,
    kek: &KeyEncryptionKey,
) -> Result<(), ClientError> {
    let encrypted_mek = mek.encrypt(kek.as_ref()).unwrap();

    let response = client.post("/mek", None, &encrypted_mek).await?;

    log::info!("KEK stored successfully. API response: {:?}", response.data);
    Ok(())
}

pub async fn send_encrypted_files_paths(
    client: &ApiClient,
    file_paths: &[PathBuf],
) -> anyhow::Result<()> {
    let response = client
        .post("/encrypted_files_paths", None, &file_paths)
        .await?;

    log::info!(
        "Encrypted files paths sent successfully. API response: {:?}",
        response.data
    );
    Ok(())
}

pub async fn get_mek(
    client: &ApiClient,
    ephemeral_key: &SymetricKey,
    pk: &sign::key::PublicKey,
) -> anyhow::Result<MasterEncryptionKey> {
    let api_data = client.get("/mek", None, None).await?;

    let mek_value = api_data
        .data
        .ok_or_else(|| anyhow::anyhow!("No MEK returned from server"))?;

    let response: MekResponse = serde_json::from_value(mek_value)?;
    let mek = response.mek.decrypt(ephemeral_key)?;

    let signature = response.signature;
    let mek_bytes = serde_json::to_vec(&mek)?;

    pk.verify(&mek_bytes, &signature)
        .map_err(|e| anyhow::anyhow!("MEK signature verification failed: {}", e))?;

    Ok(mek)
}

pub async fn get_file_key(
    client: &ApiClient,
    path: PathBuf,
    ephemeral_key: &SymetricKey,
    sign_pk: &sign::key::PublicKey,
) -> anyhow::Result<FileKey> {
    let body = FileKeyQuery { path };

    // encrypted data with ephemeral_key
    let api_data = client.post("/file_key", None, &body).await?;

    let resp: FileKeyResponse = serde_json::from_value(
        api_data
            .data
            .ok_or_else(|| anyhow::anyhow!("No file key returned from server"))?,
    )?;

    let signature = resp.signature;
    let file_key = resp.key.decrypt(ephemeral_key)?;
    let key_bytes = serde_json::to_vec(&file_key)?;

    sign_pk
        .verify(&key_bytes, &signature)
        .map_err(|_| anyhow::anyhow!("FileKey signature verification failed"))?;

    Ok(file_key)
}

fn get_password_from_mode(args: &Args) -> anyhow::Result<Word> {
    let word = if args.dictionnary.as_ref().is_some() && args.random_password {
        let dictionnary = args.dictionnary.as_ref().unwrap();
        let path = Path::new(&dictionnary);
        log::info!("Generating random password from dictionnary...");
        Dictionnary::get_random_word(path)?
    } else {
        let validator = |input: &str| {
            if input.chars().count() < 10 {
                Ok(Validation::Invalid(
                    "Keys must have at least 10 characters.".into(),
                ))
            } else {
                Ok(Validation::Valid)
            }
        };

        let password = Password::new("Encryption Password:")
            .with_display_toggle_enabled()
            .with_display_mode(PasswordDisplayMode::Hidden)
            .with_custom_confirmation_message("Encryption Password (confirm):")
            .with_custom_confirmation_error_message("The passwords don't match.")
            .with_validator(validator)
            .with_formatter(&|_| String::from("Input received"))
            .with_help_message("It is recommended to generate a new one only for this purpose")
            .prompt()
            .map_err(anyhow::Error::from)?;

        log::info!("Password is valid. Going to generate key...");
        Word::from_str(&password)
    };

    Ok(word)
}

const SERVER_KEM_PUBLIC_KEY: &[u8] = include_bytes!("../../server/data/kem/public.key");
const SERVER_SIGN_PUBLIC_KEY: &[u8] = include_bytes!("../../server/data/sign/public.key");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    let args = Args::parse();
    let id: uuid::Uuid = args.id;
    let base_url = &args.base_url;
    let client = ApiClient::new(base_url.to_string(), id)?;

    let kem_pk = kem::PublicKey::from_bytes(SERVER_KEM_PUBLIC_KEY)?;
    let sign_pk = sign::key::PublicKey::from_bytes(SERVER_SIGN_PUBLIC_KEY)?;

    let mut mek: Option<MasterEncryptionKey> = None;

    let mode = Select::new("Mode", Modes::VARIANTS.to_vec()).prompt()?;
    let mode: Modes = Modes::from_str(mode)?;

    if let Modes::ChangePassword = mode {
        let word = get_password_from_mode(&args)?;
        let kek = KeyEncryptionKey::generate(&word)?;

        // both kek and mek call .zeroize() when they are dropped (derive feature of zeroize crate)
        update_kek(&client, &kem_pk, &kek).await?;

        return Ok(());
    }

    let target = Select::new("Targets", Targets::VARIANTS.to_vec()).prompt()?;
    let target: Targets = Targets::from_str(target)?;

    let entries = WalkDir::new(&args.work_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| match target {
            Targets::File => e.file_type().is_file(),
            Targets::Directory => e.file_type().is_dir(),
        });

    let path = Select::new(
        "Target to encrypt/decrypt",
        entries
            .map(|e| e.path().to_string_lossy().to_string())
            .collect(),
    )
    .prompt()?;
    let path = PathBuf::from_str(&path)?;

    let entries = WalkDir::new(&args.work_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            if let Targets::Directory = target {
                e.path().starts_with(path.clone())
            } else {
                e.path() == path
            }
        });

    match mode {
        Modes::Encrypt => {
            let word = get_password_from_mode(&args)?;
            let kek = KeyEncryptionKey::generate(&word)?;
            mek = Some(MasterEncryptionKey::generate());

            // both kek and mek call .zeroize() when dropped
            send_kek(&client, &kem_pk, &kek).await?;
            send_mek(&client, mek.as_ref().unwrap(), &kek).await?;
        }

        Modes::Decrypt => {
            let ephemeral_key = EphemeralKey::generate();
            send_ephemeral_key(&client, &kem_pk, &ephemeral_key).await?;
            log::info!("Sent EK to server!");

            mek = Some(get_mek(&client, &ephemeral_key.data, &sign_pk).await?);
        }

        // do nothing
        _ => {}
    }

    for entry in entries {
        let path = entry.path();
        let key = FileKey::generate(path, mek.as_ref().unwrap(), client.token.as_bytes());
        let f = File {
            path: path.to_path_buf().clone(),
        };

        log::info!("Handling path: {}", &path.to_str().unwrap());

        match &mode {
            Modes::Encrypt => {
                let encrypted_file = f.encrypt(&key)?;
                let writer = std::fs::File::create(path)?;
                serde_json::to_writer(writer, &encrypted_file)?;
            }
            Modes::Decrypt => {
                let decrypted_file = f.decrypt(&key)?;
                std::fs::write(path, decrypted_file.data)?;
            }
            // do nothing on ChangePassword mode
            _ => {}
        }
    }

    Ok(())
}
