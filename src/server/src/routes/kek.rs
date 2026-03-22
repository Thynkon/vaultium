use std::fs::{self};
use std::path::Path;

use actix_web::web;
use actix_web::{post, HttpResponse, Responder};
use lib::asymetric::kem;
use lib::key::{AsymetricDecryptable, PersistentKey, SymetricEncryptable};
use lib::symetric::key_encryption_key::{EncryptedKeyEncryptionKey, KeyEncryptionKey};
use lib::symetric::master_encryption_key::MasterEncryptionKey;

use crate::helpers::handle_format_error;
use crate::middlewares::auth::BearerAuth;
use crate::USERS_BASE_PATH;

#[post("/kek")]
pub async fn store_kek(
    auth: BearerAuth,
    encrypted_kek: web::Json<EncryptedKeyEncryptionKey>,
    kp: web::Data<kem::KeyPair>,
) -> impl Responder {
    let id: uuid::Uuid = auth.0;
    let dir_path = Path::new(USERS_BASE_PATH).join(id.to_string());

    // Decrypt KEK to validate it
    let kek = match encrypted_kek.decrypt(&kp.sk, id.as_bytes()) {
        Ok(kek) => kek,
        Err(e) => {
            eprintln!("Failed to decrypt KEK: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "title": "Failed to decrypt KEK", "code": 500 }));
        }
    };

    // Create user directory
    if let Err(e) = fs::create_dir_all(&dir_path) {
        eprintln!("Failed to create directory {:?}: {:?}", dir_path, e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "title": "Failed to create user directory", "code": 500 }));
    }

    let kek_path = dir_path.join("kek.json");
    if let Err(e) = serde_json::to_writer(fs::File::create(&kek_path).unwrap(), &kek) {
        eprintln!("Failed to write KEK to file {:?}: {:?}", kek_path, e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "title": "Failed to store KEK", "code": 500 }));
    }

    println!("STORED KEK AT: {}", &kek_path.to_str().unwrap());

    HttpResponse::Ok().json(serde_json::json!({ "data": "KEK stored successfully" }))
}

#[post("/kek/rotate")]
pub async fn update_kek(
    auth: BearerAuth,
    new_encrypted_kek: web::Json<EncryptedKeyEncryptionKey>,
    kp: web::Data<kem::KeyPair>,
) -> impl Responder {
    let id: uuid::Uuid = auth.0;
    let dir_path = Path::new(USERS_BASE_PATH).join(id.to_string());
    let kek_path = dir_path.join("kek.json");
    let mek_path = dir_path.join("mek.enc.json");

    let old_kek = match KeyEncryptionKey::read_from_file(&kek_path) {
        Ok(kek) => kek,
        Err(error) => return handle_format_error(error),
    };

    let mek = match MasterEncryptionKey::read_from_file(&mek_path, &old_kek) {
        Ok(mek) => mek,
        Err(error) => return handle_format_error(error),
    };

    // Decrypt KEK to validate it
    let new_kek = match new_encrypted_kek.decrypt(&kp.sk, id.as_bytes()) {
        Ok(kek) => kek,
        Err(e) => {
            eprintln!("Failed to decrypt KEK: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "title": "Failed to decrypt KEK", "code": 500 }));
        }
    };

    let encrypted_mek = match mek.encrypt(new_kek.as_ref()) {
        Ok(enc_mek) => enc_mek,

        Err(e) => {
            eprintln!("Failed to decrypt KEK: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "title": "Failed to decrypt KEK", "code": 500 }));
        }
    };

    // save new kek and encrypted mek
    if let Err(_e) = &new_kek.write_to_file(&kek_path) {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "title": "Failed to store KEK", "code": 500 }));
    }

    if let Err(e) = encrypted_mek.write_to_file(&mek_path) {
        eprintln!("Failed to write MEK to file {:?}: {:?}", mek_path, e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "title": "Failed to store MEK", "code": 500 }));
    }

    println!("STORED KEK AT: {}", &kek_path.to_str().unwrap());

    HttpResponse::Ok().json(serde_json::json!({ "data": "MEK stored successfully" }))
}
