use std::fs::{self};
use std::path::Path;

use actix_web::{get, post, web, HttpResponse, Responder};
use lib::asymetric::sign;
use lib::key::{PersistentKey, SymetricEncryptable};
use lib::symetric::{
    key_encryption_key::KeyEncryptionKey,
    master_encryption_key::{EncryptedMasterEncryptionKey, MasterEncryptionKey},
    EphemeralKey,
};
use lib::web::requests::MekResponse;

use crate::{helpers::handle_format_error, middlewares::auth::BearerAuth, USERS_BASE_PATH};

#[post("/mek")]
pub async fn store_mek(
    auth: BearerAuth,
    encrypted_mek: web::Json<EncryptedMasterEncryptionKey>,
) -> impl Responder {
    let id = auth.0;
    let dir_path = Path::new(USERS_BASE_PATH).join(id.to_string());

    if let Err(e) = fs::create_dir_all(&dir_path) {
        eprintln!("Failed to create directory {:?}: {:?}", dir_path, e);
        return HttpResponse::InternalServerError().body("Failed to create user directory");
    }

    let mek_path = dir_path.join("mek.enc.json");
    if let Err(e) = serde_json::to_writer(fs::File::create(&mek_path).unwrap(), &encrypted_mek) {
        eprintln!("Failed to write MEK to file {:?}: {:?}", mek_path, e);
        return HttpResponse::InternalServerError().body("Failed to store MEK");
    }

    HttpResponse::Ok().finish()
}

#[get("/mek")]
pub async fn get_mek(auth: BearerAuth, sign_kp: web::Data<sign::key::KeyPair>) -> impl Responder {
    let id = auth.0;

    let dir_path = Path::new(USERS_BASE_PATH).join(id.to_string());
    let ek_path = dir_path.join("ek.json");
    let kek_path = dir_path.join("kek.json");
    let mek_path = dir_path.join("mek.enc.json");

    let kek = match KeyEncryptionKey::read_from_file(&kek_path) {
        Ok(kek) => kek,
        Err(error) => return handle_format_error(error),
    };

    let mek = match MasterEncryptionKey::read_from_file(&mek_path, &kek) {
        Ok(mek) => mek,
        Err(error) => return handle_format_error(error),
    };

    let ek = match EphemeralKey::read_from_file(&ek_path) {
        Ok(ek) => ek,
        Err(error) => return handle_format_error(error),
    };

    let encrypted_mek = match mek.encrypt(&ek.data) {
        Ok(encrypted_mek) => encrypted_mek,
        Err(error) => return handle_format_error(error),
    };

    // Serialize MEK for signing
    let mek_json = match serde_json::to_vec(&mek) {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "title": "Failed to serialize MEK", "code": 500 }))
        }
    };

    // Sign the MEK
    let signature = sign_kp.sk.sign_detached(&mek_json);

    let response = MekResponse {
        mek: encrypted_mek,
        signature,
    };

    HttpResponse::Ok().json(serde_json::json!({"data": response}))
}
