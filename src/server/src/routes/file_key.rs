use std::path::Path;

use actix_web::{post, web, HttpResponse, Responder};
use lib::asymetric::*;
use lib::symetric::{
    key_encryption_key::KeyEncryptionKey, master_encryption_key::MasterEncryptionKey, EphemeralKey,
    FileKey,
};
use lib::web::requests::FileKeyQuery;

use crate::{helpers, middlewares::auth::BearerAuth, USERS_BASE_PATH};
use helpers::handle_format_error;
use lib::{key::PersistentKey, web::requests::FileKeyResponse};

#[post("/file_key")]
pub async fn get_file_key(
    auth: BearerAuth,
    query: web::Json<FileKeyQuery>,
    sign_kp: web::Data<sign::key::KeyPair>,
) -> impl Responder {
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

    let path = &query.path;
    let file_key = FileKey::generate(path, &mek, id.as_bytes());

    let file_key_json = match serde_json::to_vec(&file_key) {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let encrypted_file_key = match file_key.encrypt(&ek.data) {
        Ok(encrypted_file_key) => encrypted_file_key,
        Err(_err) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "title": "Failed to encrypt FK", "code": 500 }));
        }
    };

    let signature = sign_kp.sk.sign_detached(&file_key_json);
    let response = FileKeyResponse {
        key: encrypted_file_key,
        signature,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "data": response
    }))
}
