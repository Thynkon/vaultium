use std::path::Path;

use actix_web::web;
use actix_web::{post, HttpResponse, Responder};

use lib::asymetric::*;
use lib::key::{AsymetricDecryptable, PersistentKey};
use lib::symetric::EncryptedEphemeralKey;

use crate::middlewares::auth::BearerAuth;
use crate::USERS_BASE_PATH;

#[post("/ephemeral_key")]
pub async fn send_ephemeral_key(
    auth: BearerAuth,
    encrypted_ephemeral_key: web::Json<EncryptedEphemeralKey>,
    kem_kp: web::Data<kem::KeyPair>,
) -> impl Responder {
    let id = auth.0;
    let dir_path = Path::new(USERS_BASE_PATH).join(id.to_string());
    let ek_path = dir_path.join("ek.json");

    let ephemeral_key = match encrypted_ephemeral_key.decrypt(&kem_kp.sk, id.as_bytes()) {
        Ok(ek) => ek,
        Err(e) => {
            log::error!("Failed to decrypt EK: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "title": "Failed to decrypt EK", "code": 500 }));
        }
    };

    if let Err(_e) = &ephemeral_key.write_to_file(&ek_path) {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "title": "Failed to store EK", "code": 500 }));
    }

    HttpResponse::Ok().json(serde_json::json!({ "data": "EK stored successfully" }))
}
