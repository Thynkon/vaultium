use std::fs::{self};
use std::path::Path;

use actix_web::web;
use actix_web::{App, HttpServer};
use lib::asymetric::*;

mod routes;
use routes::*;
use simple_logger::SimpleLogger;

mod helpers;
mod middlewares;

pub const USERS_BASE_PATH: &str = "./data/users";

fn load_kem_keypair(base_path: &Path) -> anyhow::Result<kem::KeyPair> {
    let kem_dir = base_path.join("kem");
    let kem_priv = kem_dir.join("private.key");
    let kem_pub = kem_dir.join("public.key");

    fs::create_dir_all(&kem_dir)?;

    let kem_kp = if kem_priv.exists() && kem_pub.exists() {
        println!("Loading KEM keypair from files");
        kem::KeyPair::from_files(&kem_priv, &kem_pub)?
    } else {
        println!("Generating new KEM keypair");
        let kp = kem::KeyPair::generate();
        fs::write(&kem_priv, kp.sk_bytes())?;
        fs::write(&kem_pub, kp.pk_bytes())?;
        kp
    };

    Ok(kem_kp)
}

fn load_sign_keypair(base_path: &Path) -> anyhow::Result<sign::key::KeyPair> {
    let sign_dir = base_path.join("sign");
    let sign_priv = sign_dir.join("private.key");
    let sign_pub = sign_dir.join("public.key");

    fs::create_dir_all(&sign_dir)?;

    let sign_kp = if sign_priv.exists() && sign_pub.exists() {
        println!("Loading SIGN keypair from files");
        sign::key::KeyPair::from_files(&sign_priv, &sign_pub)?
    } else {
        println!("Generating new SIGN keypair");

        let kp = sign::key::KeyPair::generate();

        fs::write(&sign_priv, kp.sk_bytes())?;
        fs::write(&sign_pub, kp.pk_bytes())?;

        kp
    };

    Ok(sign_kp)
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    // base
    let base_path = Path::new("./data");

    let kem_kp = load_kem_keypair(base_path)?;
    let sign_kp = load_sign_keypair(base_path)?;

    // share with Actix
    let kem_kp_data = web::Data::new(kem_kp.clone());
    let sign_kp_data = web::Data::new(sign_kp.clone());

    HttpServer::new(move || {
        App::new()
            .app_data(kem_kp_data.clone())
            .app_data(sign_kp_data.clone())
            .service(ephemeral_key::send_ephemeral_key)
            .service(kek::store_kek)
            .service(kek::update_kek)
            .service(mek::get_mek)
            .service(mek::store_mek)
            .service(file_key::get_file_key)
    })
    .bind(("0.0.0.0", 8085))? // allow NGINX container to do PQ-TLS termination
    .run()
    .await?;

    Ok(())
}
