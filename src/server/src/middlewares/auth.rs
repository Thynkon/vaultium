use actix_web::{error::ErrorUnauthorized, Error, FromRequest, HttpRequest};
use std::{
    future::{ready, Ready},
    str::FromStr,
};

pub struct BearerAuth(pub uuid::Uuid);

impl FromRequest for BearerAuth {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| { s.strip_prefix("Bearer ") }.and_then(|s| uuid::Uuid::from_str(s).ok()));

        match auth_header {
            Some(token) => ready(Ok(BearerAuth(token))),
            None => ready(Err(ErrorUnauthorized(
                "Missing or invalid Authorization header",
            ))),
        }
    }
}
