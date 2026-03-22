use actix_web::http::StatusCode;
use actix_web::HttpResponse;

use lib::key;

pub fn error_response(code: u16, message: &str) -> HttpResponse {
    HttpResponse::build(StatusCode::from_u16(code).unwrap())
        .json(serde_json::json!({ "title": message, "code": code }))
}

pub fn handle_format_error(err: anyhow::Error) -> HttpResponse {
    if let Some(e) = err.downcast_ref::<key::Errors>() {
        let (status, msg) = match e {
            key::Errors::Invalid => (500, "Invalid file"),
            key::Errors::NotFound => (404, "File not found"),
        };
        return error_response(status, msg);
    }

    error_response(500, "Internal server error")
}
