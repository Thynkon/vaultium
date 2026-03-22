use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: u16,
    pub title: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP {}: {}", self.code, self.title)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn new(code: u16, title: impl Into<String>) -> Self {
        Self {
            code,
            title: title.into(),
        }
    }
}
