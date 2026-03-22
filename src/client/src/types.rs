use serde::{Deserialize, Serialize};

// Struct to map API JSON successful responses
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiData<T> {
    pub data: Option<T>,
}

impl<T> ApiData<T> {
    pub fn new() -> ApiData<T> {
        ApiData { data: None }
    }
}
