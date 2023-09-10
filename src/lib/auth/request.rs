//! This module declares all types that may be used as request payloads.
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AddKeyRequest {
    pub username: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticateRequest {
    pub username: String,
}
