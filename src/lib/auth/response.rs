//! This module declares all types that may be used as response payloads.
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticateResponse {
    pub token: String,
}
