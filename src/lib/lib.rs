//! A module for defining all types to be accepted/returned
//! from API routes.
use serde::{Deserialize, Serialize};

/// A module containing all request payload types.
pub mod request {
    use super::*;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct AddKeyRequest {
        pub username: String,
        pub public_key: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct AuthenticateRequest {
        pub username: String,
    }
}

/// A module contianing all response payload types.
pub mod response {
    use super::*;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct AuthenticateResponse {
        pub token: String,
    }
}
