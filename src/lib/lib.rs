use serde::{Deserialize, Serialize};

pub mod request {
    use super::*;

    #[derive(Serialize, Deserialize)]
    pub struct AddKeyRequest {
        pub username: String,
        pub public_key: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct AuthenticateRequest {
        pub username: String,
    }
}

pub mod response {
    use super::*;

    #[derive(Serialize, Deserialize)]
    pub struct AuthenticateResponse {
        pub token: String,
    }
}
