//! Module containing everything pertaining to authentication.
use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    Json, RequestPartsExt, TypedHeader,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

pub mod request;
pub mod response;
pub mod routes;

/// The encoding and decoding keys used for signing JWTs.
struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    /// Creates the encoding and decoding keys from an HS256 secret.
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

/// A lazy evaluated static for loading the JWT keys from the JWT_SECRET
/// environment variable.
static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    Keys::new(secret.as_bytes())
});

/// An error type for all errors that may happen during authentication.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Missing credentials")]
    MissingCredentials,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Invalid access token")]
    InvalidToken,
    #[error("Invalid key format, RSA keys must be in PEM format")]
    InvalidKeyFormat,
    #[error("Operation could not be completed")]
    OperationFailed,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            Self::MissingCredentials => StatusCode::BAD_REQUEST,
            Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::InvalidToken => StatusCode::BAD_REQUEST,
            Self::InvalidKeyFormat => StatusCode::BAD_REQUEST,
            Self::OperationFailed => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({
            "error": format!("{self}")
        }));

        (status, body).into_response()
    }
}

/// The claims to store in the JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    exp: usize,
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        let token_data =
            jsonwebtoken::decode::<Claims>(&bearer.token(), &KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

/// Creates a new JWT. The token will expire in one hour.
pub fn create_token(creation_time: chrono::DateTime<chrono::Utc>) -> Result<String, AuthError> {
    let exp = creation_time.timestamp() + (60 * 60);
    let claims = Claims { exp: exp as usize };
    let token = jsonwebtoken::encode(&Header::default(), &claims, &KEYS.encoding);

    match token {
        Ok(token) => Ok(token),
        Err(_) => Err(AuthError::OperationFailed),
    }
}
