//! This server provides authentication with RSA encrypted JWTs.
use async_trait::async_trait;
use axum::{
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, RequestPartsExt, Router,
};
use base64::prelude::{Engine, BASE64_URL_SAFE};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use openssl::rsa;
use serde::{Deserialize, Serialize};
use serde_json::json;
use skribe::{
    request::{AddKeyRequest, AuthenticateRequest},
    response::AuthenticateResponse,
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use thiserror::Error;

/// The shared state for the application.
struct AppState {
    /// A temporary map of usernames to their associated public keys.
    keys: HashMap<String, String>,
}

impl AppState {
    /// Creates a new [`AppState`].
    fn new() -> Self {
        AppState {
            keys: HashMap::new(),
        }
    }
}

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
enum AuthError {
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
struct Claims {
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
fn create_token() -> String {
    let now = chrono::Utc::now().timestamp();
    let exp = now + (60 * 60);
    let claims = Claims { exp: exp as usize };
    let token = jsonwebtoken::encode(&Header::default(), &claims, &KEYS.encoding);

    token.unwrap()
}

/// Encrypts the given JWT using the user's public key.
fn encrypt_token(token: String, public_key: &String) -> Result<String, AuthError> {
    let key = rsa::Rsa::public_key_from_pem(public_key.as_bytes())
        .map_err(|_| AuthError::InvalidKeyFormat)?;
    let mut buf = vec![0; key.size() as usize];

    key.public_encrypt(token.as_bytes(), &mut buf, rsa::Padding::PKCS1)
        .map_err(|_| AuthError::OperationFailed)?;

    Ok(BASE64_URL_SAFE.encode(buf))
}

/// Stores the user's public key for authentication.
async fn add_key(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(payload): Json<AddKeyRequest>,
) -> Result<StatusCode, AuthError> {
    let mut state = state.write().map_err(|_| AuthError::OperationFailed)?;

    state.keys.insert(payload.username, payload.public_key);

    Ok(StatusCode::OK)
}

/// Uses the user's public key to encrypt a JWT access token.
async fn authenticate(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(payload): Json<AuthenticateRequest>,
) -> Result<Response, AuthError> {
    let state = state.read().map_err(|_| AuthError::OperationFailed)?;

    if payload.username.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    if !state.keys.contains_key(&payload.username) {
        return Err(AuthError::InvalidCredentials);
    }

    let public_key = state
        .keys
        .get(&payload.username)
        .ok_or(AuthError::OperationFailed)?;
    let token = create_token();
    let encrypted_token = encrypt_token(token, public_key)?;

    let body = Json(AuthenticateResponse {
        token: encrypted_token,
    });

    Ok((StatusCode::OK, body).into_response())
}

/// Checks if JWT is valid.
async fn validate_token(
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> StatusCode {
    match jsonwebtoken::decode::<Claims>(
        &bearer.token(),
        &KEYS.decoding,
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::UNAUTHORIZED,
    }
}

/// A route protected by a JWT.
async fn protected_route(_: Claims) -> StatusCode {
    println!("somebody accessed this!");
    StatusCode::OK
}

#[tokio::main]
async fn main() {
    let state = Arc::new(RwLock::new(AppState::new()));

    let app = Router::new()
        .route("/tokens/validation", get(validate_token))
        .route("/keys", post(add_key).layer(Extension(state.clone())))
        .route(
            "/tokens",
            post(authenticate).layer(Extension(state.clone())),
        )
        .route("/protected", get(protected_route));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
