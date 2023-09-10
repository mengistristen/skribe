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
use tracing::{debug, error, info, instrument, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt, Registry};

/// The shared state for the application.
#[derive(Debug)]
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
fn create_token() -> Result<String, AuthError> {
    let now = chrono::Utc::now().timestamp();
    let exp = now + (60 * 60);
    let claims = Claims { exp: exp as usize };
    let token = jsonwebtoken::encode(&Header::default(), &claims, &KEYS.encoding);

    match token {
        Ok(token) => Ok(token),
        Err(_) => Err(AuthError::OperationFailed),
    }
}

/// Encrypts the given JWT using the user's public key.
#[instrument(skip(token, public_key))]
fn encrypt_token(token: String, public_key: &String) -> Result<String, AuthError> {
    let key = rsa::Rsa::public_key_from_pem(public_key.as_bytes()).map_err(|_| {
        warn!("public key was not in a valid format");
        AuthError::InvalidKeyFormat
    })?;
    let mut buf = vec![0; key.size() as usize];

    key.public_encrypt(token.as_bytes(), &mut buf, rsa::Padding::PKCS1)
        .map_err(|_| {
            error!("failed to encrypt jwt using public key");
            AuthError::OperationFailed
        })?;

    Ok(BASE64_URL_SAFE.encode(buf))
}

/// Stores the user's public key for authentication.
#[instrument(skip(state, payload))]
async fn add_key(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(payload): Json<AddKeyRequest>,
) -> Result<StatusCode, AuthError> {
    debug!("uploading public key for user {:?}", payload.username);

    let mut state = state.write().map_err(|err| {
        error!("error acquiring the lock for app state: {:?}", err);
        AuthError::OperationFailed
    })?;

    state.keys.insert(payload.username, payload.public_key);

    Ok(StatusCode::OK)
}

/// Uses the user's public key to encrypt a JWT access token.
#[instrument(skip(state, payload))]
async fn authenticate(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(payload): Json<AuthenticateRequest>,
) -> Result<Response, AuthError> {
    debug!("authenticating user {:?}", payload.username);

    let state = state.read().map_err(|_| AuthError::OperationFailed)?;

    if payload.username.is_empty() {
        warn!("user attempted to authenticate with an empty username");
        return Err(AuthError::MissingCredentials);
    }

    if !state.keys.contains_key(&payload.username) {
        warn!(
            "user {:?} attempted to authenticate without a valid public key",
            payload.username
        );
        return Err(AuthError::InvalidCredentials);
    }

    let public_key = state.keys.get(&payload.username).ok_or_else(|| {
        error!("error recovering user {:?}'s public key", payload.username);
        AuthError::OperationFailed
    })?;
    let token = create_token()?;
    let encrypted_token = encrypt_token(token, public_key)?;

    let body = Json(AuthenticateResponse {
        token: encrypted_token,
    });

    Ok((StatusCode::OK, body).into_response())
}

/// Checks if JWT is valid.
#[instrument(skip(bearer))]
async fn validate_token(
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> StatusCode {
    debug!("validating the bearer token");

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
#[instrument]
async fn protected_route(_: Claims) -> StatusCode {
    debug!("user accessed a protected route");
    StatusCode::OK
}

#[tokio::main]
async fn main() {
    // Create the logger
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "./logs", "skribe.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer().with_writer(non_blocking);

    let console_layer = tracing_subscriber::fmt::layer().with_target(false);

    let subscriber = Registry::default()
        .with(EnvFilter::new("server=debug"))
        .with(file_layer)
        .with(console_layer);

    tracing::subscriber::set_global_default(subscriber).expect("failed to set global default");

    let state = Arc::new(RwLock::new(AppState::new()));

    let app = Router::new()
        .route("/tokens/validation", get(validate_token))
        .route("/keys", post(add_key).layer(Extension(state.clone())))
        .route(
            "/tokens",
            post(authenticate).layer(Extension(state.clone())),
        )
        .route("/protected", get(protected_route));

    info!("Starting server at http://localhost:3000");

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
