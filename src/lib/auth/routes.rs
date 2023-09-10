//! This module includes all routes used for authentication.
use std::sync::{Arc, RwLock};

use crate::{
    auth::{create_token, response::AuthenticateResponse, AuthError, Claims, KEYS},
    state::AppState,
};
use axum::{
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json, TypedHeader,
};
use base64::prelude::{Engine, BASE64_URL_SAFE};
use jsonwebtoken::{Algorithm, Validation};
use openssl::rsa;
use tracing::{debug, error, instrument, warn};

use super::request::{AddKeyRequest, AuthenticateRequest};

/// Encrypts the given JWT using the user's public key.
#[instrument(skip(token, public_key))]
pub fn encrypt_token(token: String, public_key: &String) -> Result<String, AuthError> {
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
pub async fn add_key(
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
pub async fn authenticate(
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
    let token = create_token(chrono::Utc::now())?;
    let encrypted_token = encrypt_token(token, public_key)?;

    let body = Json(AuthenticateResponse {
        token: encrypted_token,
    });

    Ok((StatusCode::OK, body).into_response())
}

/// Checks if JWT is valid.
#[instrument(skip(bearer))]
pub async fn validate_token(
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
pub async fn protected_route(_: Claims) -> StatusCode {
    debug!("user accessed a protected route");
    StatusCode::OK
}
