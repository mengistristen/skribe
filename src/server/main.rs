//! This server provides authentication with RSA encrypted JWTs.
//!
//! The user associates a public key with their username and tokens encrypted
//! with their public key are sent on authentication. The user would then
//! decrypt the token using their private key and use that token to gain
//! access to protected routes on the server.

use axum::{
    routing::{get, post},
    Extension, Router,
};
use skribe::{
    auth::routes::{add_key, authenticate, protected_route, validate_token},
    state::AppState,
};
use std::sync::{Arc, RwLock};
use tracing::info;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt, Registry};

#[tokio::main]
async fn main() {
    // Create the logger
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "./logs", "skribe.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer().with_writer(non_blocking);

    let console_layer = tracing_subscriber::fmt::layer().with_target(false);

    let subscriber = Registry::default()
        .with(EnvFilter::new("server=debug,skribe=debug"))
        .with(file_layer)
        .with(console_layer);

    tracing::subscriber::set_global_default(subscriber).expect("failed to set global default");

    // Create and run the server
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
