use std::net::SocketAddr;

use axum::{routing::get, Router};

async fn get_notes() -> &'static str {
    "getting all notes"
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/notes", get(get_notes));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await.unwrap();
}
