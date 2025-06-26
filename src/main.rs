use axum::Router;
use std::sync::Arc;
mod command;
mod inbox;
mod prove;
mod smtp;
mod state;

use state::StateConfig;

#[tokio::main]
async fn main() {
    let state = Arc::new(StateConfig::from_file("config.json").expect("INVALID CONFIG"));

    let app = Router::new()
        .nest("/command", command::routes())
        .nest("/inbox", inbox::routes()) // will be called by the IMAP server
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4500")
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Failed to serve");
}
