use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
mod command;
mod inbox;
mod prove;
mod smtp;
mod state;

use state::StateConfig;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let state = Arc::new(StateConfig::from_file("config.json").expect("INVALID CONFIG"));

    let app = Router::new()
        .nest("/command", command::routes())
        .nest("/inbox", inbox::routes()) // will be called by the IMAP server
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4500")
        .await
        .expect("Failed to bind");

    info!(
        "Starting server on port {}",
        listener.local_addr().unwrap().port()
    );
    info!("{:?}", state);
    axum::serve(listener, app).await.expect("Failed to serve");
}
