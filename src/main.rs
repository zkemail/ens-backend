use anyhow::Result;
use axum::{response::IntoResponse, routing::get, Router};
use ens_backend::{command, inbox, state::StateConfig};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let state = Arc::new(StateConfig::from_file("config.json")?);

    let app = Router::new()
        .route("/healthz", get(health_check))
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
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> impl IntoResponse {
    "OK"
}
