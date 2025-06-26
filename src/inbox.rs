use crate::prove::generate_proof;
use crate::state::StateConfig;
use axum::{Router, extract::State, routing::post};
use std::sync::Arc;
use tracing::info;

pub async fn inbox_handler(State(state): State<Arc<StateConfig>>, body: String) -> String {
    info!("Received inbox request");
    let proof = generate_proof(body, &state.prover).await.unwrap();
    info!("Proof generated successfully");
    String::from("")
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(inbox_handler))
}
