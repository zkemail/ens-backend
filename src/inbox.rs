use crate::prove::generate_proof;
use crate::state::StateConfig;
use axum::{Router, extract::State, routing::post};
use std::sync::Arc;

pub async fn inbox_handler(State(state): State<Arc<StateConfig>>, body: String) -> String {
    let proof = generate_proof(body, &state.prover).await.unwrap();
    String::from("")
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(inbox_handler))
}
