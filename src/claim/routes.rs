use axum::{routing::{post}, Json, Router};
use crate::claim::{models::ClaimRequest};


pub async fn claim_handler(Json(request): Json<ClaimRequest>) {
    println!("{:?}", request);
}

pub fn routes() -> Router {
    Router::<()>::new().route("/", post(claim_handler))
}