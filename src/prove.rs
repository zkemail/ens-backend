use axum::{routing::{post}, Json, Router};
use serde::{Serialize,Deserialize};
use dotenv::dotenv;
use reqwest::Client;
use alloy::{primitives::Address};

pub async fn prove_handler(body: String) {
    println!("Request body: {}", body);
}

pub fn routes() -> Router {
    Router::<()>::new().route("/", post(prove_handler))
}