use axum::{routing::{post}, Json, Router};
use serde::{Serialize,Deserialize};
use dotenv::dotenv;
use reqwest::Client;
use alloy::{primitives::Address};
use relayer_utils::{generate_email_circuit_input, AccountCode, EmailCircuitParams, bytes32_to_fr};

pub async fn prove_handler(body: String) {
    println!("Request body: {}", body);
    let random_bytes: [u8; 32] = [0; 32];
    let fr = bytes32_to_fr(&random_bytes).unwrap();
    let account_code = AccountCode::from(fr);
    let params = EmailCircuitParams {
        ignore_body_hash_check: Some(false),
        max_body_length: Some(1024),
        max_header_length: Some(1024),
        sha_precompute_selector: Some(String::from("(<div id=3D\"[^\"]*zkemail[^\"]*\"[^>]*>)")),
    };

    let inputs = generate_email_circuit_input(&body, &account_code, Some(params)).await.unwrap();

    println!("Generated inputs: {:?}", inputs);

}

pub fn routes() -> Router {
    Router::<()>::new().route("/", post(prove_handler))
}