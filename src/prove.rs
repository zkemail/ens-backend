use axum::{routing::{post}, Json, Router};
use serde::{Serialize,Deserialize};
use dotenv::dotenv;
use reqwest::Client;
use alloy::{primitives::Address};
use relayer_utils::{generate_email_circuit_input, AccountCode, EmailCircuitParams, bytes32_to_fr};
use anyhow::{Result, Context};


pub async fn prove_handler(body: String) {
    println!("Request body: {}", body);
}

pub async fn generate_inputs(body: String) -> Result<String> {
    let random_bytes: [u8; 32] = [0; 32];
    let fr = bytes32_to_fr(&random_bytes)?;
    let account_code = AccountCode::from(fr);
    let params = EmailCircuitParams {
        ignore_body_hash_check: Some(false),
        max_body_length: Some(1024),
        max_header_length: Some(1024),
        sha_precompute_selector: Some(String::from("(<div id=3D\"[^\"]*zkemail[^\"]*\"[^>]*>)")),
    };

    let result = generate_email_circuit_input(&body, &account_code, Some(params))
        .await
        .context("Failed to generate email circuit inputs")?;
    Ok(result)
}

pub fn routes() -> Router {
    Router::<()>::new().route("/", post(prove_handler))
}

#[cfg(test)]
pub mod test {
    use serde_json::Value;
    use super::generate_inputs;
    
    #[tokio::test]
    async fn test_generates_correct_inputs() {
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let expected_inputs_str = std::fs::read_to_string("test/fixtures/claim_ens_1/inputs.json").unwrap();
        let expected_inputs: Value = serde_json::from_str(&expected_inputs_str).unwrap();
        
        let inputs_str = generate_inputs(email).await.unwrap();
        let inputs: Value = serde_json::from_str(&inputs_str).unwrap();

        assert_eq!(inputs, expected_inputs);        
    }
}