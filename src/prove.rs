use anyhow::{Context, Result};
use axum::{Router, routing::post};
use dotenv::dotenv;
use relayer_utils::{AccountCode, EmailCircuitParams, bytes32_to_fr, generate_email_circuit_input};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProveRequest {
    blueprint_id: String,
    proof_id: String,
    zkey_download_url: String,
    circuit_cpp_download_url: String,
    input: Value,
}

#[derive(Deserialize, Debug)]
pub struct Proof {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
    protocol: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]

pub struct ProofResponse {
    proof: Proof,
    public_outputs: Vec<String>,
}

pub async fn prove_handler(body: String) -> String {
    dotenv().ok();
    let prover_url = std::env::var("PROVER_URL").expect("PROVER_URL NOT SET");
    let prover_api_key = std::env::var("PROVER_API_KEY").expect("PROVER_API_KEY NOT SET");
    let blueprint_id = std::env::var("BLUEPRINT_ID").expect("BLUEPRINT_ID NOT SET");
    let circuit_cpp_download_url =
        std::env::var("CIRCUIT_CPP_DOWNLOAD_URL").expect("CIRCUIT_CPP_DOWNLOAD_URL NOT SET");
    let zkey_download_url = std::env::var("ZKEY_DOWNLOAD_URL").expect("ZKEY_DOWNLOAD_URL NOT SET");

    let prove_request = ProveRequest {
        blueprint_id,
        proof_id: "".to_string(),
        zkey_download_url,
        circuit_cpp_download_url,
        input: serde_json::from_str(
            &generate_inputs(body)
                .await
                .context("Failed to generate inputs")
                .unwrap(),
        )
        .context("Failed to convert inputs to json")
        .unwrap(),
    };

    Client::new()
        .post(prover_url)
        .header("x-api-key", prover_api_key)
        .json(&prove_request)
        .send()
        .await
        .context("Failed to send request")
        .unwrap()
        .text()
        .await
        .context("Failed to get response text")
        .unwrap()
}

pub async fn generate_inputs(body: String) -> Result<String> {
    let params = EmailCircuitParams {
        ignore_body_hash_check: Some(false),
        max_body_length: Some(1024),
        max_header_length: Some(1024),
        sha_precompute_selector: Some(String::from("(<div id=3D\"[^\"]*zkemail[^\"]*\"[^>]*>)")),
    };

    let result = generate_email_circuit_input(
        &body,
        &AccountCode::from(bytes32_to_fr(&[0; 32])?),
        Some(params),
    )
    .await
    .context("Failed to generate email circuit inputs")?;
    Ok(result)
}

pub fn routes() -> Router {
    Router::<()>::new().route("/", post(prove_handler))
}

#[cfg(test)]
pub mod test {
    use crate::prove::prove_handler;

    use super::{generate_inputs, ProofResponse};
    use serde_json::Value;

    #[tokio::test]
    async fn test_generates_correct_inputs() {
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let expected_inputs_str =
            std::fs::read_to_string("test/fixtures/claim_ens_1/inputs.json").unwrap();
        let expected_inputs: Value = serde_json::from_str(&expected_inputs_str).unwrap();

        let inputs_str = generate_inputs(email).await.unwrap();
        let inputs: Value = serde_json::from_str(&inputs_str).unwrap();

        assert_eq!(inputs, expected_inputs);
    }

    #[tokio::test]
    async fn test_generate_proof() {
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let proof_str = prove_handler(email).await;
        let proof: ProofResponse = serde_json::from_str(&proof_str).unwrap();
        assert!(!proof.public_outputs.is_empty());
        assert_eq!(proof.proof.protocol, "groth16");
    }
}
