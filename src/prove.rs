use crate::state::{ProverConfig, StateConfig};
use anyhow::{Context, Result};
use axum::{Router, extract::State, routing::post};
use regex::Regex;
use relayer_utils::{AccountCode, EmailCircuitParams, bytes32_to_fr, generate_email_circuit_input};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(Serialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct ProveRequest<'a> {
    blueprint_id: &'a str,
    proof_id: &'a str,
    zkey_download_url: &'a str,
    circuit_cpp_download_url: &'a str,
    input: Value,
}

#[derive(Deserialize)]
pub struct Proof {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
    protocol: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofResponse {
    proof: Proof,
    public_outputs: Vec<String>,
}

pub async fn prove_handler(State(state): State<Arc<StateConfig>>, body: String) -> String {
    let _proof = generate_proof(body, &state.prover).await.unwrap();
    String::from("")
}

pub async fn generate_proof(body: String, prover_config: &ProverConfig) -> Result<String> {
    Client::new()
        .post(&prover_config.url)
        .header("x-api-key", &prover_config.api_key)
        .json(&ProveRequest {
            blueprint_id: &prover_config.blueprint_id,
            proof_id: "",
            zkey_download_url: &prover_config.zkey_download_url,
            circuit_cpp_download_url: &prover_config.circuit_cpp_download_url,
            input: generate_inputs(body).await?,
        })
        .send()
        .await
        .context("Failed to send request")?
        .text()
        .await
        .context("Failed to get response text")
}

pub async fn generate_inputs(body: String) -> Result<Value> {
    Ok(serde_json::to_value(
        generate_email_circuit_input(
            &body,
            &AccountCode::from(bytes32_to_fr(&[0; 32])?),
            Some(EmailCircuitParams {
                ignore_body_hash_check: Some(false),
                max_body_length: Some(1024),
                max_header_length: Some(1024),
                sha_precompute_selector: Some(String::from(
                    "(<div id=3D\"[^\"]*zkemail[^\"]*\"[^>]*>)",
                )),
            }),
        )
        .await
        .context("Failed to generate email circuit inputs")?,
    )
    .context("Failed to convert inputs to json")?)
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(prove_handler))
}

#[cfg(test)]
pub mod test {
    use super::{ProofResponse, ProverConfig, generate_inputs};
    use crate::prove::{ProveRequest, generate_proof};
    use httpmock::prelude::*;
    use serde_json::Value;

    #[tokio::test]
    async fn test_generates_correct_inputs() {
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let expected_inputs_str =
            std::fs::read_to_string("test/fixtures/claim_ens_1/inputs.json").unwrap();
        let expected_inputs: Value = serde_json::from_str(&expected_inputs_str).unwrap();

        let inputs = generate_inputs(email).await.unwrap();

        assert_eq!(inputs, expected_inputs);
    }

    #[tokio::test]
    async fn test_generate_proof() {
        let server = MockServer::start();
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let inputs = generate_inputs(email.clone()).await.unwrap();

        let expected_request = ProveRequest {
            blueprint_id: "dummy-blueprint",
            proof_id: "",
            zkey_download_url: "http://example.com/circuit.zkey",
            circuit_cpp_download_url: "http://example.com/circuit.cpp",
            input: inputs,
        };

        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/prove")
                .header("x-api-key", "test-key")
                .json_body(serde_json::to_value(&expected_request).unwrap());
            let prover_response =
                std::fs::read_to_string("test/fixtures/claim_ens_1/prover_response.json").unwrap();
            then.status(200)
                .header("Content-Type", "application/json")
                .body(prover_response);
        });

        let config = ProverConfig {
            url: server.url("/api/prove"),
            api_key: "test-key".to_string(),
            blueprint_id: "dummy-blueprint".to_string(),
            circuit_cpp_download_url: "http://example.com/circuit.cpp".to_string(),
            zkey_download_url: "http://example.com/circuit.zkey".to_string(),
        };

        let proof_str = generate_proof(email, &config).await.unwrap();
        mock.assert();
        let proof: ProofResponse = serde_json::from_str(&proof_str).unwrap();
        assert!(!proof.public_outputs.is_empty());
        assert_eq!(proof.proof.protocol, "groth16");
    }
}
