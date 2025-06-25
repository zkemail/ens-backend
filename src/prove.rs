use crate::state::{ProverConfig, StateConfig};
use alloy::{
    primitives::{Address, address},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result};
use axum::{Router, extract::State, routing::post};
use regex::Regex;
use relayer_utils::{AccountCode, EmailCircuitParams, bytes32_to_fr, generate_email_circuit_input};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

// Generate bindings for the registrar contract
sol! {
    #[sol(rpc)]
    contract Registrar {
        function claim(string[], address) external;
    }
}

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

pub(crate) async fn send_claim_tx(parts: Vec<String>, body: &str) {
    let rpc = std::env::var("RPC_URL").unwrap();
    let signer: PrivateKeySigner = std::env::var("PRIVATE_KEY").unwrap().parse().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(&rpc)
        .await
        .unwrap();

    let registrar_addr: Address = address!("0xA1ACF2Dcfa1671389d15C4585fAAaC50B7A30D63");
    let registrar = Registrar::new(registrar_addr, provider.clone());

    let tx = registrar
        .claim(parts, extract_address(body).unwrap())
        .send()
        .await
        .unwrap();
    tx.get_receipt().await.unwrap();
}

fn extract_address(body: &str) -> Option<Address> {
    // First decode quoted-printable encoding
    let decoded = body
        .replace("=\r\n", "") // Remove soft line breaks
        .replace("=\n", "")
        .replace("=3D", "="); // Replace =3D with =

    // Create regex to match the address pattern inside zkemail div
    let re =
        Regex::new(r#"<div[^>]*zkemail[^>]*>Claim ENS name for address (0x[a-fA-F0-9]+)"#).unwrap();

    // Extract the address from the match and convert to Address type
    re.captures(&decoded)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().parse().unwrap())
}

fn extract_email_segments(header: &str) -> Option<(Vec<String>, String)> {
    let re = Regex::new(r"From:[^\r\n]*<([^>]+)>").unwrap();

    if let Some(caps) = re.captures(header) {
        if let Some(email_match) = caps.get(1) {
            let email = email_match.as_str();

            let mut iter = email.split('@');
            if let (Some(local), Some(host)) = (iter.next(), iter.next()) {
                let mut parts = Vec::new();

                for segment in local.split('.') {
                    parts.push(segment.to_string());
                }
                for segment in host.split('.') {
                    parts.push(segment.to_string());
                }

                return Some((parts, email.to_string()));
            }
        }
    }

    None
}

pub async fn generate_proof(body: String, prover_config: &ProverConfig) -> Result<String> {
    let prove_request = ProveRequest {
        blueprint_id: &prover_config.blueprint_id,
        proof_id: "",
        zkey_download_url: &prover_config.zkey_download_url,
        circuit_cpp_download_url: &prover_config.circuit_cpp_download_url,
        input: serde_json::from_str(
            &generate_inputs(body)
                .await
                .context("Failed to generate inputs")?,
        )
        .context("Failed to convert inputs to json")?,
    };

    Client::new()
        .post(&prover_config.url)
        .header("x-api-key", &prover_config.api_key)
        .json(&prove_request)
        .send()
        .await
        .context("Failed to send request")?
        .text()
        .await
        .context("Failed to get response text")
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

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(prove_handler))
}

#[cfg(test)]
pub mod test {
    use super::{ProofResponse, ProverConfig, generate_inputs};
    use crate::prove::{
        ProveRequest, extract_address, extract_email_segments, generate_proof,
    };
    use alloy::primitives::address;
    use httpmock::prelude::*;
    use serde_json::Value;

    #[test]
    fn test_extract_email_parts() {
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let expected_parts = vec!["thezdev1", "gmail", "com"];
        let email_parts = extract_email_segments(&email).unwrap();
        assert_eq!(email_parts.0, expected_parts);
    }

    #[test]
    fn test_extract_address() {
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let address = extract_address(&email);
        assert_eq!(
            address,
            Some(address!("0xafBD210c60dD651892a61804A989eEF7bD63CBA0"))
        );

        // Test with invalid input
        let invalid_body = "<div>No address here</div>";
        assert_eq!(extract_address(invalid_body), None);
    }

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
        let server = MockServer::start();
        let email = std::fs::read_to_string("test/fixtures/claim_ens_1/email.eml").unwrap();
        let inputs_str = generate_inputs(email.clone()).await.unwrap();
        let inputs: Value = serde_json::from_str(&inputs_str).unwrap();

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

        let proof_str = generate_proof(email, &config)
            .await
            .unwrap();
        mock.assert();
        let proof: ProofResponse = serde_json::from_str(&proof_str).unwrap();
        assert!(!proof.public_outputs.is_empty());
        assert_eq!(proof.proof.protocol, "groth16");
    }
}
