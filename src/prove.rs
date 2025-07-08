use crate::state::ProverConfig;
use alloy::primitives::{Bytes, U256};
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use relayer_utils::{AccountCode, EmailCircuitParams, bytes32_to_fr, generate_email_circuit_input};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum ProofConversionError {
    #[error("Failed to parse string to U256: {0}")]
    U256Parsing(String),
    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),
}

pub trait SolidityProof {
    fn public_inputs(&self) -> Result<Vec<U256>, ProofConversionError>;
    fn proof_bytes(&self) -> Result<Bytes, ProofConversionError>;
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

#[derive(Deserialize, Debug, Serialize)]
pub struct Proof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
}

#[derive(Deserialize, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofResponse {
    pub proof: Proof,
    pub public_outputs: Vec<String>,
}

impl SolidityProof for ProofResponse {
    fn public_inputs(&self) -> Result<Vec<U256>, ProofConversionError> {
        self.public_outputs
            .iter()
            .map(|o| {
                U256::from_str_radix(o, 10)
                    .map_err(|e| ProofConversionError::U256Parsing(e.to_string()))
            })
            .collect()
    }

    fn proof_bytes(&self) -> Result<Bytes, ProofConversionError> {
        let pi_a_res: Result<Vec<U256>, _> = self
            .proof
            .pi_a
            .iter()
            .take(2)
            .map(|s| {
                U256::from_str_radix(s, 10)
                    .map_err(|e| ProofConversionError::U256Parsing(e.to_string()))
            })
            .collect();
        let pi_a: [U256; 2] = pi_a_res?.try_into().map_err(|_| {
            ProofConversionError::InvalidProofFormat("pi_a must have 2 elements".to_string())
        })?;

        if self.proof.pi_b.len() < 2 || self.proof.pi_b.iter().any(|inner| inner.len() < 2) {
            return Err(ProofConversionError::InvalidProofFormat(
                "pi_b must be a 2x2 matrix".to_string(),
            ));
        }

        let pi_b_0_1 = U256::from_str_radix(&self.proof.pi_b[0][1], 10)
            .map_err(|e| ProofConversionError::U256Parsing(e.to_string()))?;
        let pi_b_0_0 = U256::from_str_radix(&self.proof.pi_b[0][0], 10)
            .map_err(|e| ProofConversionError::U256Parsing(e.to_string()))?;
        let pi_b_1_1 = U256::from_str_radix(&self.proof.pi_b[1][1], 10)
            .map_err(|e| ProofConversionError::U256Parsing(e.to_string()))?;
        let pi_b_1_0 = U256::from_str_radix(&self.proof.pi_b[1][0], 10)
            .map_err(|e| ProofConversionError::U256Parsing(e.to_string()))?;
        let pi_b: [[U256; 2]; 2] = [[pi_b_0_1, pi_b_0_0], [pi_b_1_1, pi_b_1_0]];

        let pi_c_res: Result<Vec<U256>, _> = self
            .proof
            .pi_c
            .iter()
            .take(2)
            .map(|s| {
                U256::from_str_radix(s, 10)
                    .map_err(|e| ProofConversionError::U256Parsing(e.to_string()))
            })
            .collect();
        let pi_c: [U256; 2] = pi_c_res?.try_into().map_err(|_| {
            ProofConversionError::InvalidProofFormat("pi_c must have 2 elements".to_string())
        })?;

        let encoded = <([U256; 2], [[U256; 2]; 2], [U256; 2])>::abi_encode(&(pi_a, pi_b, pi_c));
        Ok(Bytes::from(encoded))
    }
}

pub async fn generate_proof(body: &str, prover_config: &ProverConfig) -> Result<ProofResponse> {
    info!("Generating proof");
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
        .json::<ProofResponse>()
        .await
        .context("Failed to deserialize proof response")
}

pub async fn generate_inputs(body: &str) -> Result<Value> {
    info!("Generating inputs");
    serde_json::from_str(
        &generate_email_circuit_input(
            body,
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
    .context("Failed to convert inputs to json")
}

#[cfg(test)]
pub mod test {
    use super::{ProverConfig, generate_inputs};
    use crate::prove::{ProveRequest, generate_proof};
    use httpmock::prelude::*;
    use serde_json::Value;

    #[tokio::test]
    async fn test_generates_correct_inputs() {
        let email = std::fs::read_to_string("test/fixtures/case1_claim/email.eml").unwrap();
        let expected_inputs_str =
            std::fs::read_to_string("test/fixtures/case1_claim/inputs.json").unwrap();
        let expected_inputs: Value = serde_json::from_str(&expected_inputs_str).unwrap();
        let inputs = generate_inputs(&email).await.unwrap();

        assert_eq!(inputs, expected_inputs);
    }

    #[tokio::test]
    async fn test_generate_proof() {
        let server = MockServer::start();
        let email = std::fs::read_to_string("test/fixtures/case1_claim/email.eml").unwrap();
        let inputs = generate_inputs(&email).await.unwrap();

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
                std::fs::read_to_string("test/fixtures/case1_claim/prover_response.json").unwrap();
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

        let proof = generate_proof(&email, &config).await.unwrap();
        mock.assert();
        assert!(!proof.public_outputs.is_empty());
        assert_eq!(proof.proof.protocol, "groth16");
    }
}
