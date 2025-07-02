use crate::command::CommandRequest;
use crate::prove::{generate_proof, Proof};
use crate::state::{ChainConfig, ProverConfig, StateConfig};
use alloy::dyn_abi::Encoder;
use alloy::primitives::{Bytes, U256};
use alloy::sol_types::{SolValue, sol_data::{FixedArray, Uint}};
use alloy::{primitives::address, providers::ProviderBuilder, sol};
use alloy_sol_types::abi::Token;
use alloy_sol_types::SolType;
use axum::{Router, extract::State, routing::post};
use html_escape::decode_html_entities;
use httpmock::prelude::*;
use regex::Regex;
use reqwest::StatusCode;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;

sol! {
    #[sol(rpc)]
    contract ProofEncoder {
        function encode(uint256[] memory input, bytes memory proof) public returns (bytes memory);
        function verify(bytes calldata command) public view returns (bool);
    }
}

#[derive(Debug, Error)]
pub enum InboxError {
    #[error("Failed to decode quoted-printable: {0}")]
    QuotedPrintableDecoding(String),
    #[error("Failed to compile regex: {0}")]
    RegexCompilation(#[from] regex::Error),
    #[error("Failed to extract relayer data")]
    RelayerDataExtraction,
    #[error("Failed to parse relayer data: {0}")]
    RelayerDataParsing(#[from] serde_json::Error),
    #[error("Failed to generate proof: {0}")]
    ProofGeneration(String),
}

impl From<InboxError> for (StatusCode, String) {
    fn from(err: InboxError) -> Self {
        let status = match &err {
            InboxError::QuotedPrintableDecoding(_) => StatusCode::BAD_REQUEST,
            InboxError::RegexCompilation(_) => StatusCode::INTERNAL_SERVER_ERROR,
            InboxError::RelayerDataExtraction => StatusCode::BAD_REQUEST,
            InboxError::RelayerDataParsing(_) => StatusCode::BAD_REQUEST,
            InboxError::ProofGeneration(_) => StatusCode::EXPECTATION_FAILED,
        };
        (status, err.to_string())
    }
}

/// Decodes quoted-printable encoded text
fn decode_quoted_printable(body: &str) -> Result<String, InboxError> {
    quoted_printable::decode(body, quoted_printable::ParseMode::Robust)
        .map_err(|e| InboxError::QuotedPrintableDecoding(e.to_string()))
        .map(|decoded| String::from_utf8_lossy(&decoded).into_owned())
}

/// Extracts the command request from the email body
fn get_command_request(body: &str) -> Result<CommandRequest, InboxError> {
    let clean_body = decode_quoted_printable(body)?;
    info!("Clean body: {:?}", clean_body);

    // Extract relayer data from the hidden div using regex
    let re = Regex::new(r#"<div[^>]*id="[^"]*relayer-data[^"]*"[^>]*>(.*?)</div>"#)?;

    let relayer_data = re
        .captures(&clean_body)
        .and_then(|cap| cap.get(1))
        .ok_or(InboxError::RelayerDataExtraction)?
        .as_str();

    let decoded_relayer_data = decode_html_entities(&relayer_data);
    info!("Extracted relayer data: {}", decoded_relayer_data);

    // Extract email from HTML anchor tag if present
    let anchor_re = Regex::new(r#"<a[^>]*>([^<]+)</a>"#)?;
    let decoded_relayer_data = anchor_re
        .replace_all(&decoded_relayer_data, "$1")
        .to_string();

    let command_request: CommandRequest = serde_json::from_str(&decoded_relayer_data)?;
    Ok(command_request)
}

/// Handles incoming email confirmations for commands
pub async fn inbox_handler(
    State(state): State<Arc<StateConfig>>,
    body: String,
) -> Result<(), (StatusCode, String)> {
    info!("Received inbox request");

    let command_request = get_command_request(&body).map_err(|e: InboxError| {
        error!("Failed to get command request: {:?}", e);
        (StatusCode::BAD_REQUEST, e.to_string())
    })?;
    info!("{:?}", command_request);

    let proof = generate_proof(&body, &state.prover)
        .await
        .map_err(|e| InboxError::ProofGeneration(e.to_string()))?;
    info!("{:?}", proof);

    let provider = ProviderBuilder::new()
        .connect(
            &state
                .rpc
                .first()
                .ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("No RPC found"),
                ))?
                .url,
        )
        .await
        .map_err(|e| {
            error!("Failed to connect to rpc");
            (StatusCode::FAILED_DEPENDENCY, e.to_string())
        })?;

    info!("{:?}", provider);

    let verifier = ProofEncoder::new(command_request.verifier, provider);
    let public_inputs = proof
        .public_outputs
        .iter()
        .map(|o| U256::from_str_radix(&o, 10).unwrap())
        .collect::<Vec<U256>>();

    let pi_a = [
        U256::from_str_radix(proof.proof.pi_a.get(0).unwrap(), 10).unwrap(),
        U256::from_str_radix(proof.proof.pi_a.get(1).unwrap(), 10).unwrap(),
    ]; 
    
    let pi_b = [
        [
            U256::from_str_radix(proof.proof.pi_b.get(0).unwrap().get(1).unwrap(), 10).unwrap(),
            U256::from_str_radix(proof.proof.pi_b.get(0).unwrap().get(0).unwrap(), 10).unwrap(),
        ],
        [
            U256::from_str_radix(proof.proof.pi_b.get(1).unwrap().get(1).unwrap(), 10).unwrap(),
            U256::from_str_radix(proof.proof.pi_b.get(1).unwrap().get(0).unwrap(), 10).unwrap(),
        ],
    ];
    let pi_c = [
        U256::from_str_radix(proof.proof.pi_c.get(0).unwrap(), 10).unwrap(),
        U256::from_str_radix(proof.proof.pi_c.get(1).unwrap(), 10).unwrap(),
    ];
    
    let encoded = <([U256; 2], [[U256; 2]; 2], [U256; 2])>::abi_encode(&(pi_a, pi_b, pi_c));
    let proof_bytes = Bytes::from(encoded);

    info!("pi_a: {:?}", pi_a);
    info!("pi_b: {:?}", pi_b);
    info!("pi_c: {:?}", pi_c);
    info!("proof bytes {}", proof_bytes);
    info!("public signals {:?}", public_inputs.clone());
    
    let encoded_proof = verifier
        .encode(public_inputs, proof_bytes)
        .call()
        .await
        .unwrap();
    info!("Encoded proof: {}", encoded_proof.clone());
    let is_valid = verifier.verify(encoded_proof.clone()).call().await.unwrap();
    info!("Is encoding valid: {}", is_valid);

    Ok(())
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(inbox_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tokio;

    fn init_test_logger() {
        // Initialize logger only once
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_span_events(FmtSpan::FULL)
            .with_level(true)
            .with_file(true)
            .with_line_number(true)
            .with_target(false)
            .try_init();
    }

    #[tokio::test]
    async fn test_inbox_handler() {
        // Initialize test logger
        init_test_logger();

        let config = StateConfig::from_file("config.json").expect("failed to load config.json");

        // Start a mock server
        let server = MockServer::start();

        // Read the expected prover response
        let prover_response = fs::read_to_string("test/fixtures/claim_ens_1/prover_response.json")
            .expect("Failed to read prover response fixture");

        // Create a mock for the prover endpoint
        let prover_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/prove")
                .header("x-api-key", "test-api-key");
            then.status(200)
                .header("content-type", "application/json")
                .body(prover_response);
        });

        // Setup test state with mock server URL
        let state = Arc::new(StateConfig {
            smtp_url: "http://localhost:3000/api/sendEmail".to_string(),
            prover: ProverConfig {
                url: server.url("/api/prove"),
                api_key: "test-api-key".to_string(),
                blueprint_id: "test-blueprint-id".to_string(),
                circuit_cpp_download_url: "http://example.com/circuit.cpp".to_string(),
                zkey_download_url: "http://example.com/circuit.zkey".to_string(),
            },
            rpc: config.rpc.clone(),
        });

        // Read test fixture email
        let email_content = fs::read_to_string("test/fixtures/claim_ens_1/email.eml")
            .expect("Failed to read test email fixture");

        // Call the inbox handler
        let result = inbox_handler(State(state), email_content).await;

        // Verify the result
        assert_eq!(result, Ok(()));

        // Verify the prover was called
        prover_mock.assert();

        // TODO: Once the handler is fully implemented, add more assertions:
        // - Verify the proof was generated correctly
        // - Verify the command was extracted correctly (should be "Claim ENS name for address 0xafBD210c60dD651892a61804A989eEF7bD63CBA0")
        // - Verify the from address was extracted correctly (should be "thezdev1@gmail.com")
    }
}
