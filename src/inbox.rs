use crate::command::CommandRequest;
use crate::prove::{ProofResponse, SolidityProof, generate_proof};
use crate::state::StateConfig;
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use alloy::{providers::ProviderBuilder, sol};
use alloy_primitives::address;
use axum::{Router, extract::State, routing::post};
use reqwest::StatusCode;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info};

sol! {
    #[sol(rpc)]
    contract ProofEncoder {
        function encode(uint256[] memory input, bytes memory proof) external view returns (bytes memory);
        function entrypoint(bytes calldata command) external;
    }
}

/// Handles incoming email confirmations for commands
pub async fn inbox_handler(
    State(state): State<Arc<StateConfig>>,
    body: String,
) -> Result<(), (StatusCode, String)> {
    info!("Received inbox request");

    let command_request =
        CommandRequest::from_email_body(&body).map_err(|e| -> (StatusCode, String) {
            error!("Failed to get command request: {:?}", e);
            e.into()
        })?;
    info!("{:?}", command_request);

    let proof: ProofResponse = generate_proof(&body, &state.prover).await.map_err(|e| {
        error!("Failed to generate proof: {:?}", e);
        (StatusCode::EXPECTATION_FAILED, e.to_string())
    })?;
    info!("{:?}", proof);

    let chain = state.rpc.first().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        String::from("No rpc found"),
    ))?;
    let signer: PrivateKeySigner = chain.private_key.parse().unwrap();

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(&chain.url)
        .await
        .map_err(|e| {
            error!("Failed to connect to rpc");
            (StatusCode::FAILED_DEPENDENCY, e.to_string())
        })?;
    info!("{:?}", provider);

    let public_inputs = proof.public_inputs().map_err(|e| {
        error!("Failed to get public inputs: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;
    let proof_bytes = proof.proof_bytes().map_err(|e| {
        error!("Failed to get proof bytes: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;
    info!("proof bytes {}", proof_bytes);
    info!("public signals {:?}", public_inputs.clone());

    let verifier = ProofEncoder::new(command_request.verifier, provider);
    let encoded_proof = verifier
        .encode(public_inputs, proof_bytes)
        .call()
        .await
        .map_err(|e| {
            error!("Failed to encode proof: {:?}", e);
            (StatusCode::FAILED_DEPENDENCY, e.to_string())
        })?;
    info!("Encoded proof: {}", encoded_proof.clone());

    verifier
        .entrypoint(encoded_proof)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to submit the proof: {:?}", e);
            (StatusCode::FAILED_DEPENDENCY, e.to_string())
        })?
        .watch()
        .await
        .expect("Could not watch transaction");
    info!("Transaction submitted");

    Ok(())
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(inbox_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ProverConfig;
    use httpmock::prelude::*;
    use std::fs;
    use tracing_subscriber::fmt::format::FmtSpan;

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
        let prover_response = fs::read_to_string("test/fixtures/case1_claim/prover_response.json")
            .expect("Failed to read prover response fixture");

        // Create a mock for the prover endpoint
        let prover_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/prove")
                .header("x-api-key", "test-api-key");
            then.status(200)
                .header("content-type", "application/json")
                .body(&prover_response);
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
        let email_content = fs::read_to_string("test/fixtures/case1_claim/email.eml")
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

    #[tokio::test]
    async fn test_inbox_handler_with_resolver() {
        // Initialize test logger
        init_test_logger();

        let config = StateConfig::from_file("config.json").expect("failed to load config.json");

        // Start a mock server
        let server = MockServer::start();

        // Read the expected prover response
        let prover_response = fs::read_to_string("test/fixtures/case3/prover_response.json")
            .expect("Failed to read prover response fixture");

        // Create a mock for the prover endpoint
        let prover_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/prove")
                .header("x-api-key", "test-api-key");
            then.status(200)
                .header("content-type", "application/json")
                .body(&prover_response);
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
        let email_content = fs::read_to_string("test/fixtures/case3/email.eml")
            .expect("Failed to read test email fixture");

        // Call the inbox handler
        let result = inbox_handler(State(state), email_content).await;

        // Verify the result
        assert_eq!(result, Ok(()));

        // Verify the prover was called
        prover_mock.assert();

        // TODO: Once the handler is fully implemented, add more assertions:
        // - Verify the proof was generated correctly
        // - Verify the command was extracted correctly
        // - Verify the from address was extracted correctly
    }
}
