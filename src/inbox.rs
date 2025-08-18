use crate::command::CommandRequest;
use crate::dkim::check_and_update_dkim;
use crate::prove::{ProofResponse, SolidityProof, generate_proof};
use crate::smtp::SmtpRequest;
use crate::state::StateConfig;
use alloy::signers::local::PrivateKeySigner;
use alloy::{providers::ProviderBuilder, sol};
use axum::{Router, extract::State, routing::post};
use reqwest::StatusCode;
use std::fs;
use std::sync::Arc;
use tracing::{error, info};

sol! {
    #[sol(rpc)]
    contract ProofEncoder {
        function encode(uint256[] memory input, bytes memory proof) external view returns (bytes memory);
        function entrypoint(bytes calldata command) external;
        function dkimRegistryAddress() external view returns (address);
    }
}

async fn send_success_email(
    state: &StateConfig,
    to: &str,
    tx_hash: &str,
) -> Result<(), (StatusCode, String)> {
    let template = fs::read_to_string("templates/transaction_success.html").map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read template: {}", e),
        )
    })?;

    let html_body = template.replace("{{tx_hash}}", tx_hash);

    SmtpRequest {
        to: to.to_string(),
        subject: "Your Request has been Completed".to_string(),
        body_plain: format!(
            "Your request has been successfully processed. Transaction hash: {}",
            tx_hash
        ),
        body_html: html_body,
        reference: None,
        reply_to: None,
        body_attachments: None,
    }
    .send(&state.smtp_url)
    .await
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

    let chain = state.rpc.first().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        String::from("No rpc found"),
    ))?;
    info!("chain {:?}", chain);

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

    let verifier = ProofEncoder::new(command_request.verifier, provider);
    let dkim_address = verifier.dkimRegistryAddress().call().await.map_err(|e| {
        error!("Failed to get dkim registry address: {:?}", e);
        (StatusCode::FAILED_DEPENDENCY, e.to_string())
    })?;
    info!("dkim_address {:?}", dkim_address);

    check_and_update_dkim(&body, dkim_address, state.clone())
        .await
        .map_err(|e| {
            error!("Failed to check and update dkim: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    let proof: ProofResponse = generate_proof(&body, &state.prover).await.map_err(|e| {
        error!("Failed to generate proof: {:?}", e);
        (StatusCode::EXPECTATION_FAILED, e.to_string())
    })?;
    info!("{:?}", proof);

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

    let encoded_proof = verifier
        .encode(public_inputs, proof_bytes)
        .call()
        .await
        .map_err(|e| {
            error!("Failed to encode proof: {:?}", e);
            (StatusCode::FAILED_DEPENDENCY, e.to_string())
        })?;
    info!("Encoded proof: {}", encoded_proof.clone());

    if !state.test {
        let pending_tx = verifier
            .entrypoint(encoded_proof)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to submit the proof: {:?}", e);
                (StatusCode::FAILED_DEPENDENCY, e.to_string())
            })?;
        let tx_hash = pending_tx.tx_hash().to_string();

        pending_tx
            .watch()
            .await
            .expect("Could not watch transaction");
        info!("Transaction submitted with hash {}", tx_hash);

        send_success_email(&state, &command_request.email, &tx_hash)
            .await
            .map_err(|e| {
                error!("Failed to send success email: {:?}", e);
                e
            })?;
    }

    Ok(())
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(inbox_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{IcpConfig, ProverConfig};

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
            icp: IcpConfig {
                dkim_canister_id: "test-dkim-canister-id".to_string(),
                wallet_canister_id: "test-wallet-canister-id".to_string(),
                ic_replica_url: "http://localhost:8080".to_string(),
            },
            pem_path: "test-pem-path".to_string(),
            smtp_url: "http://localhost:3000/api/sendEmail".to_string(),
            prover: ProverConfig {
                url: server.url("/api/prove"),
                api_key: "test-api-key".to_string(),
                blueprint_id: "test-blueprint-id".to_string(),
                circuit_cpp_download_url: "http://example.com/circuit.cpp".to_string(),
                zkey_download_url: "http://example.com/circuit.zkey".to_string(),
            },
            rpc: config.rpc.clone(),
            test: true,
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
    }

    #[tokio::test]
    async fn test_inbox_handler_with_resolver() {
        // Initialize test logger
        init_test_logger();

        let config = StateConfig::from_file("config.json").expect("failed to load config.json");

        // Start a mock server
        let server = MockServer::start();

        // Read the expected prover response
        let prover_response =
            fs::read_to_string("test/fixtures/case2_claim_with_resolver/prover_response.json")
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
            icp: IcpConfig {
                dkim_canister_id: "test-dkim-canister-id".to_string(),
                wallet_canister_id: "test-wallet-canister-id".to_string(),
                ic_replica_url: "http://localhost:8080".to_string(),
            },
            pem_path: "test-pem-path".to_string(),
            smtp_url: "http://localhost:3000/api/sendEmail".to_string(),
            prover: ProverConfig {
                url: server.url("/api/prove"),
                api_key: "test-api-key".to_string(),
                blueprint_id: "test-blueprint-id".to_string(),
                circuit_cpp_download_url: "http://example.com/circuit.cpp".to_string(),
                zkey_download_url: "http://example.com/circuit.zkey".to_string(),
            },
            rpc: config.rpc.clone(),
            test: true,
        });

        // Read test fixture email
        let email_content = fs::read_to_string("test/fixtures/case2_claim_with_resolver/email.eml")
            .expect("Failed to read test email fixture");

        // Call the inbox handler
        let result = inbox_handler(State(state), email_content).await;

        // Verify the result
        assert_eq!(result, Ok(()));

        // Verify the prover was called
        prover_mock.assert();
    }
}
