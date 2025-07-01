use crate::prove::generate_proof;
use crate::state::{ChainConfig, ProverConfig, StateConfig};
use crate::command::CommandRequest;
use axum::{Router, extract::State, routing::post};
use httpmock::prelude::*;
use relayer_utils::{ParsedEmail, parse_email};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use regex::Regex;
use html_escape::decode_html_entities;

pub async fn inbox_handler(State(state): State<Arc<StateConfig>>, body: String) {
    /*
    this is the handler for the inbox endpoint
    it will receive the raw email content including the headers
    the email are supposed to be reply confirmations of commands sent to the relayer
    first we need to use relayer utils to parse the email,
    extract the sender, and the command, which is in a div with id zkemail
    then we generate the proof and send the command to command handler service
    which will craft a transaction based on the command and it corresponding verifier and submits the transaction to the blockchain
     */
    info!("Received inbox request");
    let proof = generate_proof(&body, &state.prover).await.map_err(|e| (StatusCode::EXPECTATION_FAILED, e.to_string()))?;
    info!("Proof: {:?}", proof);

    let clean_body = decode_quoted_printable(&body).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    info!("Clean body: {:?}", clean_body);

    // Extract relayer data from the hidden div using regex
    let re = Regex::new(r#"<div[^>]*id="[^"]*relayer-data[^"]*"[^>]*>(.*?)</div>"#)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let relayer_data = re.captures(&clean_body)
        .and_then(|cap| cap.get(1))
        .ok_or((StatusCode::BAD_REQUEST, "Failed to extract relayer data".to_string()))?
        .as_str();

    let decoded_relayer_data = decode_html_entities(&relayer_data).replace("[at]", "@");
    info!("Extracted relayer data: {}", decoded_relayer_data);

    // Extract email from HTML anchor tag if present
    let anchor_re = Regex::new(r#"<a[^>]*>([^<]+)</a>"#).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let decoded_relayer_data = anchor_re.replace_all(&decoded_relayer_data, "$1").to_string();

    let command_request: CommandRequest = serde_json::from_str(&decoded_relayer_data)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to parse relayer data: {}", e)))?;

    info!("Command request: {:?}", command_request);

    Ok(())
}

fn decode_quoted_printable(body: &str) -> Result<String, String> {
    let decoded = quoted_printable::decode(body, quoted_printable::ParseMode::Robust).map_err(|e| e.to_string())?;
    // Try to convert to UTF-8, replacing invalid sequences with a placeholder
    Ok(String::from_utf8_lossy(&decoded).into_owned())
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
            rpc: vec![ChainConfig {
                name: "test-chain".to_string(),
                chain_id: 1,
                url: "http://localhost:8545".to_string(),
                private_key: "0x1234567890abcdef".to_string(),
            }],
        });

        // Read test fixture email
        let email_content = fs::read_to_string("test/fixtures/claim_ens_1/email.eml")
            .expect("Failed to read test email fixture");

        // Call the inbox handler
        let result = inbox_handler(State(state), email_content).await;

        // Verify the result
        assert_eq!(result, Ok(String::from("")));

        // Verify the prover was called
        prover_mock.assert();

        // TODO: Once the handler is fully implemented, add more assertions:
        // - Verify the proof was generated correctly
        // - Verify the command was extracted correctly (should be "Claim ENS name for address 0xafBD210c60dD651892a61804A989eEF7bD63CBA0")
        // - Verify the from address was extracted correctly (should be "thezdev1@gmail.com")
    }
}
