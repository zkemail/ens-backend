use alloy::{
    primitives::{Address, address},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result};
use axum::{Router, routing::post};
use dotenv::dotenv;
use regex::Regex;
use relayer_utils::{AccountCode, EmailCircuitParams, bytes32_to_fr, generate_email_circuit_input};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;

#[derive(Serialize, Deserialize, Debug)]
pub struct ClaimRequest {
    pub email: String,
    pub address: Address,
}

#[derive(Debug, Serialize)]
struct SmtpRequest {
    to: String,
    subject: String,
    body_plain: String,
    body_html: String,
    reference: Option<String>,
    reply_to: Option<String>,
    body_attachments: Option<String>,
}
// Generate bindings for the registrar contract
sol! {
    #[sol(rpc)]
    contract Registrar {
        function claim(string[], address) external;
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ProveRequest {
    blueprint_id: String,
    proof_id: String,
    zkey_download_url: String,
    circuit_cpp_download_url: String,
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

pub async fn prove_handler(body: String) -> String {
    let parts = extract_email_segments(&body).unwrap();
    send_claim_tx(parts.clone().0, &body).await;

    dotenv().ok();
    let smtp_url = std::env::var("SMTP_URL").expect("SMTP_URL NOT SET");
    let client = Client::new();

    // build the smtp request
    let smtp_request = SmtpRequest {
        to: parts.1.clone(),
        subject: String::from("Ens Claimed"),
        body_plain: format!("Successfully Claimed: {}", parts.1.replace("@", ".")),
        body_html: format!("Successfully Claimed: {}.zkemail.eth", parts.1.replace("@", ".")),
        reference: None,
        reply_to: None,
        body_attachments: None,
    };

    client
        .post(smtp_url)
        .json(&smtp_request)
        .send()
        .await
        .unwrap();

    String::from("")
    // return generate_proof(body).await.unwrap()
}

async fn send_claim_tx(parts: Vec<String>, body: &str) {
    println!(
        "[send_claim_tx] Starting claim transaction with parts: {:?}",
        parts
    );

    dotenv().ok();
    println!("[send_claim_tx] Environment variables loaded");

    let rpc = std::env::var("RPC_URL").unwrap();
    println!("[send_claim_tx] RPC URL retrieved");

    let signer: PrivateKeySigner = std::env::var("PRIVATE_KEY").unwrap().parse().unwrap();
    println!("[send_claim_tx] Private key parsed successfully");

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(&rpc)
        .await
        .unwrap();
    println!("[send_claim_tx] Provider connected to RPC");

    let registrar_addr: Address = address!("0xA1ACF2Dcfa1671389d15C4585fAAaC50B7A30D63");
    println!("[send_claim_tx] Registrar address: {:?}", registrar_addr);

    let registrar = Registrar::new(registrar_addr, provider.clone());
    println!("[send_claim_tx] Registrar contract instance created");

    println!("[send_claim_tx] Sending claim transaction...");
    let tx = registrar.claim(parts, extract_address(body).unwrap()).send().await.unwrap();
    println!("[send_claim_tx] Transaction sent, hash: {:?}", tx.tx_hash());

    println!("[send_claim_tx] Waiting for transaction receipt...");
    let receipt = tx.get_receipt().await.unwrap();
    println!(
        "[send_claim_tx] Transaction receipt received: {:?}",
        receipt
    );
}

fn extract_address(body: &str) -> Option<Address> {
    // First decode quoted-printable encoding
    let decoded = body.replace("=\r\n", "")  // Remove soft line breaks
        .replace("=\n", "")
        .replace("=3D", "=");  // Replace =3D with =

    // Create regex to match the address pattern inside zkemail div
    let re = Regex::new(r#"<div[^>]*zkemail[^>]*>Claim ENS name for address (0x[a-fA-F0-9]+)"#).unwrap();
    
    // Extract the address from the match and convert to Address type
    re.captures(&decoded)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().parse().unwrap())
}

fn extract_email_segments(header: &str) -> Option<(Vec<String>, String)> {
    println!("[extract_email_segments] Starting email extraction from header");

    // match "From:" up to the end of that header line, capture everything inside "<...>"
    let re = Regex::new(r"From:[^\r\n]*<([^>]+)>").unwrap();
    println!("[extract_email_segments] Regex pattern compiled");

    // try to capture the inner email; if that fails, bail out
    if let Some(caps) = re.captures(header) {
        println!("[extract_email_segments] Found 'From:' header match");
        if let Some(email_match) = caps.get(1) {
            let email = email_match.as_str();
            println!("[extract_email_segments] Extracted email: {}", email);

            // split into local‐part and host
            let mut iter = email.split('@');
            if let (Some(local), Some(host)) = (iter.next(), iter.next()) {
                println!(
                    "[extract_email_segments] Local part: {}, Host part: {}",
                    local, host
                );
                let mut parts = Vec::new();

                // break local-part on every dot
                for segment in local.split('.') {
                    parts.push(segment.to_string());
                }
                // break domain-part on every dot
                for segment in host.split('.') {
                    parts.push(segment.to_string());
                }

                println!("[extract_email_segments] Final parts: {:?}", parts);
                return Some((parts, email.to_string()));
            } else {
                println!(
                    "[extract_email_segments] Failed to split email into local and host parts"
                );
            }
        } else {
            println!("[extract_email_segments] No email found in angle brackets");
        }
    } else {
        println!("[extract_email_segments] No 'From:' header match found");
    }

    println!("[extract_email_segments] Returning None - extraction failed");
    None
}

pub async fn generate_proof(body: String) -> Result<String> {
    dotenv().ok();
    let prover_url = env::var("PROVER_URL").expect("PROVER_URL NOT SET");
    let prover_api_key = env::var("PROVER_API_KEY").expect("PROVER_API_KEY NOT SET");
    let blueprint_id = env::var("BLUEPRINT_ID").expect("BLUEPRINT_ID NOT SET");
    let circuit_cpp_download_url =
        env::var("CIRCUIT_CPP_DOWNLOAD_URL").expect("CIRCUIT_CPP_DOWNLOAD_URL NOT SET");
    let zkey_download_url = env::var("ZKEY_DOWNLOAD_URL").expect("ZKEY_DOWNLOAD_URL NOT SET");

    let prove_request = ProveRequest {
        blueprint_id,
        proof_id: "".to_string(),
        zkey_download_url,
        circuit_cpp_download_url,
        input: serde_json::from_str(
            &generate_inputs(body)
                .await
                .context("Failed to generate inputs")?,
        )
        .context("Failed to convert inputs to json")?,
    };

    Client::new()
        .post(prover_url)
        .header("x-api-key", prover_api_key)
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

pub fn routes() -> Router {
    Router::<()>::new().route("/", post(prove_handler))
}

#[cfg(test)]
pub mod test {
    use super::{ProofResponse, generate_inputs};
    use crate::prove::{ProveRequest, extract_email_segments, prove_handler, send_claim_tx, extract_address};
    use httpmock::prelude::*;
    use serde_json::Value;
    use alloy::primitives::address;

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
        assert_eq!(address, Some(address!("0xafBD210c60dD651892a61804A989eEF7bD63CBA0")));

        // Test with invalid input
        let invalid_body = "<div>No address here</div>";
        assert_eq!(extract_address(invalid_body), None);
    }

    #[tokio::test]
    async fn test_claim() {
        send_claim_tx(vec![String::from("from"), String::from("rust")], "").await;
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
            blueprint_id: "dummy-blueprint".to_string(),
            proof_id: "".to_string(),
            zkey_download_url: "http://example.com/circuit.zkey".to_string(),
            circuit_cpp_download_url: "http://example.com/circuit.cpp".to_string(),
            input: inputs,
        };

        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/api/prove")
                .header("x-api-key", "test-key")
                .json_body_obj(&expected_request);
            let prover_response =
                std::fs::read_to_string("test/fixtures/claim_ens_1/prover_response.json").unwrap();
            then.status(200)
                .header("Content-Type", "application/json")
                .body(prover_response);
        });

        unsafe {
            std::env::set_var("PROVER_URL", server.url("/api/prove"));
            std::env::set_var("PROVER_API_KEY", "test-key");
            std::env::set_var("BLUEPRINT_ID", "dummy-blueprint");
            std::env::set_var("CIRCUIT_CPP_DOWNLOAD_URL", "http://example.com/circuit.cpp");
            std::env::set_var("ZKEY_DOWNLOAD_URL", "http://example.com/circuit.zkey");
        }

        let proof_str = prove_handler(email).await;
        mock.assert();
        let proof: ProofResponse = serde_json::from_str(&proof_str).unwrap();
        assert!(!proof.public_outputs.is_empty());
        assert_eq!(proof.proof.protocol, "groth16");
    }
}
