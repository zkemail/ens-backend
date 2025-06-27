use crate::prove::generate_proof;
use crate::state::StateConfig;
use axum::{Router, extract::State, routing::post};
use relayer_utils::{parse_email, ParsedEmail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

pub async fn inbox_handler(State(state): State<Arc<StateConfig>>, body: String) -> String {
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

    let parsed_email = ParsedEmail::new_from_raw_email(&body).await.expect("Failed to parse email");
    let from_addr = parsed_email.get_from_addr().expect("Failed to get from address");
    let command = parsed_email.get_command(false).expect("Failed to get command");

    info!("From address: {:?}", from_addr);
    info!("Command: {:?}", command);

    // info!("Received inbox request");
    // let proof = generate_proof(body, &state.prover).await.unwrap();
    // info!("Proof generated successfully");
    String::from("")
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(inbox_handler))
}
