use crate::smtp::SmtpRequest;
use crate::state::StateConfig;
use axum::{Json, Router, extract::State, routing::post};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;
use std::{sync::Arc, fs};
use anyhow::Result;

/// Represents a request to initiate a command that requires email-based
/// authorization. The user provides their email, a subject for the email, and the
/// command to be authorized.
///
/// # Example
///
/// ```json
/// {
///     "email": "user@example.com",
///     "subject": "Link email to vitalik.eth",
///     "command": "I want to link this email to vitalik.eth"
/// }
/// ```
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandRequest {
    email: String,
    command: String,
}


/// This endpoint sends an email to the provided email address that embeds the
/// command a user wants to authorize. The user will need to reply to the email
/// for the continuation of the process. This handler is responsible for crafting
/// and sending the email.
///
/// The `command` is embedded in a `div` tag with the ID `zkemail` in the HTML body
/// of the email. This specific format is required for the circuits to extract the
/// command from the email reply.
pub async fn command_handler(
    State(state): State<Arc<StateConfig>>,
    Json(request): Json<CommandRequest>,
) -> Result<(), (StatusCode, String)> {
    let template = fs::read_to_string("templates/command_confirmation.html").map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let relayer_data = serde_json::to_string(&request).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let html_body = template.replace("{{command}}", &request.command).replace("{{relayer_data}}", relayer_data.as_str());

    info!("Command request: {:?}", request);

    SmtpRequest {
            to: request.email,
            subject: format!("[Reply Needed] {}", request.command),
            body_plain: request.command.clone(),
            body_html: html_body,
            reference: None,
            reply_to: None,
            body_attachments: None,
        }
        .send(&state.smtp_url)
        .await
}

pub fn routes() -> Router<Arc<StateConfig>> {
    Router::new().route("/", post(command_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChainConfig, ProverConfig};
    use httpmock::prelude::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_command_handler_success() {
        let server = MockServer::start();

        let request = CommandRequest {
            email: "test@example.com".to_string(),
            command: "Test Command".to_string(),
        };

        // Load the expected HTML template for comparison
        let template = fs::read_to_string("templates/command_confirmation.html").expect("Failed to read template");
        let relayer_data = serde_json::to_string(&request).expect("Failed to serialize request");
        let expected_html = template.replace("{{command}}", &request.command).replace("{{relayer_data}}", relayer_data.as_str());

        let expected_body = json!({
            "to": "test@example.com",
            "subject": "[Reply Needed] Test Command",
            "body_plain": "Test Command",
            "body_html": expected_html,
            "reference": null,
            "reply_to": null,
            "body_attachments": null
        });

        let smtp_mock = server.mock(|when, then| {
            when.method(POST).path("/").json_body(expected_body);
            then.status(200);
        });

        let state = StateConfig {
            smtp_url: server.url("/"),
            prover: ProverConfig {
                url: "".to_string(),
                api_key: "".to_string(),
                blueprint_id: "".to_string(),
                circuit_cpp_download_url: "".to_string(),
                zkey_download_url: "".to_string(),
            },
            rpc: vec![ChainConfig {
                name: "".to_string(),
                chain_id: 0,
                url: "".to_string(),
                private_key: "".to_string(),
            }],
        };

        let result = command_handler(State(Arc::new(state)), Json(request)).await;

        assert!(result.is_ok());
        smtp_mock.assert();
    }
}
