use crate::smtp::SmtpRequest;
use crate::state::StateConfig;
use axum::{Json, Router, extract::State, routing::post};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

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
    subject: String,
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
    State(state): State<StateConfig>,
    Json(request): Json<CommandRequest>,
) -> Result<(), (StatusCode, String)> {
    Client::new()
        .post(state.smtp_url)
        .json(&SmtpRequest {
            to: request.email,
            subject: format!("[Reply Needed] {}", request.subject),
            body_plain: request.command.clone(),
            body_html: format!(
                "<html><body><div id=\"zkemail\">{}</div></body></html>",
                request.command
            ),
            reference: None,
            reply_to: None,
            body_attachments: None,
        })
        .send()
        .await
        .map(|_| ())
        .map_err(|err| (StatusCode::SERVICE_UNAVAILABLE, err.to_string()))
}

pub fn routes() -> Router<StateConfig> {
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
            subject: "Test Subject".to_string(),
            command: "Test Command".to_string(),
        };

        let expected_body = json!({
            "to": "test@example.com",
            "subject": "[Reply Needed] Test Subject",
            "body_plain": "Test Command",
            "body_html": "<html><body><div id=\"zkemail\">Test Command</div></body></html>",
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

        let result = command_handler(State(state), Json(request)).await;

        assert!(result.is_ok());
        smtp_mock.assert();
    }
}
