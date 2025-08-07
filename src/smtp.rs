use axum::http::StatusCode;
use reqwest::Client;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SmtpRequest {
    pub to: String,
    pub subject: String,
    pub body_plain: String,
    pub body_html: String,
    pub reference: Option<String>,
    pub reply_to: Option<String>,
    pub body_attachments: Option<String>,
}

impl SmtpRequest {
    pub async fn send(&self, smtp_url: &str) -> Result<(), (StatusCode, String)> {
        Self::send_request(self, smtp_url).await
    }

    pub async fn send_request(
        request: &SmtpRequest,
        smtp_url: &str,
    ) -> Result<(), (StatusCode, String)> {
        Client::new()
            .post(smtp_url)
            .json(request)
            .send()
            .await
            .map(|_| ())
            .map_err(|err| (StatusCode::SERVICE_UNAVAILABLE, err.to_string()))
    }
}
