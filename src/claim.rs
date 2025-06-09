use axum::{routing::{post}, Json, Router};
use serde::{Serialize,Deserialize};
use dotenv::dotenv;
use reqwest::Client;
use alloy::{primitives::Address};

#[derive(Serialize,Deserialize,Debug)]
pub struct ClaimRequest {
    pub email: String,
    pub address: Address 
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

pub async fn claim_handler(Json(request): Json<ClaimRequest>) {
    dotenv().ok();
    let smtp_url= std::env::var("SMTP_URL").expect("SMTP_URL NOT SET");
    let client = Client::new();

    // build the smtp request
    let smtp_request = SmtpRequest {
        to: request.email,
        subject: String::from("Confirm Claiming ENS"),
        body_plain: format!("Claim ENS name for address {}", request.address),
        body_html: format!("<html><body><div id=\"zkemail\">Claim ENS name for address {}</div></body></html>", request.address),
        reference: None,
        reply_to: None,
        body_attachments: None
    };

    client.post(smtp_url).json(&smtp_request).send().await.unwrap();

}

pub fn routes() -> Router {
    Router::<()>::new().route("/", post(claim_handler))
}