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
