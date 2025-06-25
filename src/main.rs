use axum::Router;
mod command;
mod prove;
mod smtp;
mod state;

use state::StateConfig;

#[tokio::main]
async fn main() {
    let state = StateConfig::from_file("config.json").expect("INVALID CONFIG");

    let app = Router::new()
        .nest("/request", command::routes())
        .nest("/inbox", prove::routes()) // will be called by the IMAP server
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4500").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
