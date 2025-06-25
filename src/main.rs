use axum::Router;
use dotenv::dotenv;
mod command_request;
mod prove;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let app = Router::new()
        .nest("/request", command_request::routes()) // called by the user
        .nest("/inbox", prove::routes()); // will be called by the IMAP server 
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4500").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
