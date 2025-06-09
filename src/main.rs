use axum::{Router};
mod claim;


#[tokio::main]
async fn main() {
    let app = Router::new().nest("/claim", claim::routes::routes());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4500").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}