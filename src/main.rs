use axum::Router;
use dotenv::dotenv;
mod claim;
mod prove;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let app = Router::new()
        .nest("/claim", claim::routes())
        .nest("/prove", prove::routes());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4500").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
