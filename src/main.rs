use axum::Router;
use dotenv::dotenv;
use tower_http::cors::{Any, CorsLayer};
mod claim;
mod prove;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .nest("/claim", claim::routes())
        .nest("/prove", prove::routes())
        .layer(cors);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4500").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
