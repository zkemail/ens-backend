use ens_backend::prove::generate_inputs;

#[tokio::main]
async fn main() {
    let email = std::fs::read_to_string("test/fixtures/case1_claim/email.eml").unwrap();
    let inputs = generate_inputs(&email).await.unwrap();
    println!("{:?}", inputs);
}