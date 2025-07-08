use ens_backend::{prove::{generate_inputs, generate_proof}, state::StateConfig};

#[tokio::main]
async fn main() {
    let config = StateConfig::from_file("config.json").expect("Could not load config file");
    let basedir = std::path::PathBuf::from("test/fixtures/case1_claim");
    // for each test case it is expected that the file basedir/email.eml already exists
    // and then this script takes that file and generates inputs.json and prover_response.json in the same directory
    let email_file_path = basedir.join("email.eml");

    let email = std::fs::read_to_string(&email_file_path).unwrap();
    let inputs = generate_inputs(&email).await.unwrap();
    let proof = generate_proof(&email, &config.prover).await.expect("Could not generate proof");

    

    println!("{:?}", proof);
   
}