use anyhow::{Context, Result};
use ens_backend::{prove::{generate_inputs, generate_proof}, state::StateConfig};
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting fixtures generation");
    let config = StateConfig::from_file("config.json").context("Could not load config file")?;
    let basedir = std::path::PathBuf::from("test/fixtures/case1_claim");
    // for each test case it is expected that the file basedir/email.eml already exists
    // and then this script takes that file and generates inputs.json and prover_response.json in the same directory
    let email_file_path = basedir.join("email.eml");

    info!("Reading email from: {}", email_file_path.display());
    let email = std::fs::read_to_string(&email_file_path).context("Could not read email file")?;

    info!("Generating inputs...");
    let inputs = generate_inputs(&email).await.context("Could not generate inputs")?;
    info!("Inputs generated.");

    info!("Generating proof...");
    let proof = generate_proof(&email, &config.prover).await.context("Could not generate proof")?;
    info!("Proof generated.");

    let inputs_file_path = basedir.join("inputs.json");
    info!("Writing inputs to: {}", inputs_file_path.display());
    std::fs::write(
        &inputs_file_path,
        serde_json::to_string_pretty(&inputs).context("Could not serialize inputs")?,
    )
    .context("Could not write inputs.json")?;

    let prover_response_file_path = basedir.join("prover_response.json");
    info!("Writing prover response to: {}", prover_response_file_path.display());
    std::fs::write(
        &prover_response_file_path,
        serde_json::to_string_pretty(&proof).context("Could not serialize proof")?,
    )
    .context("Could not write prover_response.json")?;

    info!("Fixtures generation completed successfully.");
    Ok(())
}