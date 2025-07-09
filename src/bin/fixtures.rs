use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use ens_backend::{
    prove::{generate_inputs, generate_proof},
    state::StateConfig,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting fixtures generation");
    let config =
        Arc::new(StateConfig::from_file("config.json").context("Could not load config file")?);
    let fixtures_dir = std::path::PathBuf::from("test/fixtures");
    let test_cases =
        std::fs::read_dir(&fixtures_dir).context("Could not read fixtures directory")?;

    for case in test_cases {
        let entry = case.context("Could not read directory entry")?;
        let basedir = entry.path();

        if basedir.is_dir() {
            info!("Processing directory: {}", basedir.display());
            process_raw_email_file(basedir.clone(), config.clone())
                .await
                .context(format!("Could not process {:?}", basedir))?;
        }
    }

    Ok(())
}

// for each test case it is expected that the file basedir/email.eml already exists
// and then this script takes that file and generates inputs.json and prover_response.json in the same directory
async fn process_raw_email_file(basedir: PathBuf, config: Arc<StateConfig>) -> Result<()> {
    let email_file_path = basedir.join("email.eml");
    let inputs_file_path = basedir.join("inputs.json");
    let prover_response_file_path = basedir.join("prover_response.json");

    // Check if all three files already exist
    if email_file_path.exists() && inputs_file_path.exists() && prover_response_file_path.exists() {
        info!("Skipping {} - all files already exist", basedir.display());
        return Ok(());
    }

    info!("Reading email from: {}", email_file_path.display());
    let email = std::fs::read_to_string(&email_file_path).context("Could not read email file")?;

    info!("Generating inputs...");
    let inputs = generate_inputs(&email)
        .await
        .context("Could not generate inputs")?;
    info!("Inputs generated.");

    info!("Generating proof...");
    let proof = generate_proof(&email, &config.prover)
        .await
        .context("Could not generate proof")?;
    info!("Proof generated.");

    info!("Writing inputs to: {}", inputs_file_path.display());
    std::fs::write(
        &inputs_file_path,
        serde_json::to_string_pretty(&inputs).context("Could not serialize inputs")?,
    )
    .context("Could not write inputs.json")?;

    info!(
        "Writing prover response to: {}",
        prover_response_file_path.display()
    );
    std::fs::write(
        &prover_response_file_path,
        serde_json::to_string_pretty(&proof).context("Could not serialize proof")?,
    )
    .context("Could not write prover_response.json")?;

    info!("Fixtures generation completed successfully.");

    Ok(())
}
