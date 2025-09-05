use alloy::primitives::keccak256;
use anyhow::anyhow;
use candid::Encode;

use relayer_utils::ParsedEmail;
use relayer_utils::fr_to_bytes32;
use relayer_utils::public_key_hash;

use candid::CandidType;

use ic_agent::agent::http_transport::ReqwestTransport;
use ic_agent::agent::*;
use ic_agent::identity::*;
use ic_utils::canister::*;
use ic_utils::interfaces::WalletCanister;

use serde::Deserialize;

use crate::state::StateConfig;
use std::sync::Arc;

use alloy::hex::FromHex;
use alloy::primitives::{Address, Bytes, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;

use reqwest::StatusCode;
use tracing::{error, info};

sol! {
    #[sol(rpc)]
    contract ECDSAOwnedDKIMRegistry {
        function isKeyHashValid(bytes32 domainHash, bytes32 publicKeyHash) view returns (bool);
        function setDKIMPublicKeyHash(string memory selector, string memory domainName, bytes32 publicKeyHash, bytes memory signature) public;
    }
}

///  Amount of cycles charged by the ICP canister
pub const SIGN_CHARGED_CYCLE: u128 = 66_730_321_884;

// Number of confirmations required for a transaction to be considered confirmed
const CONFIRMATIONS: u64 = 1;

/// Represents a client for interacting with the DKIM Oracle.
#[derive(Debug, Clone)]
pub struct DkimOracleClient<'a> {
    /// The dkim oracle canister.
    pub dkim_canister: Canister<'a>,
    /// The wallet canister.
    pub wallet_canister: WalletCanister<'a>,
}

/// Represents a signed DKIM public key.
#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedDkimPublicKey {
    /// The selector for the DKIM key
    pub selector: String,
    /// The domain for the DKIM key
    pub domain: String,
    /// The signature of the DKIM key
    pub signature: String,
    /// The public key
    pub public_key: String,
    /// The hash of the public key
    pub public_key_hash: String,
}

impl<'a> DkimOracleClient<'a> {
    /// Generates an agent for the DKIM Oracle Client.
    ///
    /// # Arguments
    ///
    /// * `pem_path` - The path to the PEM file.
    /// * `replica_url` - The URL of the replica.
    ///
    /// # Returns
    ///
    /// An `anyhow::Result<Agent>`.
    pub fn gen_agent(pem_path: &str, replica_url: &str) -> anyhow::Result<Agent> {
        // Create identity from PEM file
        let identity = Secp256k1Identity::from_pem_file(pem_path)?;

        // Create transport using the replica URL
        let transport = ReqwestTransport::create(replica_url)?;

        // Build and return the agent
        let agent = AgentBuilder::default()
            .with_identity(identity)
            .with_transport(transport)
            .build()?;
        Ok(agent)
    }

    /// Creates a new DkimOracleClient.
    ///
    /// # Arguments
    ///
    /// * `dkim_canister_id` - The ID of the dkim canister.
    /// * `wallet_canister_id` - The ID of the wallet canister.
    /// * `agent` - The agent to use for communication.
    ///
    /// # Returns
    ///
    /// An `anyhow::Result<Self>`.
    pub async fn new(
        dkim_canister_id: &str,
        wallet_canister_id: &str,
        agent: &'a Agent,
    ) -> anyhow::Result<Self> {
        // Build the canister using the provided ID and agent
        let dkim_canister = CanisterBuilder::new()
            .with_canister_id(dkim_canister_id)
            .with_agent(agent)
            .build()?;
        let wallet_canister = WalletCanister::from_canister(
            ic_utils::Canister::builder()
                .with_agent(agent)
                .with_canister_id(wallet_canister_id)
                .build()?,
        )
        .await?;
        Ok(Self {
            dkim_canister,
            wallet_canister,
        })
    }

    /// Requests a signature for a DKIM public key.
    ///
    /// # Arguments
    ///
    /// * `selector` - The selector for the DKIM key.
    /// * `domain` - The domain for the DKIM key.
    ///
    /// # Returns
    ///
    /// An `anyhow::Result<SignedDkimPublicKey>`.
    pub async fn request_signature(
        &self,
        selector: &str,
        domain: &str,
    ) -> anyhow::Result<SignedDkimPublicKey> {
        // Build the request to sign the DKIM public key
        let mut arg = Argument::new();
        arg.set_raw_arg(Encode!(&selector, &domain).unwrap());
        let (response,) = self
            .wallet_canister
            .call128::<(Result<SignedDkimPublicKey, String>,), _>(
                *self.dkim_canister.canister_id(),
                "sign_dkim_public_key",
                arg,
                SIGN_CHARGED_CYCLE,
            )
            .call_and_wait()
            .await?;
        let sign = response.map_err(|e| anyhow!(format!("Error from canister: {:?}", e)))?;
        Ok(sign)
    }
}

/// Checks and updates the DKIM for a given email.
///
/// # Arguments
///
/// * `email` - The email address.
/// * `parsed_email` - The parsed email data.
/// * `controller_eth_addr` - The Ethereum address of the controller.
/// * `wallet_addr` - The address of the wallet.
/// * `account_salt` - The salt for the account.
///
/// # Returns
///
/// A `Result<()>`.
pub async fn check_and_update_dkim(
    body: &str,
    dkim_address: Address,
    state: Arc<StateConfig>,
) -> anyhow::Result<()> {
    // Parse the email from the raw content
    let parsed_email = ParsedEmail::new_from_raw_email(&body)
        .await
        .map_err(|e| {
            error!("Failed to parse email: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })
        .map_err(|e| anyhow!("Failed to parse email: {:?}", e))?;

    info!("Parsed email: {:?}", parsed_email);

    // Generate public key hash
    let mut public_key_n = parsed_email.public_key.clone();
    public_key_n.reverse();
    let public_key_hash = fr_to_bytes32(&public_key_hash(&public_key_n)?)?;
    let public_key_hash = FixedBytes::<32>::from(public_key_hash);
    info!("public_key_hash {:?}", public_key_hash);

    // Get email domain
    let domain = parsed_email.get_email_domain()?;
    info!("domain {:?}", domain);

    let chain = state
        .rpc
        .first()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("No rpc found"),
        ))
        .map_err(|e| anyhow!("No rpc found {:?}", e))?;
    info!("chain {:?}", chain);
    let signer: PrivateKeySigner = chain.private_key.parse().unwrap();

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect(&chain.url)
        .await
        .map_err(|e| {
            error!("Failed to connect to rpc");
            (StatusCode::FAILED_DEPENDENCY, e.to_string())
        })
        .map_err(|e| anyhow!("Failed to connect to rpc {:?}", e))?;
    info!("{:?}", provider);

    let dkim = ECDSAOwnedDKIMRegistry::new(dkim_address, provider);

    // Check if DKIM public key hash is valid
    let domain_hash = keccak256(domain.as_bytes());
    if dkim
        .isKeyHashValid(domain_hash, public_key_hash)
        .call()
        .await?
    {
        info!("public key registered");
        return Ok(());
    }

    // Get selector using regex
    let regex_pattern = r"((\r\n)|^)dkim-signature:([a-z]+=[^;]+; )+s=([0-9a-z_-]+);";
    let re = regex::Regex::new(regex_pattern).map_err(|e| anyhow!("Invalid regex: {}", e))?;

    let selector = re
        .captures(&parsed_email.canonicalized_header)
        .and_then(|caps| caps.get(4))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow!("Failed to extract selector using regex"))?;

    info!("selector {}", selector);

    // Generate IC agent and create oracle client
    let ic_agent = DkimOracleClient::gen_agent(&state.pem_path, &state.icp.ic_replica_url)?;
    info!("ic_agent {:?}", ic_agent);

    info!("icp canister id {:?}", &state.icp.dkim_canister_id);
    info!("icp replica url {:?}", &state.icp.ic_replica_url);

    let oracle_client = DkimOracleClient::new(
        &state.icp.dkim_canister_id,
        &state.icp.wallet_canister_id,
        &ic_agent,
    )
    .await?;
    info!("oracle_client {:?}", oracle_client);

    // Request signature from oracle
    let oracle_result = oracle_client.request_signature(&selector, &domain).await?;
    info!("DKIM oracle result {:?}", oracle_result);

    // Process oracle response
    let public_key_hash = FixedBytes::<32>::from_hex(&oracle_result.public_key_hash[2..])?;
    info!("public_key_hash from oracle {:?}", public_key_hash);
    let signature = Bytes::from_hex(&oracle_result.signature[2..])?;
    info!("signature {:?}", signature);

    // Set DKIM public key hash
    let pending_tx = dkim
        .setDKIMPublicKeyHash(selector.clone(), domain.clone(), public_key_hash, signature)
        .send()
        .await?;

    // Wait for the transaction to be confirmed
    let receipt = pending_tx
        .with_required_confirmations(CONFIRMATIONS)
        .get_receipt()
        .await?;

    // Format the transaction hash
    let tx_hash = receipt.transaction_hash;
    info!("DKIM registry updated {:?}", tx_hash);
    Ok(())
}
