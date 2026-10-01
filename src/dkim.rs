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

    // Selector of the DKIM-Signature the proof is built on (the one in the canonicalized
    // header). The key is registered under the From: domain (see dkim_selector).
    let (selector, signing_domain) = dkim_selector(&parsed_email.canonicalized_header)?;
    if let Some(d) = signing_domain.as_deref() {
        if !oracle_can_resolve(d, &domain, &selector) {
            info!(
                "DKIM d={} is neither {} nor its gappssmtp alias; the oracle may not find the key",
                d, domain
            );
        }
    }

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

/// `s=` of the DKIM-Signature in a canonicalized header (the last DKIM-Signature field, i.e.
/// the signature the proof is built on).
///
/// REASON: the selector used to be read with
/// `((\r\n)|^)dkim-signature:([a-z]+=[^;]+; )+s=([0-9a-z_-]+);` (copied from
/// email-tx-builder's relayer), which needs a lowercase field name (c=simple keeps
/// "DKIM-Signature"), exactly one space after every ';', no folding, and a lowercase
/// selector.
///
/// NOTE: `d=` is deliberately NOT required to equal the From: domain. The registry and the
/// circuits key on the From: domain, and the ICP DNS oracle only signs keys it finds in DNS
/// under names derived from that domain (`<s>._domainkey.<from>`, then
/// `<s>._domainkey.<from-with-dashes>.<s>.gappssmtp.com`), so delegated signers such as Google
/// Workspace (`d=...gappssmtp.com`) must pass through here; an unrelated `d=` cannot get its
/// key registered under someone else's domain because the oracle never looks at `d=`.
pub fn dkim_selector(canonicalized_header: &str) -> anyhow::Result<(String, Option<String>)> {
    // Unfold (CRLF + SP/HTAB continues a field), then split into fields.
    let unfolded = canonicalized_header
        .replace("\r\n ", " ")
        .replace("\r\n\t", "\t");
    let field = unfolded
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("dkim-signature"))
        .map(|(_, value)| value)
        .last()
        .ok_or_else(|| anyhow!("No DKIM-Signature in the canonicalized header"))?;

    let tag = |name: &str| -> Option<String> {
        field.split(';').find_map(|part| {
            let (k, v) = part.split_once('=')?;
            (k.trim() == name).then(|| v.chars().filter(|c| !c.is_whitespace()).collect())
        })
    };
    let selector = tag("s")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("DKIM-Signature has no s= tag"))?;
    Ok((selector, tag("d").map(|d| d.to_ascii_lowercase())))
}

/// Whether the ICP DNS oracle can find the key for a signature with `d=` under `from_domain`
/// (it tries `<from>` and `<from-with-dashes>.<selector>.gappssmtp.com`). Used for logging only.
fn oracle_can_resolve(signing_domain: &str, from_domain: &str, selector: &str) -> bool {
    let from = from_domain.to_ascii_lowercase();
    signing_domain == from
        || signing_domain
            == format!("{}.{}.gappssmtp.com", from.replace('.', "-"), selector.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{dkim_selector, oracle_can_resolve};

    fn sel(h: &str) -> String {
        dkim_selector(h).unwrap().0
    }

    #[test]
    fn selector_from_relaxed_header() {
        let h = "from:a@example.com\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=20230601; bh=x; b=";
        assert_eq!(sel(h), "20230601");
        assert!(oracle_can_resolve("example.com", "example.com", "20230601"));
    }

    #[test]
    fn selector_from_simple_folded_header_without_spaces() {
        let h = "From: a@example.com\r\nDKIM-Signature: v=1;a=rsa-sha256;d=Example.com;\r\n\ts=Selector1-example-com;bh=x;b=";
        assert_eq!(
            dkim_selector(h).unwrap(),
            ("Selector1-example-com".to_string(), Some("example.com".to_string()))
        );
    }

    #[test]
    fn google_workspace_gappssmtp_signature_passes_through() {
        let h = "from:a@example.com\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example-com.20230601.gappssmtp.com; s=20230601; bh=x; b=";
        let (s, d) = dkim_selector(h).unwrap();
        assert_eq!(s, "20230601");
        assert!(oracle_can_resolve(&d.unwrap(), "example.com", &s));
    }

    #[test]
    fn microsoft_365_tenant_signature_passes_through() {
        // Not resolvable by the oracle's naming, but still not blocked here: the oracle only
        // registers what DNS publishes under the From: domain.
        let h = "from:a@contoso.com\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=contoso.onmicrosoft.com; s=selector1-contoso-com; bh=x; b=";
        let (s, d) = dkim_selector(h).unwrap();
        assert_eq!(s, "selector1-contoso-com");
        assert!(!oracle_can_resolve(&d.unwrap(), "contoso.com", &s));
    }

    #[test]
    fn s_inside_another_tag_or_field_is_not_used() {
        let h = "subject:has s=evil;\r\nx-dkim-signature:v=1; d=example.com; s=wrong;\r\ndkim-signature:v=1; d=example.com; ss=no; s=right; b=";
        assert_eq!(sel(h), "right");
    }
}
