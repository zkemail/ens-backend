use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StateConfig {
    pub smtp_url: String,
    pub prover: ProverConfig,
    pub rpc: Vec<ChainConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProverConfig {
    pub url: String,
    pub api_key: String,
    pub blueprint_id: String,
    pub circuit_cpp_download_url: String,
    pub zkey_download_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChainConfig {
    pub name: String,
    pub chain_id: u64,
    pub url: String,
    pub private_key: String,
}

impl StateConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: StateConfig = serde_json::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_config_from_file() {
        // Test loading config from config.sample.json
        let config = StateConfig::from_file("config.sample.json");
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.smtp_url, "http://localhost:3000/api/sendEmail");
        assert_eq!(config.prover.url, "https://prover.zk.email/api/prove");
        assert_eq!(config.prover.api_key, "your-api-key-here");
        assert_eq!(config.prover.blueprint_id, "your-blueprint-id-here");
        assert_eq!(config.rpc.len(), 1);

        let chain = &config.rpc[0];
        assert_eq!(chain.name, "default");
        assert_eq!(chain.chain_id, 11155111);
        assert_eq!(
            chain.url,
            "https://eth-sepolia.g.alchemy.com/v2/your-alchemy-key-here"
        );
        assert_eq!(chain.private_key, "your-private-key-here");
    }

    #[test]
    fn test_state_config_deserialization() {
        let json = r#"{
            "smtpUrl": "http://localhost:3000/api/sendEmail",
            "prover": {
                "url": "https://prover.zk.email/api/prove",
                "apiKey": "test-api-key",
                "blueprintId": "test-blueprint-id",
                "circuitCppDownloadUrl": "https://storage.googleapis.com/circom-ether-email-auth/reveal/circuit_cpp.zip",
                "zkeyDownloadUrl": "https://storage.googleapis.com/circom-ether-email-auth/reveal/circuit_zkey.zip"
            },
            "rpc":
                [
                    {
                        "name": "test-chain",
                        "chainId": 12345,
                        "url": "https://test-rpc.com",
                        "privateKey": "0x1234567890abcdef"
                    }
                ]
        }"#;

        let config: StateConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.smtp_url, "http://localhost:3000/api/sendEmail");
        assert_eq!(config.prover.api_key, "test-api-key");
        assert_eq!(config.prover.blueprint_id, "test-blueprint-id");
        assert_eq!(config.rpc.len(), 1);
        assert_eq!(config.rpc[0].name, "test-chain");
        assert_eq!(config.rpc[0].chain_id, 12345);
    }

    #[test]
    fn test_invalid_json_handling() {
        let invalid_json = "{ invalid json }";
        let result: Result<StateConfig, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
}
