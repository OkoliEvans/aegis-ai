use std::{env, fs, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct GuardianConfig {
    pub app_host: String,
    pub app_port: u16,
    pub database_url: Option<String>,
    pub initia_chain_id: Option<String>,
    pub initia_lcd: String,
    pub initia_rpc: String,
    pub initia_ws: String,
    pub anthropic_api_key: Option<String>,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from_email: Option<String>,
    pub smtp_from_name: Option<String>,
    pub known_protocols: Vec<String>,
    pub guardian_policy_contract_address: Option<String>,
    pub guardian_policy_reporter_key: Option<String>,
    pub guardian_policy_keyring_backend: String,
    pub guardian_policy_cli: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalRollupMetadata {
    #[serde(default)]
    chain_id: Option<String>,
    endpoints: LocalRollupEndpoints,
    #[serde(default)]
    contracts: LocalRollupContracts,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalRollupEndpoints {
    rest: String,
    rpc: String,
    rpc_ws: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LocalRollupContracts {
    #[serde(default)]
    guardian_policy: Option<LocalRollupContract>,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalRollupContract {
    #[serde(default)]
    contract_address: Option<String>,
}

fn local_rollup_metadata_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".initia/local-rollup.json")
}

fn load_local_rollup_metadata() -> Option<LocalRollupMetadata> {
    let raw = fs::read_to_string(local_rollup_metadata_path()).ok()?;
    serde_json::from_str(&raw).ok()
}

fn env_or_fallback(name: &str, fallback: Option<&str>) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| fallback.map(ToOwned::to_owned))
}

fn default_policy_cli() -> String {
    let home = env::var("HOME").ok();
    let candidates = [
        home.as_deref()
            .map(|home| format!("{home}/go/bin/minitiad")),
        Some("/opt/homebrew/bin/minitiad".to_string()),
        Some("/usr/local/bin/minitiad".to_string()),
    ];

    candidates
        .into_iter()
        .flatten()
        .find(|path| fs::metadata(path).is_ok())
        .unwrap_or_else(|| "minitiad".to_string())
}

impl GuardianConfig {
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();
        let local_rollup = load_local_rollup_metadata();
        let local_endpoints = local_rollup.as_ref().map(|metadata| &metadata.endpoints);

        Ok(Self {
            app_host: env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            app_port: env::var("APP_PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL").ok().filter(|v| !v.is_empty()),
            initia_chain_id: env_or_fallback(
                "INITIA_CHAIN_ID",
                local_rollup
                    .as_ref()
                    .and_then(|metadata| metadata.chain_id.as_deref()),
            ),
            initia_lcd: env_or_fallback(
                "INITIA_LCD",
                local_endpoints.map(|endpoints| endpoints.rest.as_str()),
            )
            .context(
                "INITIA_LCD must be set or .initia/local-rollup.json must provide endpoints.rest",
            )?,
            initia_rpc: env_or_fallback(
                "INITIA_RPC",
                local_endpoints.map(|endpoints| endpoints.rpc.as_str()),
            )
            .unwrap_or_else(|| "https://rpc.testnet.initia.xyz".to_string()),
            initia_ws: env_or_fallback(
                "INITIA_WS",
                local_endpoints.map(|endpoints| endpoints.rpc_ws.as_str()),
            )
            .context(
                "INITIA_WS must be set or .initia/local-rollup.json must provide endpoints.rpc_ws",
            )?,
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok().filter(|v| !v.is_empty()),
            smtp_host: env::var("SMTP_HOST").ok().filter(|v| !v.is_empty()),
            smtp_port: env::var("SMTP_PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(587),
            smtp_username: env::var("SMTP_USERNAME").ok().filter(|v| !v.is_empty()),
            smtp_password: env::var("SMTP_PASSWORD").ok().filter(|v| !v.is_empty()),
            smtp_from_email: env::var("SMTP_FROM_EMAIL").ok().filter(|v| !v.is_empty()),
            smtp_from_name: env::var("SMTP_FROM_NAME").ok().filter(|v| !v.is_empty()),
            known_protocols: env::var("KNOWN_PROTOCOLS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            guardian_policy_contract_address: env_or_fallback(
                "GUARDIAN_POLICY_CONTRACT_ADDRESS",
                env_or_fallback(
                    "VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS",
                    local_rollup
                        .as_ref()
                        .and_then(|metadata| metadata.contracts.guardian_policy.as_ref())
                        .and_then(|contract| contract.contract_address.as_deref()),
                )
                .as_deref(),
            ),
            guardian_policy_reporter_key: env_or_fallback(
                "GUARDIAN_POLICY_REPORTER_KEY",
                local_rollup
                    .as_ref()
                    .and_then(|metadata| metadata.contracts.guardian_policy.as_ref())
                    .and_then(|contract| contract.contract_address.as_ref())
                    .map(|_| "gas-station"),
            ),
            guardian_policy_keyring_backend: env::var("GUARDIAN_POLICY_KEYRING_BACKEND")
                .ok()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "test".to_string()),
            guardian_policy_cli: env::var("GUARDIAN_POLICY_CLI")
                .ok()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(default_policy_cli),
        })
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        SocketAddr::from_str(&format!("{}:{}", self.app_host, self.app_port))
            .context("failed to parse APP_HOST/APP_PORT into a socket address")
    }
}
