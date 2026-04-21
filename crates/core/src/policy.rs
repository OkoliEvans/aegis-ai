use std::collections::BTreeSet;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::warn;
use url::form_urlencoded::byte_serialize;

use crate::{GuardianConfig, RiskFinding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianPolicyView {
    pub owner: String,
    pub warn_threshold: u8,
    pub confirm_threshold: u8,
    pub block_threshold: u8,
    pub trusted_contracts: Vec<String>,
    pub trusted_recipients: Vec<String>,
    pub auto_block_new_contracts: bool,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianPolicyIncident {
    pub id: u64,
    pub owner: String,
    pub reporter: String,
    pub event_type: String,
    pub severity: String,
    pub tx_hash: Option<String>,
    pub summary: String,
    pub details_json: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianQuarantineEntry {
    pub owner: String,
    pub address: String,
    pub reason: String,
    pub risk_score: u8,
    pub quarantined_at: u64,
}

#[derive(Debug, Clone)]
pub struct GuardianPolicyClient {
    lcd: String,
    rpc: String,
    contract_address: String,
    chain_id: Option<String>,
    reporter_key: Option<String>,
    keyring_backend: String,
    cli_binary: String,
}

impl GuardianPolicyClient {
    pub fn from_config(config: &GuardianConfig) -> Option<Self> {
        let contract_address = config.guardian_policy_contract_address.clone()?;
        Some(Self {
            lcd: config.initia_lcd.clone(),
            rpc: config.initia_rpc.clone(),
            contract_address,
            chain_id: config.initia_chain_id.clone(),
            reporter_key: config.guardian_policy_reporter_key.clone(),
            keyring_backend: config.guardian_policy_keyring_backend.clone(),
            cli_binary: config.guardian_policy_cli.clone(),
        })
    }

    pub fn contract_address(&self) -> &str {
        &self.contract_address
    }

    pub fn reporting_enabled(&self) -> bool {
        self.chain_id.is_some() && self.reporter_key.is_some()
    }

    pub async fn fetch_policy(&self, owner: &str) -> Result<Option<GuardianPolicyView>> {
        let response: SmartQueryEnvelope<PolicyResponse> = self
            .smart_query(serde_json::json!({
                "get_policy": {
                    "owner": owner
                }
            }))
            .await?;

        Ok(response.data.policy)
    }

    pub async fn is_trusted_contract(&self, address: &str) -> Result<bool> {
        let response: SmartQueryEnvelope<TrustedContractResponse> = self
            .smart_query(serde_json::json!({
                "is_trusted_contract": {
                    "address": address
                }
            }))
            .await?;

        Ok(response.data.trusted)
    }

    pub async fn list_incidents(
        &self,
        owner: &str,
        limit: u32,
    ) -> Result<Vec<GuardianPolicyIncident>> {
        let response: SmartQueryEnvelope<IncidentListResponse> = self
            .smart_query(serde_json::json!({
                "list_incidents": {
                    "owner": owner,
                    "limit": limit
                }
            }))
            .await?;

        Ok(response.data.incidents)
    }

    pub async fn list_quarantined(
        &self,
        owner: &str,
        limit: u32,
    ) -> Result<Vec<GuardianQuarantineEntry>> {
        let response: SmartQueryEnvelope<QuarantineListResponse> = self
            .smart_query(serde_json::json!({
                "list_quarantined": {
                    "owner": owner,
                    "limit": limit
                }
            }))
            .await?;

        Ok(response.data.entries)
    }

    pub async fn sync_findings(
        &self,
        owner: &str,
        findings: &[RiskFinding],
        tx_hash: Option<&str>,
    ) -> Result<()> {
        if findings.is_empty() || !self.reporting_enabled() {
            return Ok(());
        }

        let primary = findings
            .iter()
            .max_by_key(|finding| finding.weight)
            .context("cannot sync empty findings to policy contract")?;

        let summary = build_incident_summary(findings);
        self.execute(serde_json::json!({
            "record_incident": {
                "owner": owner,
                "event_type": primary.module,
                "severity": primary.severity.as_str(),
                "tx_hash": tx_hash,
                "summary": summary,
                "details_json": serde_json::to_string(&serde_json::json!({
                    "findings": findings
                }))?,
            }
        }))
        .await?;

        for target in quarantine_targets(findings) {
            if let Err(error) = self
                .execute(serde_json::json!({
                    "quarantine_address": {
                        "owner": owner,
                        "address": target.address,
                        "reason": target.reason,
                        "risk_score": target.risk_score,
                    }
                }))
                .await
            {
                warn!(
                    ?error,
                    owner,
                    address = %target.address,
                    "failed to sync quarantine target to guardian-policy"
                );
            }
        }

        Ok(())
    }

    async fn smart_query<T>(&self, msg: serde_json::Value) -> Result<SmartQueryEnvelope<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let query = serde_json::to_vec(&msg)?;
        let encoded = STANDARD.encode(query);
        let encoded = byte_serialize(encoded.as_bytes()).collect::<String>();
        let endpoint = format!(
            "{}/cosmwasm/wasm/v1/contract/{}/smart/{}",
            self.lcd.trim_end_matches('/'),
            self.contract_address,
            encoded
        );

        Client::new()
            .get(endpoint)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("failed to decode guardian policy query response")
    }

    async fn execute(&self, msg: serde_json::Value) -> Result<()> {
        let reporter_key = self
            .reporter_key
            .as_deref()
            .context("GUARDIAN_POLICY_REPORTER_KEY must be set to write policy state")?;
        let chain_id = self
            .chain_id
            .as_deref()
            .context("INITIA_CHAIN_ID must be set to write policy state")?;

        let output = Command::new(&self.cli_binary)
            .arg("tx")
            .arg("wasm")
            .arg("execute")
            .arg(&self.contract_address)
            .arg(msg.to_string())
            .arg("--from")
            .arg(reporter_key)
            .arg("--keyring-backend")
            .arg(&self.keyring_backend)
            .arg("--chain-id")
            .arg(chain_id)
            .arg("--node")
            .arg(&self.rpc)
            .arg("--gas")
            .arg("auto")
            .arg("--gas-adjustment")
            .arg("1.4")
            .arg("--broadcast-mode")
            .arg("sync")
            .arg("--yes")
            .arg("-o")
            .arg("json")
            .output()
            .await
            .with_context(|| format!("failed to spawn {}", self.cli_binary))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            anyhow::bail!(
                "guardian-policy execute failed with status {}: {}{}{}",
                output.status,
                stderr.trim(),
                if stderr.trim().is_empty() || stdout.trim().is_empty() {
                    ""
                } else {
                    " | "
                },
                stdout.trim()
            );
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct SmartQueryEnvelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct PolicyResponse {
    policy: Option<GuardianPolicyView>,
}

#[derive(Debug, Deserialize)]
struct IncidentListResponse {
    incidents: Vec<GuardianPolicyIncident>,
}

#[derive(Debug, Deserialize)]
struct QuarantineListResponse {
    entries: Vec<GuardianQuarantineEntry>,
}

#[derive(Debug, Deserialize)]
struct TrustedContractResponse {
    trusted: bool,
}

#[derive(Debug)]
struct QuarantineTarget {
    address: String,
    reason: String,
    risk_score: u8,
}

fn build_incident_summary(findings: &[RiskFinding]) -> String {
    if let Some(single) = findings.first().filter(|_| findings.len() == 1) {
        return single.description.clone();
    }

    let modules = findings
        .iter()
        .map(|finding| finding.module.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    format!(
        "Guardian published {} findings across {}",
        findings.len(),
        modules.join(", ")
    )
}

fn quarantine_targets(findings: &[RiskFinding]) -> Vec<QuarantineTarget> {
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();

    for finding in findings {
        let Some(address) = extract_quarantine_address(finding) else {
            continue;
        };
        if !address.starts_with("init") || !seen.insert(address.clone()) {
            continue;
        }

        targets.push(QuarantineTarget {
            address,
            reason: finding.description.clone(),
            risk_score: finding.weight.clamp(0, 100) as u8,
        });
    }

    targets
}

fn extract_quarantine_address(finding: &RiskFinding) -> Option<String> {
    for key in ["suspicious", "sender", "contract_address"] {
        let value = finding
            .payload
            .get(key)
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty());
        if value.is_some() {
            return value.map(ToOwned::to_owned);
        }
    }

    None
}
