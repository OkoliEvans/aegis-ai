use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone)]
pub struct TxContext {
    pub sender: String,
    pub recipient: String,
    pub is_first_interaction: bool,
    pub value_uinit: u64,
    pub contract_age_blocks: Option<i64>,
    pub is_verified: Option<bool>,
    pub function_name: Option<String>,
    pub user_baseline_avg: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeRiskAssessment {
    pub has_drain_path: bool,
    pub confidence: String,
    pub suspicious_paths: Vec<String>,
    pub recommended_action: String,
    pub reasoning: String,
}

impl BytecodeRiskAssessment {
    pub fn unknown() -> Self {
        Self {
            has_drain_path: false,
            confidence: "low".to_string(),
            suspicious_paths: Vec::new(),
            recommended_action: "warn".to_string(),
            reasoning: "Could not parse LLM response".to_string(),
        }
    }
}

pub async fn llm_assess(ctx: &TxContext, api_key: &str) -> Result<String> {
    let prompt = format!(
        r#"You are a blockchain security analyst for the Initia chain.

Transaction:
- Sender: {}
- Recipient: {} (first interaction: {})
- Value: {} uINIT
- Contract age: {}
- Verified: {}
- Function: {}
- User baseline avg: {} uINIT

Respond ONLY with JSON:
{{"risk_level":"low|medium|high|critical","primary_concern":"...","recommended_action":"allow|warn|block","reasoning":"..."}}"#,
        ctx.sender,
        ctx.recipient,
        ctx.is_first_interaction,
        ctx.value_uinit,
        ctx.contract_age_blocks
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        ctx.is_verified
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        ctx.function_name.as_deref().unwrap_or("transfer"),
        ctx.user_baseline_avg,
    );

    call_claude(&prompt, api_key, 256).await
}

pub async fn llm_analyze_bytecode(
    pseudocode: &str,
    contract_addr: &str,
    api_key: &str,
) -> Result<BytecodeRiskAssessment> {
    let prompt = format!(
        r#"You are a smart contract security auditor. Analyze this decompiled Move/EVM pseudocode for contract {}.

Identify any execution paths where user funds can be drained, frozen, or redirected.

Pseudocode:
{}

Respond ONLY with JSON:
{{
  "has_drain_path": true,
  "confidence": "low|medium|high",
  "suspicious_paths": ["..."],
  "recommended_action": "allow|warn|block",
  "reasoning": "..."
}}"#,
        contract_addr, pseudocode
    );

    let raw = call_claude(&prompt, api_key, 512).await?;
    Ok(serde_json::from_str(&raw).unwrap_or_else(|_| BytecodeRiskAssessment::unknown()))
}

async fn call_claude(prompt: &str, api_key: &str, max_tokens: u32) -> Result<String> {
    let response: serde_json::Value = Client::new()
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "messages": [{ "role": "user", "content": prompt }]
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed to decode Anthropic response")?;

    Ok(response["content"][0]["text"]
        .as_str()
        .unwrap_or("{}")
        .to_string())
}
