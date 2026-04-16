use anyhow::{Context, Result};
use guardian_core::models::ApprovalRecord;
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct MoveResource {
    #[serde(rename = "type")]
    type_name: String,
    data: serde_json::Value,
}

pub async fn scan_approvals(lcd: &str, owner: &str) -> Result<Vec<ApprovalRecord>> {
    let endpoint = format!(
        "{}/initia/move/v1/accounts/{owner}/resources",
        lcd.trim_end_matches('/')
    );
    let response = Client::new()
        .get(endpoint)
        .send()
        .await?
        .error_for_status()?;

    let payload: serde_json::Value = response.json().await?;
    let resources = payload
        .get("resources")
        .cloned()
        .map(|value| serde_json::from_value::<Vec<MoveResource>>(value))
        .transpose()
        .context("failed to parse move resources")?
        .unwrap_or_default();

    Ok(resources
        .into_iter()
        .filter(|resource| {
            let lower = resource.type_name.to_ascii_lowercase();
            lower.contains("allowance") || lower.contains("approval")
        })
        .filter_map(|resource| parse_allowance(owner, resource))
        .collect())
}

pub fn score_approval(
    approval: &ApprovalRecord,
    current_height: i64,
    known_protocols: &[String],
) -> i32 {
    let mut score = 0;

    if approval.amount == u128::MAX.to_string() {
        score += 40;
    }
    if !known_protocols
        .iter()
        .any(|protocol| protocol == &approval.spender)
    {
        score += 30;
    }

    let age_blocks = current_height.saturating_sub(approval.granted_at_height);
    if age_blocks > 432_000 {
        score += 20;
    }

    score
}

fn parse_allowance(owner: &str, resource: MoveResource) -> Option<ApprovalRecord> {
    let spender = resource
        .data
        .get("spender")
        .and_then(|value| value.as_str())
        .or_else(|| {
            resource
                .data
                .pointer("/allowance/spender")
                .and_then(|value| value.as_str())
        })?;
    let amount = resource
        .data
        .get("amount")
        .and_then(|value| value.as_str())
        .or_else(|| {
            resource
                .data
                .pointer("/allowance/amount")
                .and_then(|value| value.as_str())
        })
        .unwrap_or("0");
    let denom = resource
        .data
        .get("denom")
        .and_then(|value| value.as_str())
        .or_else(|| {
            resource
                .data
                .pointer("/allowance/denom")
                .and_then(|value| value.as_str())
        })
        .unwrap_or("unknown");
    let granted_at_height = resource
        .data
        .get("granted_at_height")
        .and_then(|value| value.as_i64())
        .or_else(|| {
            resource
                .data
                .pointer("/allowance/granted_at_height")
                .and_then(|value| value.as_i64())
        })
        .unwrap_or_default();

    Some(ApprovalRecord {
        id: Uuid::new_v4(),
        owner: owner.to_string(),
        spender: spender.to_string(),
        token_denom: denom.to_string(),
        amount: amount.to_string(),
        granted_at_height,
        revoked: false,
        risk_score: 0,
        created_at: chrono::Utc::now(),
    })
}
