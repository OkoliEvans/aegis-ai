use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use guardian_core::{BalanceDelta, SimulationResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct SimulateRequest {
    tx_bytes: String,
}

#[derive(Debug, Deserialize)]
struct SimulateResponse {
    #[serde(default)]
    gas_info: Option<GasInfo>,
    #[serde(default)]
    result: Option<TxResult>,
}

#[derive(Debug, Deserialize)]
struct GasInfo {
    #[serde(default)]
    gas_used: String,
}

#[derive(Debug, Deserialize)]
struct TxResult {
    #[serde(default)]
    log: String,
    #[serde(default)]
    events: Vec<serde_json::Value>,
}

pub async fn simulate(lcd: &str, tx_bytes: &[u8]) -> Result<SimulationResult> {
    let endpoint = format!("{}/cosmos/tx/v1beta1/simulate", lcd.trim_end_matches('/'));
    let response: SimulateResponse = Client::new()
        .post(endpoint)
        .json(&SimulateRequest {
            tx_bytes: STANDARD.encode(tx_bytes),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed to decode simulate response")?;

    let log = response
        .result
        .as_ref()
        .map(|result| result.log.clone())
        .unwrap_or_default();

    Ok(SimulationResult {
        will_fail: looks_like_failure(&log),
        fail_reason: extract_revert_reason(&log),
        gas_estimate: response
            .gas_info
            .and_then(|gas| gas.gas_used.parse::<u64>().ok())
            .unwrap_or_default(),
        balance_deltas: response
            .result
            .map(|result| extract_deltas(&result.events))
            .unwrap_or_default(),
    })
}

fn looks_like_failure(log: &str) -> bool {
    let lower = log.to_ascii_lowercase();
    lower.contains("failed") || lower.contains("error")
}

fn extract_revert_reason(log: &str) -> Option<String> {
    log.split("error:")
        .nth(1)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_deltas(events: &[serde_json::Value]) -> Vec<BalanceDelta> {
    let mut deltas = Vec::new();

    for event in events {
        let Some(event_type) = event.get("type").and_then(|value| value.as_str()) else {
            continue;
        };
        if event_type != "coin_received" && event_type != "coin_spent" {
            continue;
        }

        let attributes = event
            .get("attributes")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();

        let address = find_attribute(
            &attributes,
            if event_type == "coin_received" {
                "receiver"
            } else {
                "spender"
            },
        )
        .or_else(|| find_attribute(&attributes, "receiver"))
        .or_else(|| find_attribute(&attributes, "sender"))
        .unwrap_or_default();
        let amount_field = find_attribute(&attributes, "amount").unwrap_or_default();
        let (amount, denom) = parse_amount_and_denom(&amount_field);

        if !address.is_empty() && !denom.is_empty() {
            deltas.push(BalanceDelta {
                address,
                denom,
                delta: if event_type == "coin_spent" {
                    -amount
                } else {
                    amount
                },
            });
        }
    }

    deltas
}

fn find_attribute(attributes: &[serde_json::Value], key: &str) -> Option<String> {
    attributes.iter().find_map(|entry| {
        let entry_key = entry.get("key").and_then(|value| value.as_str())?;
        if entry_key == key {
            entry
                .get("value")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned)
        } else {
            None
        }
    })
}

fn parse_amount_and_denom(value: &str) -> (i128, String) {
    let split_index = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let amount = value[..split_index].parse::<i128>().unwrap_or_default();
    let denom = value[split_index..].to_string();
    (amount, denom)
}
