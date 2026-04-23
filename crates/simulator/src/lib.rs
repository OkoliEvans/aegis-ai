use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use guardian_core::{BalanceDelta, SimulationResult, SwapExecutionInsight};
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
            .as_ref()
            .map(|result| extract_deltas(&result.events))
            .unwrap_or_default(),
        observed_actions: response
            .result
            .as_ref()
            .map(|result| extract_actions(&result.events))
            .unwrap_or_default(),
        touched_contracts: response
            .result
            .as_ref()
            .map(|result| extract_contracts(&result.events))
            .unwrap_or_default(),
        swap_execution: response
            .result
            .as_ref()
            .and_then(|result| extract_swap_execution(&result.events)),
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

fn extract_actions(events: &[serde_json::Value]) -> Vec<String> {
    let mut actions = Vec::new();
    for event in events {
        if let Some(event_type) = event.get("type").and_then(|value| value.as_str()) {
            if matches!(
                event_type,
                "wasm" | "instantiate" | "store_code" | "update_admin" | "clear_admin" | "migrate"
            ) {
                actions.push(event_type.to_string());
            }
        }

        let attributes = event
            .get("attributes")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        if let Some(action) = find_attribute(&attributes, "action")
            .or_else(|| find_attribute(&attributes, "_contract_address"))
        {
            actions.push(action);
        }
    }
    actions.sort();
    actions.dedup();
    actions
}

fn extract_contracts(events: &[serde_json::Value]) -> Vec<String> {
    let mut contracts = Vec::new();
    for event in events {
        let attributes = event
            .get("attributes")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        for key in ["_contract_address", "contract_address"] {
            if let Some(address) = find_attribute(&attributes, key) {
                contracts.push(address);
            }
        }
    }
    contracts.sort();
    contracts.dedup();
    contracts
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

fn extract_swap_execution(events: &[serde_json::Value]) -> Option<SwapExecutionInsight> {
    let mut offered_amount = None;
    let mut return_amount = None;
    let mut spread_amount = None;
    let mut commission_amount = None;
    let mut offer_pool = None;
    let mut ask_pool = None;

    for event in events {
        let attributes = event
            .get("attributes")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();

        offered_amount = offered_amount.or_else(|| {
            find_amount_attribute(
                &attributes,
                &["offer_amount", "offer_asset_amount", "amount_in"],
            )
        });
        return_amount = return_amount.or_else(|| {
            find_amount_attribute(&attributes, &["return_amount", "ask_amount", "amount_out"])
        });
        spread_amount = spread_amount.or_else(|| {
            find_amount_attribute(&attributes, &["spread_amount", "price_impact_amount"])
        });
        commission_amount = commission_amount
            .or_else(|| find_amount_attribute(&attributes, &["commission_amount", "fee_amount"]));
        offer_pool = offer_pool.or_else(|| {
            find_amount_attribute(&attributes, &["offer_pool", "input_pool", "reserve_in"])
        });
        ask_pool = ask_pool.or_else(|| {
            find_amount_attribute(&attributes, &["ask_pool", "output_pool", "reserve_out"])
        });
    }

    let insight = SwapExecutionInsight {
        offered_amount,
        return_amount,
        spread_amount,
        commission_amount,
        offer_pool,
        ask_pool,
    };

    if insight.offered_amount.is_some()
        || insight.return_amount.is_some()
        || insight.spread_amount.is_some()
        || insight.offer_pool.is_some()
        || insight.ask_pool.is_some()
    {
        Some(insight)
    } else {
        None
    }
}

fn find_amount_attribute(attributes: &[serde_json::Value], keys: &[&str]) -> Option<i128> {
    keys.iter().find_map(|key| {
        find_attribute(attributes, key).and_then(|value| parse_token_amount(&value))
    })
}

fn parse_token_amount(value: &str) -> Option<i128> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(parsed) = trimmed.parse::<i128>() {
        return Some(parsed);
    }

    let split_index = trimmed.find(|character: char| !character.is_ascii_digit())?;
    trimmed[..split_index].parse::<i128>().ok()
}
