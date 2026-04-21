use anyhow::{Context, Result};
use guardian_core::{models::ApprovalRecord, IncomingTx, RiskFinding, Severity};
use reqwest::Client;
use reqwest::StatusCode;
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

    if approval.amount == u128::MAX.to_string() || approval.amount.eq_ignore_ascii_case("all") {
        score += 40;
    }
    if !known_protocols.iter().any(|protocol| {
        protocol == &approval.spender
            || approval
                .contract_address
                .as_ref()
                .is_some_and(|contract| protocol == contract)
    }) {
        score += 30;
    }
    if approval.approval_type.as_deref() == Some("cw721_all") {
        score += 20;
    }

    let age_blocks = current_height.saturating_sub(approval.granted_at_height);
    if age_blocks > 432_000 {
        score += 20;
    }

    score
}

pub fn inspect_contract_approval(
    tx: &IncomingTx,
    known_protocols: &[String],
) -> Option<RiskFinding> {
    let contract = tx.contract_address.as_deref()?;
    let msg = tx.contract_msg.as_ref()?.as_object()?;
    let (action, payload) = msg.iter().next()?;

    let (spender_field, revoke_options, base_weight) = match action.as_str() {
        "approve_all" | "set_approval_for_all" => (
            "operator",
            vec![serde_json::json!({
                "kind": "cw721",
                "execute_msg": { "revoke_all": { "operator": payload.get("operator").cloned().unwrap_or(serde_json::Value::Null) } }
            })],
            70,
        ),
        "increase_allowance" | "approve" => (
            "spender",
            vec![
                serde_json::json!({
                    "kind": "cw20",
                    "execute_msg": {
                        "decrease_allowance": {
                            "spender": payload.get("spender").cloned().unwrap_or(serde_json::Value::Null),
                            "amount": payload.get("amount").cloned().unwrap_or(serde_json::json!("0"))
                        }
                    }
                }),
                serde_json::json!({
                    "kind": "cw721",
                    "execute_msg": { "revoke": { "spender": payload.get("spender").cloned().unwrap_or(serde_json::Value::Null) } }
                }),
            ],
            55,
        ),
        _ => return None,
    };

    let spender = payload
        .get(spender_field)
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let amount = payload
        .get("amount")
        .and_then(|value| value.as_str())
        .unwrap_or("0");

    let mut weight = base_weight;
    if !known_protocols.iter().any(|protocol| protocol == spender) {
        weight += 20;
    }
    if payload.get("expires").is_none() {
        weight += 10;
    }
    if amount == u128::MAX.to_string()
        || amount
            .parse::<u128>()
            .map(|value| value > 1_000_000_000_000)
            .unwrap_or(false)
    {
        weight += 15;
    }

    Some(RiskFinding {
        module: "approval_intent".to_string(),
        severity: if weight >= 80 {
            Severity::High
        } else {
            Severity::Medium
        },
        weight,
        description: format!(
            "Contract call `{action}` grants spender/operator {spender} on {contract}"
        ),
        payload: serde_json::json!({
            "contract_address": contract,
            "action": action,
            "spender": spender,
            "amount": amount,
            "revoke_options": revoke_options,
            "interwovenkit_example": {
                "typeUrl": "/cosmwasm.wasm.v1.MsgExecuteContract",
                "contractAddress": contract,
                "sender": tx.sender,
            }
        }),
    })
}

pub fn scan_is_unavailable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<reqwest::Error>()
        .and_then(|inner| inner.status())
        .is_some_and(|status| {
            matches!(
                status,
                StatusCode::NOT_IMPLEMENTED
                    | StatusCode::METHOD_NOT_ALLOWED
                    | StatusCode::NOT_FOUND
            )
        })
}

pub fn apply_contract_approval_delta(
    approvals: &mut Vec<ApprovalRecord>,
    tx: &IncomingTx,
    current_height: i64,
) -> bool {
    match parse_contract_approval_delta(tx, current_height) {
        Some(ApprovalDelta::Grant(record)) => {
            if let Some(existing) = approvals.iter_mut().find(|entry| {
                entry.owner == record.owner
                    && entry.spender == record.spender
                    && entry.contract_address == record.contract_address
                    && entry.approval_type == record.approval_type
            }) {
                existing.token_denom = record.token_denom;
                existing.amount = record.amount;
                existing.granted_at_height = record.granted_at_height;
                existing.revoked = false;
                existing.risk_score = record.risk_score;
                existing.approval_type = record.approval_type;
                existing.contract_address = record.contract_address;
                existing.revoke_messages = record.revoke_messages;
                return true;
            }

            approvals.push(record);
            true
        }
        Some(ApprovalDelta::Revoke {
            spender,
            contract_address,
            approval_type,
        }) => {
            let before = approvals.len();
            approvals.retain(|entry| {
                !(entry.spender == spender
                    && entry.contract_address.as_deref() == Some(contract_address.as_str())
                    && approval_type
                        .as_deref()
                        .map_or(true, |kind| entry.approval_type.as_deref() == Some(kind)))
            });
            before != approvals.len()
        }
        None => false,
    }
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
        approval_type: Some("move_allowance".to_string()),
        contract_address: None,
        revoke_messages: serde_json::json!([]),
        created_at: chrono::Utc::now(),
    })
}

enum ApprovalDelta {
    Grant(ApprovalRecord),
    Revoke {
        spender: String,
        contract_address: String,
        approval_type: Option<String>,
    },
}

fn parse_contract_approval_delta(tx: &IncomingTx, current_height: i64) -> Option<ApprovalDelta> {
    let contract = tx.contract_address.as_deref()?;
    let msg = tx.contract_msg.as_ref()?.as_object()?;
    let (action, payload) = msg.iter().next()?;

    match action.as_str() {
        "approve_all" | "set_approval_for_all" => {
            let spender = payload.get("operator")?.as_str()?;
            Some(ApprovalDelta::Grant(ApprovalRecord {
                id: Uuid::new_v4(),
                owner: tx.sender.clone(),
                spender: spender.to_string(),
                token_denom: "cw721".to_string(),
                amount: "all".to_string(),
                granted_at_height: current_height,
                revoked: false,
                risk_score: 0,
                approval_type: Some("cw721_all".to_string()),
                contract_address: Some(contract.to_string()),
                revoke_messages: serde_json::json!([exec_contract_message(
                    &tx.sender,
                    contract,
                    serde_json::json!({
                        "revoke_all": {
                            "operator": spender
                        }
                    })
                )]),
                created_at: chrono::Utc::now(),
            }))
        }
        "increase_allowance" => {
            let spender = payload.get("spender")?.as_str()?;
            let amount = payload
                .get("amount")
                .and_then(|value| value.as_str())
                .unwrap_or("0");

            Some(ApprovalDelta::Grant(ApprovalRecord {
                id: Uuid::new_v4(),
                owner: tx.sender.clone(),
                spender: spender.to_string(),
                token_denom: "cw20".to_string(),
                amount: amount.to_string(),
                granted_at_height: current_height,
                revoked: false,
                risk_score: 0,
                approval_type: Some("cw20_allowance".to_string()),
                contract_address: Some(contract.to_string()),
                revoke_messages: serde_json::json!([exec_contract_message(
                    &tx.sender,
                    contract,
                    serde_json::json!({
                        "decrease_allowance": {
                            "spender": spender,
                            "amount": amount
                        }
                    })
                )]),
                created_at: chrono::Utc::now(),
            }))
        }
        "approve" => {
            let spender = payload.get("spender")?.as_str()?;
            let token_id = payload
                .get("token_id")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned);

            Some(ApprovalDelta::Grant(ApprovalRecord {
                id: Uuid::new_v4(),
                owner: tx.sender.clone(),
                spender: spender.to_string(),
                token_denom: token_id
                    .as_ref()
                    .map(|token| format!("cw721:{token}"))
                    .unwrap_or_else(|| "cw721".to_string()),
                amount: token_id
                    .as_ref()
                    .map(|token| format!("token:{token}"))
                    .unwrap_or_else(|| "1".to_string()),
                granted_at_height: current_height,
                revoked: false,
                risk_score: 0,
                approval_type: Some("cw721_token".to_string()),
                contract_address: Some(contract.to_string()),
                revoke_messages: serde_json::json!([exec_contract_message(
                    &tx.sender,
                    contract,
                    serde_json::json!({
                        "revoke": {
                            "spender": spender,
                            "token_id": token_id
                        }
                    })
                )]),
                created_at: chrono::Utc::now(),
            }))
        }
        "decrease_allowance" => Some(ApprovalDelta::Revoke {
            spender: payload.get("spender")?.as_str()?.to_string(),
            contract_address: contract.to_string(),
            approval_type: Some("cw20_allowance".to_string()),
        }),
        "revoke_all" => Some(ApprovalDelta::Revoke {
            spender: payload.get("operator")?.as_str()?.to_string(),
            contract_address: contract.to_string(),
            approval_type: Some("cw721_all".to_string()),
        }),
        "revoke" => Some(ApprovalDelta::Revoke {
            spender: payload.get("spender")?.as_str()?.to_string(),
            contract_address: contract.to_string(),
            approval_type: Some("cw721_token".to_string()),
        }),
        _ => None,
    }
}

fn exec_contract_message(
    sender: &str,
    contract: &str,
    msg_json: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "typeUrl": "/cosmwasm.wasm.v1.MsgExecuteContract",
        "value": {
            "sender": sender,
            "contract": contract,
            "msg_json": msg_json,
            "funds": []
        }
    })
}
