use axum::{body::Bytes, extract::State, response::Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use guardian_core::{GuardianDecision, IncomingTx};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

pub async fn proxy_handler(State(state): State<AppState>, body: Bytes) -> Json<Value> {
    let request: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    let method = request
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or_default();

    if method != "broadcast_tx_sync" && method != "broadcast_tx_async" {
        return forward_passthrough();
    }

    let tx_b64 = request
        .pointer("/params/tx")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let tx_bytes = STANDARD.decode(tx_b64).unwrap_or_default();
    let tx = parse_cosmos_tx(&tx_bytes);

    let decision = state.agent.evaluate(&tx, &tx_bytes).await;
    match decision {
        GuardianDecision::Allow => Json(json!({
            "jsonrpc": "2.0",
            "result": {
                "forwarded": true,
                "status": "allow"
            }
        })),
        GuardianDecision::Warn { findings } => {
            state.notifier.fire(&tx.sender, &findings, None).await;
            Json(json!({
                "jsonrpc": "2.0",
                "result": {
                    "forwarded": true,
                    "status": "warn",
                    "findings": findings
                }
            }))
        }
        GuardianDecision::Confirm { findings } | GuardianDecision::Block { findings, .. } => {
            state.notifier.fire(&tx.sender, &findings, None).await;
            Json(json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": "Transaction blocked by Guardian",
                    "data": {
                        "findings": findings,
                        "dashboard": format!("http://{}:{}", state.config.app_host, state.config.app_port)
                    }
                }
            }))
        }
    }
}

fn forward_passthrough() -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "result": {
            "passthrough": true
        }
    }))
}

fn parse_cosmos_tx(tx_bytes: &[u8]) -> IncomingTx {
    if let Ok(decoded) = serde_json::from_slice::<GuardianTxHint>(tx_bytes) {
        return IncomingTx {
            sender: decoded.sender,
            recipient: decoded.recipient,
            amount: decoded.amount,
            denom: decoded.denom,
            contract_address: decoded.contract_address,
            function_name: decoded.function_name,
            controller_chain: decoded.controller_chain,
            message_type: decoded.message_type,
            raw_bytes: tx_bytes.to_vec(),
            timestamp: chrono::Utc::now(),
        };
    }

    IncomingTx {
        sender: "unknown_sender".to_string(),
        recipient: "unknown_recipient".to_string(),
        amount: "0".to_string(),
        denom: "uinit".to_string(),
        contract_address: None,
        function_name: None,
        controller_chain: None,
        message_type: None,
        raw_bytes: tx_bytes.to_vec(),
        timestamp: chrono::Utc::now(),
    }
}

#[derive(Debug, Deserialize)]
struct GuardianTxHint {
    sender: String,
    recipient: String,
    amount: String,
    #[serde(default = "default_denom")]
    denom: String,
    contract_address: Option<String>,
    function_name: Option<String>,
    controller_chain: Option<String>,
    message_type: Option<String>,
}

fn default_denom() -> String {
    "uinit".to_string()
}
