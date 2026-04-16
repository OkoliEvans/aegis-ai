use axum::{body::Bytes, extract::State, response::Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cosmrs::proto::cosmos::{
    bank::v1beta1::{MsgMultiSend, MsgSend},
    tx::v1beta1::{TxBody, TxRaw},
};
use guardian_core::{GuardianDecision, IncomingTx};
use prost::Message;
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
        return forward_to_node(&state.config.initia_rpc, &body).await;
    }

    let tx_b64 = request
        .pointer("/params/tx")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let tx_bytes = STANDARD.decode(tx_b64).unwrap_or_default();
    let tx = parse_cosmos_tx(&tx_bytes);

    let decision = state.agent.evaluate(&tx, &tx_bytes).await;
    match decision {
        GuardianDecision::Allow => forward_to_node(&state.config.initia_rpc, &body).await,
        GuardianDecision::Warn { findings } => {
            state.notifier.fire(&tx.sender, &findings, None).await;
            forward_to_node(&state.config.initia_rpc, &body).await
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

async fn forward_to_node(rpc_url: &str, body: &[u8]) -> Json<Value> {
    let endpoint = rpc_url.trim_end_matches('/').to_string();
    let response = reqwest::Client::new()
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await;

    match response {
        Ok(response) => match response.json::<Value>().await {
            Ok(value) => Json(value),
            Err(error) => Json(json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32002,
                    "message": "Guardian failed to decode upstream RPC response",
                    "data": error.to_string(),
                }
            })),
        },
        Err(error) => Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32001,
                "message": "Guardian failed to contact upstream RPC",
                "data": error.to_string(),
            }
        })),
    }
}

fn parse_cosmos_tx(tx_bytes: &[u8]) -> IncomingTx {
    if let Some(decoded) = decode_protobuf_tx(tx_bytes) {
        return decoded;
    }

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

fn decode_protobuf_tx(tx_bytes: &[u8]) -> Option<IncomingTx> {
    let tx_raw = TxRaw::decode(tx_bytes).ok()?;
    let body = TxBody::decode(tx_raw.body_bytes.as_slice()).ok()?;
    let first_message = body.messages.first()?;

    let mut tx = IncomingTx {
        sender: "unknown_sender".to_string(),
        recipient: "unknown_recipient".to_string(),
        amount: "0".to_string(),
        denom: "uinit".to_string(),
        contract_address: None,
        function_name: None,
        controller_chain: None,
        message_type: Some(first_message.type_url.clone()),
        raw_bytes: tx_bytes.to_vec(),
        timestamp: chrono::Utc::now(),
    };

    match first_message.type_url.as_str() {
        "/cosmos.bank.v1beta1.MsgSend" => {
            let message = MsgSend::decode(first_message.value.as_slice()).ok()?;
            tx.sender = message.from_address;
            tx.recipient = message.to_address;
            if let Some(coin) = message.amount.first() {
                tx.amount = coin.amount.clone();
                tx.denom = coin.denom.clone();
            }
        }
        "/cosmos.bank.v1beta1.MsgMultiSend" => {
            let message = MsgMultiSend::decode(first_message.value.as_slice()).ok()?;
            if let Some(input) = message.inputs.first() {
                tx.sender = input.address.clone();
                if let Some(coin) = input.coins.first() {
                    tx.amount = coin.amount.clone();
                    tx.denom = coin.denom.clone();
                }
            }
            if let Some(output) = message.outputs.first() {
                tx.recipient = output.address.clone();
            }
        }
        _ => {}
    }

    Some(tx)
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

#[cfg(test)]
mod tests {
    use super::{decode_protobuf_tx, default_denom};
    use cosmrs::proto::{
        cosmos::{
            bank::v1beta1::MsgSend,
            tx::v1beta1::{TxBody, TxRaw},
        },
        prost::Name,
    };
    use prost::Message;

    #[test]
    fn decodes_msg_send_transactions() {
        let msg = MsgSend {
            from_address: "init1sender".to_string(),
            to_address: "init1recipient".to_string(),
            amount: vec![cosmrs::proto::cosmos::base::v1beta1::Coin {
                denom: default_denom(),
                amount: "42".to_string(),
            }],
        };
        let any = cosmrs::proto::Any {
            type_url: MsgSend::type_url(),
            value: msg.encode_to_vec(),
        };
        let body = TxBody {
            messages: vec![any],
            memo: String::new(),
            timeout_height: 0,
            extension_options: vec![],
            non_critical_extension_options: vec![],
        };
        let tx_raw = TxRaw {
            body_bytes: body.encode_to_vec(),
            auth_info_bytes: vec![],
            signatures: vec![],
        };

        let parsed = decode_protobuf_tx(&tx_raw.encode_to_vec()).expect("tx should decode");
        assert_eq!(parsed.sender, "init1sender");
        assert_eq!(parsed.recipient, "init1recipient");
        assert_eq!(parsed.amount, "42");
        assert_eq!(parsed.denom, "uinit");
    }
}
