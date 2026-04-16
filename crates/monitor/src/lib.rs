use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use guardian_core::ChainEvent;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, warn};

pub async fn stream_events(ws_url: &str, tx: mpsc::Sender<ChainEvent>) -> Result<()> {
    let (mut ws, _) = connect_async(ws_url)
        .await
        .with_context(|| format!("failed to connect to websocket endpoint {ws_url}"))?;

    let subscription = json!({
        "jsonrpc": "2.0",
        "method": "subscribe",
        "id": 1,
        "params": { "query": "tm.event='Tx'" }
    });
    ws.send(Message::Text(subscription.to_string().into()))
        .await?;

    while let Some(message) = ws.next().await {
        match message {
            Ok(Message::Text(text)) => {
                if let Ok(event) = parse_chain_event(&text) {
                    if tx.send(event).await.is_err() {
                        warn!("event channel dropped; stopping monitor");
                        break;
                    }
                } else {
                    debug!("ignoring websocket message that did not parse as ChainEvent");
                }
            }
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

fn parse_chain_event(raw: &str) -> Result<ChainEvent> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let events = &value["result"]["events"];

    let tx_hash = first_event_value(events, "tx.hash");
    let sender = first_event_value(events, "message.sender");
    let height = first_event_value(events, "tx.height")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_default();

    Ok(ChainEvent {
        tx_hash: tx_hash.unwrap_or_default(),
        sender: sender.unwrap_or_default(),
        height,
        raw: raw.to_string(),
    })
}

fn first_event_value(events: &serde_json::Value, key: &str) -> Option<String> {
    events
        .get(key)
        .and_then(|value| value.as_array())
        .and_then(|values| values.first())
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}
