use guardian_core::{models::WatchedAddress, ChainEvent, RiskFinding, Severity};
use serde_json::Value;
use std::collections::HashSet;

const DEFAULT_UINIT_DUST_THRESHOLD: u128 = 100_000;

pub fn detect_dust_events(
    event: &ChainEvent,
    watched_addresses: &[WatchedAddress],
    known_protocols: &[String],
) -> Vec<(String, RiskFinding)> {
    let parsed = match parse_transfer_event(&event.raw) {
        Some(parsed) => parsed,
        None => return Vec::new(),
    };

    let watched_by_address = watched_addresses
        .iter()
        .map(|entry| (entry.address.as_str(), entry))
        .collect::<std::collections::HashMap<_, _>>();

    let trusted: HashSet<&str> = known_protocols.iter().map(String::as_str).collect();
    let mut findings = Vec::new();

    for transfer in parsed.transfers {
        let Some(watched) = watched_by_address.get(transfer.recipient.as_str()) else {
            continue;
        };

        if transfer.sender == transfer.recipient {
            continue;
        }
        if trusted.contains(transfer.sender.as_str()) {
            continue;
        }

        let threshold = threshold_for_denom(&transfer.denom);
        if transfer.amount > threshold {
            continue;
        }

        let finding = RiskFinding {
            module: "dust".to_string(),
            severity: Severity::Medium,
            weight: 30,
            description: format!(
                "Detected a tiny unsolicited transfer of {} {} from {} to watched address {}",
                transfer.amount,
                transfer.denom,
                shorten(&transfer.sender),
                shorten(&transfer.recipient)
            ),
            payload: serde_json::json!({
                "tx_hash": event.tx_hash,
                "sender": transfer.sender,
                "recipient": transfer.recipient,
                "amount": transfer.amount.to_string(),
                "denom": transfer.denom,
                "watched_label": watched.label,
                "watched_owner": watched.owner_address,
                "height": event.height,
                "classification": "dust_attack_candidate",
            }),
        };

        findings.push((watched.owner_address.clone(), finding));
    }

    findings
}

fn threshold_for_denom(denom: &str) -> u128 {
    if denom == "uinit" || denom == "umin" {
        DEFAULT_UINIT_DUST_THRESHOLD
    } else {
        1
    }
}

fn shorten(address: &str) -> String {
    if address.len() <= 14 {
        address.to_string()
    } else {
        format!("{}...{}", &address[..8], &address[address.len() - 6..])
    }
}

#[derive(Debug)]
struct ParsedTransferEvent {
    transfers: Vec<Transfer>,
}

#[derive(Debug)]
struct Transfer {
    sender: String,
    recipient: String,
    amount: u128,
    denom: String,
}

fn parse_transfer_event(raw: &str) -> Option<ParsedTransferEvent> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let events = value.get("result")?.get("events")?;
    let senders = event_values(events, "message.sender");
    let recipients = event_values(events, "transfer.recipient");
    let amounts = event_values(events, "transfer.amount");

    if recipients.is_empty() || amounts.is_empty() {
        return None;
    }

    let default_sender = senders.first().cloned().unwrap_or_default();
    let transfers = recipients
        .into_iter()
        .zip(amounts)
        .filter_map(|(recipient, amount)| {
            let (parsed_amount, denom) = parse_coin(&amount)?;
            Some(Transfer {
                sender: default_sender.clone(),
                recipient,
                amount: parsed_amount,
                denom,
            })
        })
        .collect::<Vec<_>>();

    if transfers.is_empty() {
        None
    } else {
        Some(ParsedTransferEvent { transfers })
    }
}

fn event_values(events: &Value, key: &str) -> Vec<String> {
    events
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_coin(input: &str) -> Option<(u128, String)> {
    let trimmed = input.trim();
    let split_index = trimmed.find(|ch: char| !ch.is_ascii_digit())?;
    let (amount, denom) = trimmed.split_at(split_index);
    Some((amount.parse().ok()?, denom.to_string()))
}

#[cfg(test)]
mod tests {
    use super::detect_dust_events;
    use chrono::Utc;
    use guardian_core::{models::WatchedAddress, ChainEvent};
    use uuid::Uuid;

    fn watched(address: &str, owner: &str) -> WatchedAddress {
        WatchedAddress {
            id: Uuid::new_v4(),
            address: address.to_string(),
            label: Some("Primary".to_string()),
            owner_address: owner.to_string(),
            is_simulation_target: false,
            is_poisoned: false,
            risk_score: 0,
            first_seen: Utc::now(),
            last_activity: Utc::now(),
        }
    }

    #[test]
    fn flags_unsolicited_tiny_uinit_transfer_to_watched_wallet() {
        let event = ChainEvent {
            tx_hash: "abc".to_string(),
            sender: "init1attacker99999999999999999999999999bad".to_string(),
            height: 7,
            raw: serde_json::json!({
                "result": {
                    "events": {
                        "message.sender": ["init1attacker99999999999999999999999999bad"],
                        "transfer.recipient": ["init1watched00000000000000000000000000safe"],
                        "transfer.amount": ["500uinit"]
                    }
                }
            })
            .to_string(),
        };

        let findings = detect_dust_events(
            &event,
            &[watched(
                "init1watched00000000000000000000000000safe",
                "init1watched00000000000000000000000000safe",
            )],
            &[],
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].0, "init1watched00000000000000000000000000safe");
        assert_eq!(findings[0].1.module, "dust");
    }

    #[test]
    fn ignores_transfers_above_dust_threshold() {
        let event = ChainEvent {
            tx_hash: "abc".to_string(),
            sender: "init1attacker99999999999999999999999999bad".to_string(),
            height: 7,
            raw: serde_json::json!({
                "result": {
                    "events": {
                        "message.sender": ["init1attacker99999999999999999999999999bad"],
                        "transfer.recipient": ["init1watched00000000000000000000000000safe"],
                        "transfer.amount": ["150000uinit"]
                    }
                }
            })
            .to_string(),
        };

        let findings = detect_dust_events(
            &event,
            &[watched(
                "init1watched00000000000000000000000000safe",
                "init1watched00000000000000000000000000safe",
            )],
            &[],
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_known_protocol_senders() {
        let event = ChainEvent {
            tx_hash: "abc".to_string(),
            sender: "init1protocol00000000000000000000000000dex".to_string(),
            height: 7,
            raw: serde_json::json!({
                "result": {
                    "events": {
                        "message.sender": ["init1protocol00000000000000000000000000dex"],
                        "transfer.recipient": ["init1watched00000000000000000000000000safe"],
                        "transfer.amount": ["1uinit"]
                    }
                }
            })
            .to_string(),
        };

        let findings = detect_dust_events(
            &event,
            &[watched(
                "init1watched00000000000000000000000000safe",
                "init1watched00000000000000000000000000safe",
            )],
            &["init1protocol00000000000000000000000000dex".to_string()],
        );

        assert!(findings.is_empty());
    }
}
