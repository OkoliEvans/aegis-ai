use guardian_core::{IncomingTx, RiskFinding, Severity, SimulationResult};
use serde_json::Value;

const REENTRANCY_HINTS: &[&str] = &[
    "reenter",
    "reentrancy",
    "callback",
    "recursive",
    "hook",
    "execute_attack",
    "drain_then_call",
];

pub fn inspect_reentrancy(
    tx: &IncomingTx,
    simulation: Option<&SimulationResult>,
) -> Option<RiskFinding> {
    let mut signals = Vec::new();

    if let Some(function_name) = tx.function_name.as_deref() {
        if contains_hint(function_name) {
            signals.push(format!(
                "function `{function_name}` matches a reentrancy hint"
            ));
        }
    }

    if let Some(msg) = tx.contract_msg.as_ref() {
        let message_hits = collect_hint_paths(msg);
        if !message_hits.is_empty() {
            signals.extend(
                message_hits
                    .into_iter()
                    .map(|path| format!("execute payload references `{path}`")),
            );
        }
    }

    if let Some(simulation) = simulation {
        for action in &simulation.observed_actions {
            if contains_hint(action) {
                signals.push(format!("simulation observed suspicious action `{action}`"));
            }
        }

        if let Some(reason) = simulation.fail_reason.as_deref() {
            if contains_hint(reason) {
                signals.push("simulation failure reason references reentrant behavior".to_string());
            }
        }
    }

    if signals.is_empty() {
        return None;
    }

    let mut weight = 55;
    if tx.function_name.as_deref().is_some_and(contains_hint) {
        weight += 20;
    }
    if tx
        .contract_msg
        .as_ref()
        .is_some_and(|msg| !collect_hint_paths(msg).is_empty())
    {
        weight += 15;
    }
    if simulation.is_some_and(|result| {
        result
            .observed_actions
            .iter()
            .any(|action| contains_hint(action))
            || result
                .fail_reason
                .as_deref()
                .map(contains_hint)
                .unwrap_or(false)
    }) {
        weight += 15;
    }

    let severity = if weight >= 80 {
        Severity::Critical
    } else {
        Severity::High
    };

    Some(RiskFinding {
        module: "reentrancy".to_string(),
        severity,
        weight: weight.min(95),
        description: "Contract call matches reentrancy or callback-drain execution patterns"
            .to_string(),
        payload: serde_json::json!({
            "contract_address": tx.contract_address,
            "function_name": tx.function_name,
            "signals": signals,
        }),
    })
}

fn contains_hint(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    REENTRANCY_HINTS.iter().any(|hint| lower.contains(hint))
}

fn collect_hint_paths(value: &Value) -> Vec<String> {
    let mut matches = Vec::new();
    collect_hint_paths_inner(value, "$", &mut matches);
    matches.sort();
    matches.dedup();
    matches
}

fn collect_hint_paths_inner(value: &Value, path: &str, matches: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next_path = format!("{path}.{key}");
                if contains_hint(key) {
                    matches.push(next_path.clone());
                }
                collect_hint_paths_inner(child, &next_path, matches);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let next_path = format!("{path}[{index}]");
                collect_hint_paths_inner(child, &next_path, matches);
            }
        }
        Value::String(content) => {
            if contains_hint(content) {
                matches.push(path.to_string());
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use guardian_core::IncomingTx;

    use super::inspect_reentrancy;

    fn sample_tx() -> IncomingTx {
        IncomingTx {
            sender: "init1sender".to_string(),
            recipient: "init1contract".to_string(),
            amount: "0".to_string(),
            denom: "uinit".to_string(),
            contract_address: Some("init1contract".to_string()),
            function_name: Some("execute_attack".to_string()),
            contract_msg: Some(serde_json::json!({
                "execute_attack": {
                    "callback": "reenter_vault"
                }
            })),
            controller_chain: None,
            message_type: None,
            raw_bytes: vec![],
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn flags_suspicious_reentrancy_patterns() {
        let finding = inspect_reentrancy(&sample_tx(), None).expect("finding expected");
        assert_eq!(finding.module, "reentrancy");
        assert!(finding.weight >= 80);
    }

    #[test]
    fn ignores_normal_contract_calls() {
        let mut tx = sample_tx();
        tx.function_name = Some("swap".to_string());
        tx.contract_msg = Some(serde_json::json!({ "swap": { "offer_asset": "uinit" } }));

        assert!(inspect_reentrancy(&tx, None).is_none());
    }
}
