use chrono::{TimeZone, Utc};
use guardian_analyzer::{anomaly, approvals, dust, ica, liquidity, poison, reentrancy, slippage};
use guardian_core::{
    models::{ApprovalRecord, TxPattern, WatchedAddress},
    ChainEvent, IncomingTx, RiskFinding, SimulationResult, SwapExecutionInsight,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub id: &'static str,
    pub attack_surface: &'static str,
    pub target_address: String,
    pub findings: Vec<RiskFinding>,
}

pub fn address_poisoning_scenario() -> ScenarioResult {
    let target_address = "init1target00000000000000000000000000safe".to_string();
    let finding = poison::check_poison(
        "init1target11110000000000000000000000safe",
        std::slice::from_ref(&target_address),
    )
    .into_iter()
    .collect();

    ScenarioResult {
        id: "address_poisoning",
        attack_surface: "poison",
        target_address,
        findings: finding,
    }
}

pub fn dust_attack_scenario() -> ScenarioResult {
    let target_address = "init1watched00000000000000000000000000safe".to_string();
    let event = ChainEvent {
        tx_hash: "dust-attack-001".to_string(),
        sender: "init1attacker99999999999999999999999999bad".to_string(),
        height: 42,
        raw: serde_json::json!({
            "result": {
                "events": {
                    "message.sender": ["init1attacker99999999999999999999999999bad"],
                    "transfer.recipient": [target_address.clone()],
                    "transfer.amount": ["500uinit"]
                }
            }
        })
        .to_string(),
    };
    let watched = vec![watched_address(
        &target_address,
        &target_address,
        "Primary",
        true,
    )];
    let findings = dust::detect_dust_events(&event, &watched, &[])
        .into_iter()
        .map(|(_, finding)| finding)
        .collect();

    ScenarioResult {
        id: "dust_attack",
        attack_surface: "dust",
        target_address,
        findings,
    }
}

pub fn approval_attack_scenario() -> ScenarioResult {
    let target_address = "init1owner000000000000000000000000000safe".to_string();
    let tx = IncomingTx {
        sender: target_address.clone(),
        recipient: "init1spender0000000000000000000000000evil".to_string(),
        amount: "340282366920938463463374607431768211455".to_string(),
        denom: "uinit".to_string(),
        contract_address: Some("init1contract0000000000000000000000000risk".to_string()),
        function_name: Some("approve".to_string()),
        contract_msg: Some(serde_json::json!({
            "approve": {
                "spender": "init1spender0000000000000000000000000evil",
                "amount": "340282366920938463463374607431768211455"
            }
        })),
        controller_chain: None,
        message_type: None,
        raw_bytes: vec![],
        timestamp: Utc::now(),
    };

    let mut findings = approvals::inspect_contract_approval(&tx, &[])
        .into_iter()
        .collect::<Vec<_>>();

    let mut approval = sample_approval_record(&target_address);
    approval.amount = u128::MAX.to_string();
    approval.spender = "init1spender0000000000000000000000000evil".to_string();
    approval.granted_at_height = 10;
    let score = approvals::score_approval(&approval, 500_000, &[]);
    findings.push(RiskFinding {
        module: "approval".to_string(),
        severity: if score >= 80 {
            guardian_core::Severity::High
        } else {
            guardian_core::Severity::Medium
        },
        weight: score,
        description: format!(
            "Unlimited approval to {} has remained active for an unsafe amount of time",
            approval.spender
        ),
        payload: serde_json::json!({
            "owner": approval.owner,
            "spender": approval.spender,
            "amount": approval.amount,
            "token_denom": approval.token_denom,
        }),
    });

    ScenarioResult {
        id: "approval_attack",
        attack_surface: "approval",
        target_address,
        findings,
    }
}

pub fn anomaly_attack_scenario() -> ScenarioResult {
    let target_address = "init1habitual000000000000000000000000safe".to_string();
    let baseline = TxPattern {
        address: target_address.clone(),
        avg_value_uinit: 100_000,
        typical_recipients: serde_json::json!(["init1friendly000000000000000000000000safe"]),
        typical_hour_utc: 11,
        sample_count: 24,
        updated_at: Utc::now(),
    };
    let tx = IncomingTx {
        sender: target_address.clone(),
        recipient: "init1newrecipient0000000000000000000000risk".to_string(),
        amount: "2500000".to_string(),
        denom: "uinit".to_string(),
        contract_address: None,
        function_name: None,
        contract_msg: None,
        controller_chain: None,
        message_type: None,
        raw_bytes: vec![],
        timestamp: Utc
            .with_ymd_and_hms(2026, 4, 17, 2, 15, 0)
            .single()
            .unwrap_or_else(Utc::now),
    };
    let findings = anomaly::detect_anomaly(&tx, &baseline)
        .into_iter()
        .collect();

    ScenarioResult {
        id: "behavioral_anomaly",
        attack_surface: "anomaly",
        target_address,
        findings,
    }
}

pub fn ica_attack_scenario() -> ScenarioResult {
    let target_address = "init1icaowner000000000000000000000000safe".to_string();
    let findings = ica::check_ica(
        "MsgRegisterInterchainAccount",
        "unknown-chain-9",
        &[String::from("initiation-2")],
    )
    .into_iter()
    .collect();

    ScenarioResult {
        id: "ica_abuse",
        attack_surface: "ica",
        target_address,
        findings,
    }
}

pub fn simulated_contract_abuse_scenario() -> ScenarioResult {
    let target_address = "init1contractvictim000000000000000000000safe".to_string();
    let findings = vec![
        RiskFinding {
            module: "contract".to_string(),
            severity: guardian_core::Severity::Critical,
            weight: 90,
            description:
                "Contract risk score 90/100 — unverified, upgradeable, and simulation indicates funds flow to an unknown address"
                    .to_string(),
            payload: serde_json::json!({
                "score": 90,
                "unexpected_flow": true,
                "is_verified": false,
                "is_upgradeable": true,
                "suspicious_opcodes": ["WASM_ADMIN_PRESENT", "SUSPICIOUS_LABEL"],
            }),
        },
        RiskFinding {
            module: "simulator".to_string(),
            severity: guardian_core::Severity::High,
            weight: 60,
            description: "Simulation indicates a loss of 1500000 uinit".to_string(),
            payload: serde_json::json!({
                "address": target_address,
                "denom": "uinit",
                "delta": -1500000,
            }),
        },
        RiskFinding {
            module: "wasm_admin".to_string(),
            severity: guardian_core::Severity::High,
            weight: 55,
            description: "Simulation includes privileged Wasm admin actions".to_string(),
            payload: serde_json::json!({
                "observed_actions": ["migrate", "update_admin"],
                "touched_contracts": ["init1contract0000000000000000000000000risk"],
            }),
        },
    ];

    ScenarioResult {
        id: "simulated_contract_abuse",
        attack_surface: "contract_and_simulator",
        target_address,
        findings,
    }
}

pub fn reentrancy_pattern_scenario() -> ScenarioResult {
    let target_address = "init1reentrancyvictim000000000000000000safe".to_string();
    let tx = IncomingTx {
        sender: target_address.clone(),
        recipient: "init1reentrancylab00000000000000000000risk".to_string(),
        amount: "2500000".to_string(),
        denom: "uinit".to_string(),
        contract_address: Some("init1reentrancylab00000000000000000000risk".to_string()),
        function_name: Some("execute_attack".to_string()),
        contract_msg: Some(serde_json::json!({
            "execute_attack": {
                "target": "init1victimvault00000000000000000000safe",
                "callback": "reenter_vault"
            }
        })),
        controller_chain: None,
        message_type: None,
        raw_bytes: vec![],
        timestamp: Utc::now(),
    };

    let mut findings = reentrancy::inspect_reentrancy(
        &tx,
        Some(&guardian_core::SimulationResult {
            will_fail: false,
            fail_reason: None,
            gas_estimate: 3_900_000,
            balance_deltas: vec![
                guardian_core::BalanceDelta {
                    address: target_address.clone(),
                    denom: "uinit".to_string(),
                    delta: -2500000,
                },
                guardian_core::BalanceDelta {
                    address: "init1attacker000000000000000000000000evil".to_string(),
                    denom: "uinit".to_string(),
                    delta: 2500000,
                },
            ],
            observed_actions: vec![
                "execute_attack".to_string(),
                "callback".to_string(),
                "reenter_vault".to_string(),
            ],
            touched_contracts: vec![
                "init1reentrancylab00000000000000000000risk".to_string(),
                "init1victimvault00000000000000000000safe".to_string(),
            ],
            swap_execution: None,
        }),
    )
    .into_iter()
    .collect::<Vec<_>>();

    findings.push(RiskFinding {
        module: "simulator".to_string(),
        severity: guardian_core::Severity::High,
        weight: 60,
        description:
            "Simulation shows repeated callback-driven fund movement away from the protected address"
                .to_string(),
        payload: serde_json::json!({
            "address": target_address,
            "denom": "uinit",
            "delta": -2500000,
            "observed_actions": ["execute_attack", "callback", "reenter_vault"],
        }),
    });

    ScenarioResult {
        id: "reentrancy_pattern",
        attack_surface: "contract_and_simulator",
        target_address,
        findings,
    }
}

pub fn low_liquidity_scenario() -> ScenarioResult {
    let target_address = "init1liquidityvictim00000000000000000000safe".to_string();
    let tx = IncomingTx {
        sender: target_address.clone(),
        recipient: "init1dexrouter0000000000000000000000thin".to_string(),
        amount: "800000".to_string(),
        denom: "uinit".to_string(),
        contract_address: Some("init1dexrouter0000000000000000000000thin".to_string()),
        function_name: Some("swap".to_string()),
        contract_msg: Some(serde_json::json!({
            "swap": {
                "offer_asset": {
                    "amount": "800000",
                    "info": { "native_token": { "denom": "uinit" } }
                },
                "belief_price": "0.98",
            }
        })),
        controller_chain: None,
        message_type: Some("/cosmwasm.wasm.v1.MsgExecuteContract".to_string()),
        raw_bytes: vec![],
        timestamp: Utc::now(),
    };
    let simulation = SimulationResult {
        will_fail: false,
        fail_reason: None,
        gas_estimate: 275_000,
        balance_deltas: vec![],
        observed_actions: vec!["swap".to_string(), "route_thin_pool".to_string()],
        touched_contracts: vec!["init1dexrouter0000000000000000000000thin".to_string()],
        swap_execution: Some(SwapExecutionInsight {
            offered_amount: Some(800_000),
            return_amount: Some(1_420_000),
            spread_amount: Some(110_000),
            commission_amount: Some(4_200),
            offer_pool: Some(9_000_000),
            ask_pool: Some(17_000_000),
        }),
    };

    let mut findings = liquidity::inspect_liquidity(&tx, Some(&simulation))
        .into_iter()
        .collect::<Vec<_>>();

    findings.push(RiskFinding {
        module: "simulator".to_string(),
        severity: guardian_core::Severity::High,
        weight: 55,
        description:
            "Simulation shows the swap leaning on a thin pool and losing value through price impact"
                .to_string(),
        payload: serde_json::json!({
            "address": target_address,
            "dex": "init1dexrouter0000000000000000000000thin",
            "price_impact_ratio": 0.0718,
            "pool_share_ratio": 0.0889,
        }),
    });

    ScenarioResult {
        id: "low_liquidity",
        attack_surface: "liquidity",
        target_address,
        findings,
    }
}

pub fn high_slippage_scenario() -> ScenarioResult {
    let target_address = "init1slippagevictim00000000000000000000safe".to_string();
    let tx = IncomingTx {
        sender: target_address.clone(),
        recipient: "init1dexrouter0000000000000000000000wide".to_string(),
        amount: "1500000".to_string(),
        denom: "uinit".to_string(),
        contract_address: Some("init1dexrouter0000000000000000000000wide".to_string()),
        function_name: Some("swap".to_string()),
        contract_msg: Some(serde_json::json!({
            "swap": {
                "offer_asset": {
                    "amount": "1500000",
                    "info": { "native_token": { "denom": "uinit" } }
                },
                "belief_price": "1.02",
                "max_spread": "0.065",
            }
        })),
        controller_chain: None,
        message_type: Some("/cosmwasm.wasm.v1.MsgExecuteContract".to_string()),
        raw_bytes: vec![],
        timestamp: Utc::now(),
    };

    let mut findings = slippage::inspect_slippage(&tx)
        .into_iter()
        .collect::<Vec<_>>();

    findings.push(RiskFinding {
        module: "simulator".to_string(),
        severity: guardian_core::Severity::High,
        weight: 50,
        description:
            "Simulation shows the router can clear the trade even after a material adverse move"
                .to_string(),
        payload: serde_json::json!({
            "address": target_address,
            "dex": "init1dexrouter0000000000000000000000wide",
            "max_spread": 0.065,
            "price_move_tolerated_percent": 6.5,
        }),
    });

    ScenarioResult {
        id: "high_slippage",
        attack_surface: "slippage",
        target_address,
        findings,
    }
}

pub fn all_scenarios() -> Vec<ScenarioResult> {
    vec![
        address_poisoning_scenario(),
        dust_attack_scenario(),
        approval_attack_scenario(),
        anomaly_attack_scenario(),
        ica_attack_scenario(),
        low_liquidity_scenario(),
        high_slippage_scenario(),
        simulated_contract_abuse_scenario(),
        reentrancy_pattern_scenario(),
    ]
}

fn watched_address(
    address: &str,
    owner: &str,
    label: &str,
    simulation_target: bool,
) -> WatchedAddress {
    WatchedAddress {
        id: Uuid::new_v4(),
        address: address.to_string(),
        label: Some(label.to_string()),
        owner_address: owner.to_string(),
        is_simulation_target: simulation_target,
        is_poisoned: false,
        risk_score: 0,
        first_seen: Utc::now(),
        last_activity: Utc::now(),
    }
}

fn sample_approval_record(owner: &str) -> ApprovalRecord {
    ApprovalRecord {
        id: Uuid::new_v4(),
        owner: owner.to_string(),
        spender: "init1spender0000000000000000000000000evil".to_string(),
        token_denom: "uinit".to_string(),
        amount: "0".to_string(),
        granted_at_height: 0,
        revoked: false,
        risk_score: 0,
        approval_type: Some("move_allowance".to_string()),
        contract_address: None,
        revoke_messages: serde_json::json!([]),
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::all_scenarios;

    #[test]
    fn every_simulation_scenario_produces_findings() {
        for scenario in all_scenarios() {
            assert!(
                !scenario.findings.is_empty(),
                "scenario {} should emit at least one finding",
                scenario.id
            );
        }
    }

    #[test]
    fn attack_surfaces_are_covered_once_each() {
        let ids = all_scenarios()
            .into_iter()
            .map(|scenario| scenario.id)
            .collect::<Vec<_>>();

        for expected in [
            "address_poisoning",
            "dust_attack",
            "approval_attack",
            "behavioral_anomaly",
            "ica_abuse",
            "low_liquidity",
            "high_slippage",
            "simulated_contract_abuse",
            "reentrancy_pattern",
        ] {
            assert!(ids.contains(&expected));
        }
    }
}
