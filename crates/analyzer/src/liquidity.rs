use guardian_core::{IncomingTx, RiskFinding, Severity, SimulationResult};

use crate::swap;

// Price-impact and pool-share bands intentionally mirror conservative swap-review practice:
// >1% suggests thin liquidity, >3% is high risk, and >5% is unacceptable for routine execution.
const WARN_PRICE_IMPACT: f64 = 0.01;
const HIGH_PRICE_IMPACT: f64 = 0.03;
const CRITICAL_PRICE_IMPACT: f64 = 0.05;

pub fn inspect_liquidity(
    tx: &IncomingTx,
    simulation: Option<&SimulationResult>,
) -> Option<RiskFinding> {
    if !swap::looks_like_swap(tx) {
        return None;
    }

    let execution = simulation?.swap_execution.as_ref()?;
    let offered_amount = execution
        .offered_amount
        .or_else(|| swap::extract_offer_amount(tx));

    let price_impact_ratio = execution
        .spread_amount
        .zip(execution.return_amount)
        .and_then(|(spread_amount, return_amount)| {
            let denominator = spread_amount + return_amount;
            (spread_amount > 0 && denominator > 0)
                .then_some(spread_amount as f64 / denominator as f64)
        });

    let pool_share_ratio =
        offered_amount
            .zip(execution.offer_pool)
            .and_then(|(offer_amount, offer_pool)| {
                (offer_amount > 0 && offer_pool > 0)
                    .then_some(offer_amount as f64 / offer_pool as f64)
            });

    let strongest_ratio = price_impact_ratio
        .into_iter()
        .chain(pool_share_ratio)
        .fold(0.0_f64, f64::max);

    if strongest_ratio <= WARN_PRICE_IMPACT {
        return None;
    }

    let (severity, weight, classification) = if strongest_ratio > CRITICAL_PRICE_IMPACT {
        (Severity::Critical, 85, "critically low")
    } else if strongest_ratio > HIGH_PRICE_IMPACT {
        (Severity::High, 65, "low")
    } else {
        (Severity::Medium, 35, "thin")
    };

    let mut signals = Vec::new();
    if let Some(price_impact_ratio) = price_impact_ratio {
        signals.push(format!(
            "simulation implies {:.2}% price impact from spread",
            price_impact_ratio * 100.0
        ));
    }
    if let Some(pool_share_ratio) = pool_share_ratio {
        signals.push(format!(
            "trade consumes {:.2}% of the visible input-side pool",
            pool_share_ratio * 100.0
        ));
    }

    Some(RiskFinding {
        module: "liquidity".to_string(),
        severity,
        weight,
        description: format!(
            "Swap is routing through {} liquidity and may produce unacceptable execution loss",
            classification
        ),
        payload: serde_json::json!({
            "offered_amount": offered_amount,
            "offer_pool": execution.offer_pool,
            "ask_pool": execution.ask_pool,
            "return_amount": execution.return_amount,
            "spread_amount": execution.spread_amount,
            "commission_amount": execution.commission_amount,
            "price_impact_ratio": price_impact_ratio,
            "pool_share_ratio": pool_share_ratio,
            "signals": signals,
            "function_name": tx.function_name,
            "contract_address": tx.contract_address,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::inspect_liquidity;
    use guardian_core::{IncomingTx, SimulationResult, SwapExecutionInsight};

    fn sample_tx() -> IncomingTx {
        IncomingTx {
            sender: "init1sender".to_string(),
            recipient: "init1swap".to_string(),
            amount: "500000".to_string(),
            denom: "uinit".to_string(),
            contract_address: Some("init1swap".to_string()),
            function_name: Some("swap".to_string()),
            contract_msg: Some(serde_json::json!({
                "swap": {
                    "offer_asset": {
                        "amount": "500000",
                        "info": { "native_token": { "denom": "uinit" } }
                    },
                    "belief_price": "0.98",
                }
            })),
            controller_chain: None,
            message_type: Some("/cosmwasm.wasm.v1.MsgExecuteContract".to_string()),
            raw_bytes: vec![],
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn flags_low_liquidity_from_price_impact() {
        let simulation = SimulationResult {
            will_fail: false,
            fail_reason: None,
            gas_estimate: 200_000,
            balance_deltas: vec![],
            observed_actions: vec!["swap".to_string()],
            touched_contracts: vec!["init1swap".to_string()],
            swap_execution: Some(SwapExecutionInsight {
                offered_amount: Some(500000),
                return_amount: Some(950000),
                spread_amount: Some(75000),
                commission_amount: Some(3000),
                offer_pool: Some(4000000),
                ask_pool: Some(8000000),
            }),
        };

        let finding = inspect_liquidity(&sample_tx(), Some(&simulation)).expect("finding expected");
        assert_eq!(finding.module, "liquidity");
        assert_eq!(finding.severity.as_str(), "critical");
    }

    #[test]
    fn ignores_deep_liquidity() {
        let simulation = SimulationResult {
            will_fail: false,
            fail_reason: None,
            gas_estimate: 200_000,
            balance_deltas: vec![],
            observed_actions: vec!["swap".to_string()],
            touched_contracts: vec!["init1swap".to_string()],
            swap_execution: Some(SwapExecutionInsight {
                offered_amount: Some(500000),
                return_amount: Some(995000),
                spread_amount: Some(2000),
                commission_amount: Some(3000),
                offer_pool: Some(100000000),
                ask_pool: Some(100000000),
            }),
        };

        assert!(inspect_liquidity(&sample_tx(), Some(&simulation)).is_none());
    }
}
