use guardian_core::{IncomingTx, RiskFinding, Severity};

use crate::swap;

// Inferred from mainstream router defaults and warnings: <=1% is typically routine,
// 1-3% is elevated, 3-5% is high, and >5% is treated as unacceptable.
const WARN_SLIPPAGE: f64 = 0.01;
const HIGH_SLIPPAGE: f64 = 0.03;
const CRITICAL_SLIPPAGE: f64 = 0.05;

pub fn inspect_slippage(tx: &IncomingTx) -> Option<RiskFinding> {
    if !swap::looks_like_swap(tx) {
        return None;
    }

    let (path, tolerance) = swap::extract_slippage_tolerance(tx)?;
    if tolerance <= WARN_SLIPPAGE {
        return None;
    }

    let (severity, weight, classification) = if tolerance > CRITICAL_SLIPPAGE {
        (Severity::Critical, 85, "unacceptable")
    } else if tolerance > HIGH_SLIPPAGE {
        (Severity::High, 65, "high")
    } else {
        (Severity::Medium, 35, "elevated")
    };

    Some(RiskFinding {
        module: "slippage".to_string(),
        severity,
        weight,
        description: format!(
            "Swap allows {:.2}% slippage, which is {} for routine execution",
            tolerance * 100.0,
            classification
        ),
        payload: serde_json::json!({
            "slippage_tolerance_ratio": tolerance,
            "slippage_tolerance_percent": tolerance * 100.0,
            "detected_field": path,
            "function_name": tx.function_name,
            "contract_address": tx.contract_address,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::inspect_slippage;
    use guardian_core::IncomingTx;

    fn sample_tx(max_spread: &str) -> IncomingTx {
        IncomingTx {
            sender: "init1sender".to_string(),
            recipient: "init1swap".to_string(),
            amount: "1000000".to_string(),
            denom: "uinit".to_string(),
            contract_address: Some("init1swap".to_string()),
            function_name: Some("swap".to_string()),
            contract_msg: Some(serde_json::json!({
                "swap": {
                    "offer_asset": {
                        "amount": "1000000",
                        "info": { "native_token": { "denom": "uinit" } }
                    },
                    "max_spread": max_spread,
                }
            })),
            controller_chain: None,
            message_type: Some("/cosmwasm.wasm.v1.MsgExecuteContract".to_string()),
            raw_bytes: vec![],
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn ignores_low_slippage_tolerance() {
        assert!(inspect_slippage(&sample_tx("0.005")).is_none());
    }

    #[test]
    fn flags_high_slippage_tolerance() {
        let finding = inspect_slippage(&sample_tx("0.07")).expect("finding expected");
        assert_eq!(finding.module, "slippage");
        assert_eq!(finding.severity.as_str(), "critical");
        assert!(finding.description.contains("7.00%"));
    }
}
