use guardian_core::{RiskFinding, Severity};

pub fn check_ica(
    msg_type: &str,
    controller_chain: &str,
    safe_controllers: &[String],
) -> Option<RiskFinding> {
    if !msg_type.contains("interchain_account") && !msg_type.contains("RegisterInterchainAccount") {
        return None;
    }

    if safe_controllers
        .iter()
        .any(|chain| chain == controller_chain)
    {
        return None;
    }

    Some(RiskFinding {
        module: "ica".to_string(),
        severity: Severity::High,
        weight: 75,
        description: format!(
            "Unknown chain '{controller_chain}' is requesting Interchain Account control over your address"
        ),
        payload: serde_json::json!({
            "controller_chain": controller_chain,
            "msg_type": msg_type,
            "warning": "Cross-chain account control should be explicitly verified",
        }),
    })
}
