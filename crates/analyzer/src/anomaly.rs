use guardian_core::{models::TxPattern, IncomingTx, RiskFinding, Severity};

pub fn detect_anomaly(tx: &IncomingTx, baseline: &TxPattern) -> Option<RiskFinding> {
    if baseline.sample_count < 10 {
        return None;
    }

    let mut score = 0;
    let mut flags = Vec::new();
    let value = tx.amount.parse::<i64>().unwrap_or_default();

    if value > baseline.avg_value_uinit.saturating_mul(10) {
        score += 35;
        flags.push(format!(
            "Value {}x above baseline",
            value / baseline.avg_value_uinit.max(1)
        ));
    }

    let known_recipients: Vec<String> =
        serde_json::from_value(baseline.typical_recipients.clone()).unwrap_or_default();
    if !known_recipients.contains(&tx.recipient) {
        score += 25;
        flags.push("First-time recipient".to_string());
    }

    if (tx.hour_utc() - baseline.typical_hour_utc).abs() > 8 {
        score += 15;
        flags.push("Unusual time of day".to_string());
    }

    if score < 40 {
        return None;
    }

    Some(RiskFinding {
        module: "anomaly".to_string(),
        severity: if score >= 70 {
            Severity::High
        } else {
            Severity::Medium
        },
        weight: score,
        description: flags.join("; "),
        payload: serde_json::json!({
            "flags": flags,
            "tx_value": value,
            "baseline_avg": baseline.avg_value_uinit,
        }),
    })
}

pub fn update_baseline(pattern: &mut TxPattern, tx: &IncomingTx) {
    let value = tx.amount.parse::<i64>().unwrap_or_default();
    let sample_count = i64::from(pattern.sample_count.max(0));

    pattern.avg_value_uinit =
        (pattern.avg_value_uinit.saturating_mul(sample_count) + value) / (sample_count + 1);
    pattern.sample_count += 1;

    let mut recipients: Vec<String> =
        serde_json::from_value(pattern.typical_recipients.clone()).unwrap_or_default();
    if !recipients.contains(&tx.recipient) {
        recipients.push(tx.recipient.clone());
        if recipients.len() > 50 {
            let _ = recipients.remove(0);
        }
    }
    pattern.typical_recipients =
        serde_json::to_value(recipients).unwrap_or_else(|_| serde_json::json!([]));
    pattern.typical_hour_utc = tx.hour_utc();
    pattern.updated_at = chrono::Utc::now();
}
