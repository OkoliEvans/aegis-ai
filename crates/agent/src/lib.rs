use guardian_analyzer::{anomaly, approvals, contract, ica, llm, poison};
use guardian_core::{
    models::TxPattern, GuardianConfig, GuardianDecision, GuardianRepository, IncomingTx,
    RiskFinding, Severity,
};
use guardian_simulator::simulate;
use std::sync::Arc;

pub struct GuardianAgent {
    config: GuardianConfig,
    repository: Arc<dyn GuardianRepository>,
}

impl GuardianAgent {
    pub fn new(config: GuardianConfig, repository: Arc<dyn GuardianRepository>) -> Self {
        Self { config, repository }
    }

    pub fn repository(&self) -> &Arc<dyn GuardianRepository> {
        &self.repository
    }

    pub async fn evaluate(&self, tx: &IncomingTx, raw_bytes: &[u8]) -> GuardianDecision {
        let known_addrs = self
            .repository
            .known_addresses(&tx.sender)
            .await
            .unwrap_or_default();
        let baseline = self.repository.tx_pattern(&tx.sender).await.ok().flatten();
        let current_height = self.current_height().await;

        let simulation_result = simulate(&self.config.initia_lcd, raw_bytes).await.ok();
        let sim_fund_destination = simulation_result
            .as_ref()
            .and_then(|result| {
                result
                    .balance_deltas
                    .iter()
                    .find(|delta| delta.delta > 0 && delta.address != tx.sender)
            })
            .map(|delta| delta.address.clone());

        let mut findings = Vec::new();

        if let Some(finding) = poison::check_poison(&tx.recipient, &known_addrs) {
            findings.push(finding);
        }

        if let Some(pattern) = baseline.as_ref() {
            if let Some(finding) = anomaly::detect_anomaly(tx, pattern) {
                findings.push(finding);
            }
        }

        if let Some(msg_type) = tx.message_type.as_deref() {
            if let Some(controller_chain) = tx.controller_chain.as_deref() {
                if let Some(finding) =
                    ica::check_ica(msg_type, controller_chain, &self.config.known_protocols)
                {
                    findings.push(finding);
                }
            }
        }

        let contract_risk = if let Some(contract_address) = tx.contract_address.as_deref() {
            contract::score_contract(
                &self.config.initia_lcd,
                contract_address,
                current_height,
                sim_fund_destination.as_deref(),
                &self.config.known_protocols,
            )
            .await
            .ok()
        } else {
            None
        };

        if let Some(risk) = &contract_risk {
            if risk.score >= 50 {
                findings.push(RiskFinding {
                    module: "contract".to_string(),
                    severity: if risk.score >= 80 {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    weight: risk.score,
                    description: contract_summary(risk),
                    payload: serde_json::to_value(risk).unwrap_or_else(|_| serde_json::json!({})),
                });
            }

            if !risk.is_verified {
                if let Some(api_key) = self.config.anthropic_api_key.as_deref() {
                    if let Some(contract_address) = tx.contract_address.as_deref() {
                        if let Ok(bytecode) = contract::fetch_module_bytecode_pub(
                            &self.config.initia_lcd,
                            contract_address,
                        )
                        .await
                        {
                            let pseudocode = contract::decompile_to_pseudocode(&bytecode);
                            if let Ok(assessment) =
                                llm::llm_analyze_bytecode(&pseudocode, contract_address, api_key)
                                    .await
                            {
                                if assessment.has_drain_path {
                                    findings.push(RiskFinding {
                                        module: "contract_llm".to_string(),
                                        severity: Severity::Critical,
                                        weight: match assessment.confidence.as_str() {
                                            "high" => 80,
                                            "medium" => 50,
                                            _ => 25,
                                        },
                                        description: format!(
                                            "LLM bytecode analysis found a potential drain path: {}",
                                            assessment.reasoning
                                        ),
                                        payload: serde_json::to_value(assessment)
                                            .unwrap_or_else(|_| serde_json::json!({})),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let fresh_approvals =
            match approvals::scan_approvals(&self.config.initia_lcd, &tx.sender).await {
                Ok(approvals) => approvals,
                Err(_) => self
                    .repository
                    .approval_records(&tx.sender)
                    .await
                    .unwrap_or_default(),
            };
        let _ = self
            .repository
            .set_approval_records(&tx.sender, fresh_approvals.clone())
            .await;
        for approval in &fresh_approvals {
            let score =
                approvals::score_approval(approval, current_height, &self.config.known_protocols);
            if score >= 50 {
                findings.push(RiskFinding {
                    module: "approval".to_string(),
                    severity: if score >= 80 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    weight: score,
                    description: format!(
                        "Approval to {} for {} {} is still active",
                        approval.spender, approval.amount, approval.token_denom
                    ),
                    payload: serde_json::json!({
                        "owner": approval.owner,
                        "spender": approval.spender,
                        "amount": approval.amount,
                        "token_denom": approval.token_denom,
                    }),
                });
            }
        }

        if let Some(simulation) = simulation_result {
            if simulation.will_fail {
                findings.push(RiskFinding {
                    module: "simulator".to_string(),
                    severity: Severity::High,
                    weight: 60,
                    description: format!(
                        "Transaction is expected to revert: {}",
                        simulation
                            .fail_reason
                            .unwrap_or_else(|| "unknown reason".to_string())
                    ),
                    payload: serde_json::json!({}),
                });
            }
            for delta in simulation.balance_deltas {
                if delta.delta < -1_000_000 {
                    findings.push(RiskFinding {
                        module: "simulator".to_string(),
                        severity: Severity::Medium,
                        weight: 20,
                        description: format!(
                            "Simulation indicates a loss of {} {}",
                            delta.delta.abs(),
                            delta.denom
                        ),
                        payload: serde_json::to_value(delta)
                            .unwrap_or_else(|_| serde_json::json!({})),
                    });
                }
            }
        }

        let mut total: i32 = findings.iter().map(|finding| finding.weight).sum();

        if matches!(total, 0..=29) {
            if let Some(mut stored_baseline) = baseline.clone() {
                anomaly::update_baseline(&mut stored_baseline, tx);
                let _ = self.repository.upsert_tx_pattern(stored_baseline).await;
            } else {
                let _ = self
                    .repository
                    .upsert_tx_pattern(TxPattern {
                        address: tx.sender.clone(),
                        avg_value_uinit: tx.amount.parse::<i64>().unwrap_or_default(),
                        typical_recipients: serde_json::json!([tx.recipient.clone()]),
                        typical_hour_utc: tx.hour_utc(),
                        sample_count: 1,
                        updated_at: chrono::Utc::now(),
                    })
                    .await;
            }
        }

        if (35..=65).contains(&total) {
            if let Some(api_key) = self.config.anthropic_api_key.as_deref() {
                let context = llm::TxContext {
                    sender: tx.sender.clone(),
                    recipient: tx.recipient.clone(),
                    is_first_interaction: baseline
                        .as_ref()
                        .map(|pattern| {
                            serde_json::from_value::<Vec<String>>(
                                pattern.typical_recipients.clone(),
                            )
                            .unwrap_or_default()
                            .iter()
                            .all(|recipient| recipient != &tx.recipient)
                        })
                        .unwrap_or(true),
                    value_uinit: tx.amount.parse::<u64>().unwrap_or_default(),
                    contract_age_blocks: contract_risk.as_ref().map(|risk| risk.age_blocks),
                    is_verified: contract_risk.as_ref().map(|risk| risk.is_verified),
                    function_name: tx.function_name.clone(),
                    user_baseline_avg: baseline
                        .as_ref()
                        .map(|pattern| pattern.avg_value_uinit)
                        .unwrap_or_default(),
                };
                if let Ok(assessment) = llm::llm_assess(&context, api_key).await {
                    findings.push(RiskFinding {
                        module: "llm_triage".to_string(),
                        severity: Severity::Medium,
                        weight: 10,
                        description: "LLM triage consulted for ambiguous risk band".to_string(),
                        payload: serde_json::json!({ "assessment": assessment }),
                    });
                    total = findings.iter().map(|finding| finding.weight).sum();
                }
            }
        }

        let auto_revoke = findings.iter().any(|finding| finding.module == "approval") && total > 80;

        match total {
            0..=29 => GuardianDecision::Allow,
            30..=59 => GuardianDecision::Warn { findings },
            60..=79 => GuardianDecision::Confirm { findings },
            _ => GuardianDecision::Block {
                findings,
                auto_revoke,
            },
        }
    }

    async fn current_height(&self) -> i64 {
        let endpoint = format!("{}/status", self.config.initia_rpc.trim_end_matches('/'));
        match reqwest::Client::new().get(endpoint).send().await {
            Ok(response) => {
                let body: serde_json::Value = match response.json().await {
                    Ok(body) => body,
                    Err(_) => return 0,
                };
                body.pointer("/result/sync_info/latest_block_height")
                    .and_then(|value| value.as_str())
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or_default()
            }
            Err(_) => 0,
        }
    }
}

fn contract_summary(risk: &guardian_analyzer::contract::ContractRisk) -> String {
    let mut parts = vec![format!(
        "Contract risk score {}/100; age {} blocks; verified: {}",
        risk.score, risk.age_blocks, risk.is_verified
    )];
    if risk.unexpected_flow {
        parts.push("simulation shows funds flowing to an unknown destination".to_string());
    }
    if !risk.suspicious_opcodes.is_empty() {
        parts.push(format!(
            "dangerous opcode signals: {}",
            risk.suspicious_opcodes.join(", ")
        ));
    }
    if risk.is_upgradeable {
        parts.push("contract appears upgradeable".to_string());
    }
    parts.join("; ")
}
