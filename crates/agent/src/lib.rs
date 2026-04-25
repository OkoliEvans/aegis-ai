use guardian_analyzer::{
    anomaly, approvals, contract, ica, liquidity, llm, poison, reentrancy, slippage,
};
use guardian_core::{
    models::TxPattern, GuardianConfig, GuardianDecision, GuardianPolicyClient, GuardianPolicyView,
    GuardianRepository, IncomingTx, RiskFinding, Severity,
};
use guardian_simulator::simulate;
use std::sync::Arc;
use tracing::warn;

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
        let policy_client = GuardianPolicyClient::from_config(&self.config);
        let policy = self.fetch_policy(policy_client.as_ref(), &tx.sender).await;
        let thresholds = DecisionThresholds::from_policy(policy.as_ref());
        let mut trusted_entities = self.config.known_protocols.clone();
        trusted_entities.extend(
            self.config
                .demo_approval_lab_contract_address
                .iter()
                .cloned(),
        );
        if let Some(policy) = policy.as_ref() {
            trusted_entities.extend(policy.trusted_contracts.iter().cloned());
            trusted_entities.extend(policy.trusted_recipients.iter().cloned());
        }
        if let (Some(client), Some(contract_address)) =
            (policy_client.as_ref(), tx.contract_address.as_deref())
        {
            match client.is_trusted_contract(contract_address).await {
                Ok(true) => trusted_entities.push(contract_address.to_string()),
                Ok(false) => {}
                Err(error) => warn!(
                    ?error,
                    contract_address, "failed to query trusted contract state from guardian-policy"
                ),
            }
        }
        trusted_entities.sort();
        trusted_entities.dedup();

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
        let is_risk_reducing_action = is_risk_reducing_contract_action(tx);

        if let Some(finding) = poison::check_poison(&tx.recipient, &known_addrs) {
            findings.push(finding);
        }

        if let Some(pattern) = baseline.as_ref() {
            if let Some(finding) = anomaly::detect_anomaly(tx, pattern) {
                findings.push(finding);
            }
        }

        if let Some(finding) = approvals::inspect_contract_approval(tx, &trusted_entities) {
            findings.push(finding);
        }

        if let Some(finding) = slippage::inspect_slippage(tx) {
            findings.push(finding);
        }

        if let Some(finding) = liquidity::inspect_liquidity(tx, simulation_result.as_ref()) {
            findings.push(finding);
        }

        if let Some(finding) = reentrancy::inspect_reentrancy(tx, simulation_result.as_ref()) {
            findings.push(finding);
        }

        if let Some(msg_type) = tx.message_type.as_deref() {
            if let Some(controller_chain) = tx.controller_chain.as_deref() {
                if let Some(finding) = ica::check_ica(msg_type, controller_chain, &trusted_entities)
                {
                    findings.push(finding);
                }
            }
        }

        let contract_risk = if let Some(contract_address) = tx.contract_address.as_deref() {
            contract::score_contract(
                &self.config.initia_lcd,
                self.config.initia_json_rpc.as_deref(),
                contract_address,
                current_height,
                sim_fund_destination.as_deref(),
                &trusted_entities,
                tx.function_name.as_deref(),
            )
            .await
            .ok()
        } else {
            None
        };

        if let Some(risk) = &contract_risk {
            if !is_risk_reducing_action && risk.score >= 50 {
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

            if !is_risk_reducing_action && !risk.is_verified {
                if let Some(api_key) = self.config.anthropic_api_key.as_deref() {
                    if let Some(contract_address) = tx.contract_address.as_deref() {
                        if let Ok(bytecode) = contract::fetch_module_bytecode_pub(
                            &self.config.initia_lcd,
                            self.config.initia_json_rpc.as_deref(),
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

        if !is_risk_reducing_action
            && policy
                .as_ref()
                .is_some_and(|entry| entry.auto_block_new_contracts)
            && tx.contract_address.is_some()
        {
            let contract_address = tx.contract_address.as_deref().unwrap_or_default();
            let is_trusted = trusted_entities
                .iter()
                .any(|entry| entry == contract_address);
            let is_verified = contract_risk
                .as_ref()
                .map(|risk| risk.is_verified)
                .unwrap_or(false);
            if !is_trusted && !is_verified {
                findings.push(RiskFinding {
                    module: "policy".to_string(),
                    severity: Severity::Critical,
                    weight: thresholds.block.max(85),
                    description: "User policy blocks untrusted contract interactions by default"
                        .to_string(),
                    payload: serde_json::json!({
                        "contract_address": contract_address,
                        "auto_block_new_contracts": true,
                        "warn_threshold": thresholds.warn,
                        "confirm_threshold": thresholds.confirm,
                        "block_threshold": thresholds.block,
                    }),
                });
            }
        }

        let mut fresh_approvals =
            match approvals::scan_approvals(&self.config.initia_lcd, &tx.sender).await {
                Ok(approvals) => approvals,
                Err(_) => self
                    .repository
                    .approval_records(&tx.sender)
                    .await
                    .unwrap_or_default(),
            };
        let _ = approvals::apply_contract_approval_delta(&mut fresh_approvals, tx, current_height);
        for approval in &mut fresh_approvals {
            let score = approvals::score_approval(approval, current_height, &trusted_entities);
            approval.risk_score = score;
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
        let _ = self
            .repository
            .set_approval_records(&tx.sender, fresh_approvals.clone())
            .await;

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
            if simulation.gas_estimate > 3_000_000 {
                findings.push(RiskFinding {
                    module: "simulator".to_string(),
                    severity: Severity::Medium,
                    weight: 20,
                    description: format!(
                        "Simulation gas estimate is unusually high: {}",
                        simulation.gas_estimate
                    ),
                    payload: serde_json::json!({ "gas_estimate": simulation.gas_estimate }),
                });
            }
            if simulation
                .observed_actions
                .iter()
                .any(|action| matches!(action.as_str(), "migrate" | "update_admin" | "clear_admin"))
            {
                findings.push(RiskFinding {
                    module: "wasm_admin".to_string(),
                    severity: Severity::High,
                    weight: 55,
                    description: "Simulation includes privileged Wasm admin actions".to_string(),
                    payload: serde_json::json!({
                        "observed_actions": simulation.observed_actions,
                        "touched_contracts": simulation.touched_contracts,
                    }),
                });
            }
        }

        let mut total: i32 = findings.iter().map(|finding| finding.weight).sum();

        if total < thresholds.warn {
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

        let llm_floor = (thresholds.warn + 5).max(15);
        let llm_ceiling = (thresholds.block - 10).max(llm_floor);
        if (llm_floor..=llm_ceiling).contains(&total) {
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
                    findings.push(llm::triage_finding(&assessment));
                    total = findings.iter().map(|finding| finding.weight).sum();
                }
            }
        }

        Self::classify(findings, total, thresholds)
    }

    async fn fetch_policy(
        &self,
        policy_client: Option<&GuardianPolicyClient>,
        owner: &str,
    ) -> Option<GuardianPolicyView> {
        let Some(policy_client) = policy_client else {
            return None;
        };

        match policy_client.fetch_policy(owner).await {
            Ok(policy) => policy,
            Err(error) => {
                warn!(?error, owner, "failed to query guardian-policy thresholds");
                None
            }
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

    fn classify(
        findings: Vec<RiskFinding>,
        total: i32,
        thresholds: DecisionThresholds,
    ) -> GuardianDecision {
        let auto_revoke = findings.iter().any(|finding| finding.module == "approval")
            && total >= thresholds.block;

        if total < thresholds.warn {
            GuardianDecision::Allow
        } else if total < thresholds.confirm {
            GuardianDecision::Warn { findings }
        } else if total < thresholds.block {
            GuardianDecision::Confirm { findings }
        } else {
            GuardianDecision::Block {
                findings,
                auto_revoke,
            }
        }
    }
}

fn is_risk_reducing_contract_action(tx: &IncomingTx) -> bool {
    matches!(
        tx.function_name.as_deref(),
        Some("decrease_allowance" | "revoke" | "revoke_all")
    )
}

#[derive(Debug, Clone, Copy)]
struct DecisionThresholds {
    warn: i32,
    confirm: i32,
    block: i32,
}

impl DecisionThresholds {
    fn from_policy(policy: Option<&GuardianPolicyView>) -> Self {
        let Some(policy) = policy else {
            return Self::default();
        };

        let warn = i32::from(policy.warn_threshold);
        let confirm = i32::from(policy.confirm_threshold);
        let block = i32::from(policy.block_threshold);

        if warn < confirm && confirm < block {
            Self {
                warn,
                confirm,
                block,
            }
        } else {
            Self::default()
        }
    }
}

impl Default for DecisionThresholds {
    fn default() -> Self {
        Self {
            warn: 30,
            confirm: 60,
            block: 80,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use guardian_core::{InMemoryRepository, RiskFinding, Severity};

    use super::{DecisionThresholds, GuardianAgent, GuardianConfig, GuardianDecision};

    fn sample_finding(module: &str, severity: Severity, weight: i32) -> RiskFinding {
        RiskFinding {
            module: module.to_string(),
            severity,
            weight,
            description: format!("{module} finding"),
            payload: serde_json::json!({ "module": module }),
        }
    }

    fn test_agent() -> GuardianAgent {
        GuardianAgent::new(
            GuardianConfig {
                app_host: "127.0.0.1".to_string(),
                app_port: 3000,
                database_url: None,
                initia_chain_id: Some("aegis-guard".to_string()),
                initia_lcd: "http://127.0.0.1:1".to_string(),
                initia_rpc: "http://127.0.0.1:1".to_string(),
                initia_ws: "ws://127.0.0.1:1".to_string(),
                initia_json_rpc: None,
                sepolia_json_rpc: None,
                anthropic_api_key: None,
                smtp_host: None,
                smtp_port: 587,
                smtp_username: None,
                smtp_password: None,
                smtp_from_email: None,
                smtp_from_name: None,
                known_protocols: vec![],
                guardian_policy_contract_address: None,
                guardian_policy_reporter_key: None,
                guardian_policy_keyring_backend: "test".to_string(),
                guardian_policy_cli: "minitiad".to_string(),
                demo_approval_lab_contract_address: None,
            },
            Arc::new(InMemoryRepository::default()),
        )
    }

    #[test]
    fn classify_allows_low_risk_totals() {
        let decision = GuardianAgent::classify(
            vec![sample_finding("simulator", Severity::Low, 20)],
            20,
            DecisionThresholds::default(),
        );
        assert!(matches!(decision, GuardianDecision::Allow));
    }

    #[test]
    fn classify_warns_for_mid_band_risk() {
        let decision = GuardianAgent::classify(
            vec![sample_finding("approval", Severity::Medium, 45)],
            45,
            DecisionThresholds::default(),
        );
        match decision {
            GuardianDecision::Warn { findings } => assert_eq!(findings.len(), 1),
            other => panic!("expected warn decision, got {other:?}"),
        }
    }

    #[test]
    fn classify_requires_confirmation_for_high_risk_without_block() {
        let decision = GuardianAgent::classify(
            vec![sample_finding("contract", Severity::High, 70)],
            70,
            DecisionThresholds::default(),
        );
        match decision {
            GuardianDecision::Confirm { findings } => assert_eq!(findings[0].module, "contract"),
            other => panic!("expected confirm decision, got {other:?}"),
        }
    }

    #[test]
    fn classify_blocks_and_enables_auto_revoke_for_severe_approval_risk() {
        let decision = GuardianAgent::classify(
            vec![
                sample_finding("approval", Severity::High, 55),
                sample_finding("contract", Severity::Critical, 35),
            ],
            90,
            DecisionThresholds::default(),
        );
        match decision {
            GuardianDecision::Block {
                auto_revoke,
                findings,
            } => {
                assert!(auto_revoke);
                assert_eq!(findings.len(), 2);
            }
            other => panic!("expected block decision, got {other:?}"),
        }
    }

    #[test]
    fn classify_uses_policy_thresholds_when_present() {
        let decision = GuardianAgent::classify(
            vec![sample_finding("policy", Severity::High, 48)],
            48,
            DecisionThresholds {
                warn: 20,
                confirm: 40,
                block: 70,
            },
        );
        assert!(matches!(decision, GuardianDecision::Confirm { .. }));
    }

    #[tokio::test]
    async fn evaluate_builds_baseline_for_low_risk_transactions() {
        let agent = test_agent();
        let tx = guardian_core::IncomingTx {
            sender: "init1sender".to_string(),
            recipient: "init1recipient".to_string(),
            amount: "100".to_string(),
            denom: "uinit".to_string(),
            contract_address: None,
            function_name: None,
            contract_msg: None,
            controller_chain: None,
            message_type: None,
            raw_bytes: vec![],
            timestamp: chrono::Utc::now(),
        };

        let decision = agent.evaluate(&tx, &[]).await;
        assert!(matches!(decision, GuardianDecision::Allow));

        let baseline = agent
            .repository()
            .tx_pattern(&tx.sender)
            .await
            .expect("baseline lookup should succeed");
        let baseline = baseline.expect("baseline should be created");
        assert_eq!(baseline.address, tx.sender);
        assert_eq!(baseline.avg_value_uinit, 100);
    }
}
