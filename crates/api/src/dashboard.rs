use std::convert::Infallible;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use guardian_analyzer::{contract, liquidity};
use guardian_core::{
    models::{ApprovalRecord, RegisteredUser, StoredRiskEvent, WatchedAddress},
    GuardianDecision, GuardianPolicyClient, GuardianPolicyIncident, GuardianPolicyView,
    GuardianQuarantineEntry, IncomingTx, RiskFinding, Severity, SimulationResult,
    SwapExecutionInsight,
};
use guardian_simulations::{
    address_poisoning_scenario, all_scenarios, anomaly_attack_scenario, approval_attack_scenario,
    dust_attack_scenario, high_slippage_scenario, ica_attack_scenario, low_liquidity_scenario,
    reentrancy_pattern_scenario, simulated_contract_abuse_scenario, ScenarioResult,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;
use url::form_urlencoded::byte_serialize;
use uuid::Uuid;

use crate::AppState;

type PreviewApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiErrorResponse>)>;

pub async fn sse_feed(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.notifier.subscribe();
    let stream = BroadcastStream::new(receiver)
        .filter_map(|message| async move { message.ok() })
        .map(|data| Ok(Event::default().data(data)));

    Sse::new(stream).keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
}

pub async fn list_approvals(
    State(state): State<AppState>,
    Path(owner): Path<String>,
    Query(params): Query<ListApprovalsQuery>,
) -> Result<Json<Vec<ApprovalRecord>>, axum::http::StatusCode> {
    ensure_primary_watched_address(&state, &owner).await?;

    let stored = state
        .repository
        .approval_records(&owner)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let demo_lab_approvals = load_demo_approval_lab_approvals(&state, &owner)
        .await
        .map_err(|_| axum::http::StatusCode::BAD_GATEWAY)?;
    let stored = merge_approval_records(stored, demo_lab_approvals.clone());

    if params.refresh.unwrap_or(false) {
        let approvals =
            match guardian_analyzer::approvals::scan_approvals(&state.config.initia_lcd, &owner)
                .await
            {
                Ok(approvals) => merge_approval_records(approvals, demo_lab_approvals.clone()),
                Err(error) if guardian_analyzer::approvals::scan_is_unavailable(&error) => {
                    return Ok(Json(stored));
                }
                Err(_) => return Err(axum::http::StatusCode::BAD_GATEWAY),
            };
        state
            .repository
            .set_approval_records(&owner, approvals.clone())
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(Json(approvals));
    }

    if !stored.is_empty() {
        state
            .repository
            .set_approval_records(&owner, stored.clone())
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(Json(stored));
    }

    let approvals = match guardian_analyzer::approvals::scan_approvals(
        &state.config.initia_lcd,
        &owner,
    )
    .await
    {
        Ok(approvals) => merge_approval_records(approvals, demo_lab_approvals),
        Err(error) if guardian_analyzer::approvals::scan_is_unavailable(&error) => stored,
        Err(_) => return Err(axum::http::StatusCode::BAD_GATEWAY),
    };
    state
        .repository
        .set_approval_records(&owner, approvals.clone())
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(approvals))
}

pub async fn revoke_approval_plan(
    State(state): State<AppState>,
    Json(payload): Json<RevokeApprovalPlanRequest>,
) -> Result<Json<RevokeApprovalPlanResponse>, axum::http::StatusCode> {
    let stored = state
        .repository
        .approval_records(&payload.owner)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(approval) = stored
        .iter()
        .find(|approval| approval.spender == payload.spender)
    {
        let messages = approval
            .revoke_messages
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(serde_json::from_value::<ProtoMessage>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

        if !messages.is_empty() {
            let summary = approval.contract_address.as_deref().map_or_else(
                || format!("Revoke approval granted to {}", payload.spender),
                |contract| format!("Revoke {} approval on {}", payload.spender, contract),
            );
            return Ok(Json(RevokeApprovalPlanResponse { summary, messages }));
        }
    }

    Ok(Json(RevokeApprovalPlanResponse {
        summary: format!(
            "Revoke feegrant allowance from {} to {}",
            payload.owner, payload.spender
        ),
        messages: vec![ProtoMessage {
            type_url: "/cosmos.feegrant.v1beta1.MsgRevokeAllowance".to_string(),
            value: serde_json::json!({
                "granter": payload.owner,
                "grantee": payload.spender,
            }),
        }],
    }))
}

pub async fn list_risk_events(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(params): Query<ListRiskEventsQuery>,
) -> Result<Json<Vec<StoredRiskEvent>>, axum::http::StatusCode> {
    state
        .repository
        .risk_events(&address, params.limit.unwrap_or(50).clamp(1, 200))
        .await
        .map(Json)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn list_watched_addresses(
    State(state): State<AppState>,
    Path(owner): Path<String>,
) -> Result<Json<Vec<WatchedAddress>>, axum::http::StatusCode> {
    ensure_primary_watched_address(&state, &owner).await?;

    state
        .repository
        .watched_addresses(&owner)
        .await
        .map(Json)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn get_user_profile(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<UserProfileResponse>, axum::http::StatusCode> {
    ensure_primary_watched_address(&state, &address).await?;

    let user = state
        .repository
        .user_profile(&address)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let simulation_target = state
        .repository
        .simulation_target(&address)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UserProfileResponse {
        user,
        simulation_target,
    }))
}

pub async fn get_policy_overview(
    State(state): State<AppState>,
    Path(owner): Path<String>,
) -> Result<Json<PolicyOverviewResponse>, StatusCode> {
    ensure_primary_watched_address(&state, &owner).await?;

    let Some(policy) = GuardianPolicyClient::from_config(&state.config) else {
        return Ok(Json(PolicyOverviewResponse {
            configured: false,
            contract_address: None,
            reporting_enabled: false,
            policy: None,
            incidents: Vec::new(),
            quarantined: Vec::new(),
            issues: vec![
                "Set GUARDIAN_POLICY_CONTRACT_ADDRESS to enable onchain policy state.".to_string(),
            ],
        }));
    };

    let mut issues = Vec::new();

    let policy_view = match policy.fetch_policy(&owner).await {
        Ok(view) => view,
        Err(error) => {
            issues.push(format!("Failed to load wallet policy: {error:#}"));
            None
        }
    };

    let incidents = match policy.list_incidents(&owner, 20).await {
        Ok(items) => items,
        Err(error) => {
            issues.push(format!("Failed to load onchain incidents: {error:#}"));
            Vec::new()
        }
    };

    let quarantined = match policy.list_quarantined(&owner, 20).await {
        Ok(items) => items,
        Err(error) => {
            issues.push(format!("Failed to load quarantined addresses: {error:#}"));
            Vec::new()
        }
    };

    Ok(Json(PolicyOverviewResponse {
        configured: true,
        contract_address: Some(policy.contract_address().to_string()),
        reporting_enabled: policy.reporting_enabled(),
        policy: policy_view,
        incidents,
        quarantined,
        issues,
    }))
}

pub async fn upsert_watched_address(
    State(state): State<AppState>,
    Json(payload): Json<UpsertWatchedAddressRequest>,
) -> Result<Json<WatchedAddress>, axum::http::StatusCode> {
    state
        .repository
        .upsert_watched_address(
            &payload.owner_address,
            &payload.address,
            payload.label.as_deref(),
            payload.is_simulation_target.unwrap_or(false),
        )
        .await
        .map(Json)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn register_email(
    State(state): State<AppState>,
    Json(payload): Json<RegisterEmailRequest>,
) -> Result<Json<ApiStatus>, axum::http::StatusCode> {
    state
        .repository
        .register_email(
            &payload.address,
            &payload.email_address,
            payload.email_display_name.as_deref(),
        )
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiStatus {
        status: "ok".to_string(),
    }))
}

pub async fn send_test_email(
    State(state): State<AppState>,
    Json(payload): Json<SendTestEmailRequest>,
) -> Result<Json<ApiStatus>, axum::http::StatusCode> {
    let finding = RiskFinding {
        module: "email_test".to_string(),
        severity: Severity::High,
        weight: 75,
        description: "Guardian generated this test alert to verify your email notification setup."
            .to_string(),
        payload: serde_json::json!({
            "kind": "email_test",
            "source": "manual",
        }),
    };

    state
        .notifier
        .send_test_email_alert(&payload.address, &[finding])
        .await;

    Ok(Json(ApiStatus {
        status: "ok".to_string(),
    }))
}

pub async fn run_simulation(
    State(state): State<AppState>,
    Json(payload): Json<RunSimulationRequest>,
) -> Result<Json<RunSimulationResponse>, StatusCode> {
    let simulation_target = state
        .repository
        .simulation_target(&payload.address)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let scenario_id = payload
        .scenario_id
        .as_deref()
        .unwrap_or("simulated_contract_abuse");

    let mut scenario = select_scenario(scenario_id).ok_or(StatusCode::BAD_REQUEST)?;
    if let Some(target) = simulation_target.as_ref() {
        retarget_scenario(&mut scenario, &target.address);
    }

    let tx_tag = format!("simulation:{}", scenario.id);
    state
        .notifier
        .notify_simulation_report(
            &payload.address,
            &scenario.findings,
            Some(tx_tag.as_str()),
            scenario.id,
            scenario.attack_surface,
        )
        .await;

    Ok(Json(RunSimulationResponse {
        scenario_id: scenario.id.to_string(),
        attack_surface: scenario.attack_surface.to_string(),
        target_address: scenario.target_address,
        findings: scenario.findings,
        available_scenarios: all_scenarios()
            .into_iter()
            .map(|entry| entry.id.to_string())
            .collect(),
        ran_at: chrono::Utc::now(),
    }))
}

pub async fn preview_risk_lab_contract(
    State(state): State<AppState>,
    Json(payload): Json<PreviewRiskLabRequest>,
) -> PreviewApiResult<PreviewRiskLabResponse> {
    let contract_address = payload.contract_address.trim();
    if contract_address.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Contract address is required for analysis.",
        ));
    }
    validate_analysis_network(payload.analysis_network, contract_address)
        .map_err(|(status, message)| api_error(status, message))?;

    if payload
        .analysis_mode
        .unwrap_or(PreviewAnalysisMode::Inspect)
        == PreviewAnalysisMode::Inspect
    {
        let (findings, inspection) =
            inspect_contract_findings(&state, contract_address, None, payload.analysis_network)
                .await
                .map_err(|(status, message)| api_error(status, message))?;

        return Ok(Json(PreviewRiskLabResponse {
            contract_address: contract_address.to_string(),
            decision: classify_preview_findings(findings),
            execute_message: serde_json::json!({
                "inspect_contract": {
                    "target": contract_address,
                    "mode": "read_only"
                }
            }),
            inspection: Some(inspection),
        }));
    }

    let execute_message = serde_json::json!({
        "execute_attack": {
            "callback": "reenter_vault",
            "note": "Safe demo payload for Guardian's reentrancy detector"
        }
    });

    let tx = IncomingTx {
        sender: payload.address.clone(),
        recipient: contract_address.to_string(),
        amount: payload.amount.unwrap_or_else(|| "2500000".to_string()),
        denom: payload.denom.unwrap_or_else(|| "umin".to_string()),
        contract_address: Some(contract_address.to_string()),
        function_name: Some("execute_attack".to_string()),
        contract_msg: Some(execute_message.clone()),
        controller_chain: None,
        message_type: Some("/cosmwasm.wasm.v1.MsgExecuteContract".to_string()),
        raw_bytes: vec![],
        timestamp: chrono::Utc::now(),
    };

    let decision = state.agent.evaluate(&tx, &[]).await;

    Ok(Json(PreviewRiskLabResponse {
        contract_address: contract_address.to_string(),
        decision,
        execute_message,
        inspection: None,
    }))
}

pub async fn preview_liquidity_contract(
    State(state): State<AppState>,
    Json(payload): Json<PreviewRiskLabRequest>,
) -> PreviewApiResult<PreviewRiskLabResponse> {
    let contract_address = payload.contract_address.trim();
    if contract_address.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Contract address is required for liquidity analysis.",
        ));
    }
    validate_analysis_network(payload.analysis_network, contract_address)
        .map_err(|(status, message)| api_error(status, message))?;

    if payload
        .analysis_mode
        .unwrap_or(PreviewAnalysisMode::Inspect)
        == PreviewAnalysisMode::Inspect
    {
        let (findings, inspection) = inspect_contract_findings(
            &state,
            contract_address,
            Some("swap"),
            payload.analysis_network,
        )
        .await
        .map_err(|(status, message)| api_error(status, message))?;

        return Ok(Json(PreviewRiskLabResponse {
            contract_address: contract_address.to_string(),
            decision: classify_preview_findings(findings),
            execute_message: serde_json::json!({
                "inspect_contract": {
                    "target": contract_address,
                    "mode": "read_only"
                }
            }),
            inspection: Some(inspection),
        }));
    }

    let execute_message = serde_json::json!({
        "swap": {
            "offer_asset": {
                "amount": payload.amount.clone().unwrap_or_else(|| "1200000".to_string()),
                "info": { "native_token": { "denom": payload.denom.clone().unwrap_or_else(|| "umin".to_string()) } }
            },
            "belief_price": "0.98"
        }
    });

    let tx = IncomingTx {
        sender: payload.address.clone(),
        recipient: contract_address.to_string(),
        amount: payload.amount.unwrap_or_else(|| "1200000".to_string()),
        denom: payload.denom.unwrap_or_else(|| "umin".to_string()),
        contract_address: Some(contract_address.to_string()),
        function_name: Some("swap".to_string()),
        contract_msg: Some(execute_message.clone()),
        controller_chain: None,
        message_type: Some("/cosmwasm.wasm.v1.MsgExecuteContract".to_string()),
        raw_bytes: vec![],
        timestamp: chrono::Utc::now(),
    };

    let simulation = SimulationResult {
        will_fail: false,
        fail_reason: None,
        gas_estimate: 240_000,
        balance_deltas: vec![],
        observed_actions: vec!["swap".to_string(), "route_thin_pool".to_string()],
        touched_contracts: vec![contract_address.to_string()],
        swap_execution: Some(SwapExecutionInsight {
            offered_amount: Some(tx.amount.parse().unwrap_or(1_200_000)),
            return_amount: Some(2_040_000),
            spread_amount: Some(150_000),
            commission_amount: Some(4_200),
            offer_pool: Some(11_000_000),
            ask_pool: Some(20_000_000),
        }),
    };

    let mut findings = liquidity::inspect_liquidity(&tx, Some(&simulation))
        .into_iter()
        .collect::<Vec<_>>();

    if let Ok(risk) = contract::score_contract(
        &state.config.initia_lcd,
        state.config.initia_json_rpc.as_deref(),
        contract_address,
        0,
        None,
        &state.config.known_protocols,
        tx.function_name.as_deref(),
    )
    .await
    {
        if risk.score >= 50 {
            findings.push(RiskFinding {
                module: "contract".to_string(),
                severity: if risk.score >= 80 {
                    Severity::Critical
                } else {
                    Severity::High
                },
                weight: risk.score,
                description: format!(
                    "Contract risk score {}/100; verified: {}; unexpected flow: {}",
                    risk.score, risk.is_verified, risk.unexpected_flow
                ),
                payload: serde_json::to_value(risk).unwrap_or_else(|_| serde_json::json!({})),
            });
        }
    }

    findings.push(RiskFinding {
        module: "simulator".to_string(),
        severity: Severity::High,
        weight: 50,
        description: "Synthetic swap preview shows thin liquidity and elevated execution loss risk"
            .to_string(),
        payload: serde_json::json!({
            "contract_address": contract_address,
            "price_impact_ratio": 0.0685,
            "pool_share_ratio": 0.1091,
        }),
    });

    let decision = classify_preview_findings(findings);

    Ok(Json(PreviewRiskLabResponse {
        contract_address: contract_address.to_string(),
        decision,
        execute_message,
        inspection: None,
    }))
}

async fn inspect_contract_findings(
    state: &AppState,
    contract_address: &str,
    called_function: Option<&str>,
    analysis_network: Option<PreviewAnalysisNetwork>,
) -> Result<(Vec<RiskFinding>, contract::ContractRisk), (StatusCode, String)> {
    let selected_json_rpc = selected_evm_rpc(state, analysis_network, contract_address)
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let risk = contract::score_contract(
        &state.config.initia_lcd,
        selected_json_rpc.as_deref(),
        contract_address,
        0,
        None,
        &state.config.known_protocols,
        called_function,
    )
    .await
    .map_err(map_contract_analysis_error)?;

    let mut findings = Vec::new();
    if risk.score >= 50 {
        findings.push(RiskFinding {
            module: "contract".to_string(),
            severity: if risk.score >= 80 {
                Severity::Critical
            } else {
                Severity::High
            },
            weight: risk.score,
            description: if risk.score >= 80 {
                "Bytecode and metadata signals indicate critical contract risk".to_string()
            } else {
                "Contract metadata suggests elevated operational risk and manual review is recommended"
                    .to_string()
            },
            payload: serde_json::to_value(&risk).unwrap_or_else(|_| serde_json::json!({})),
        });
    }

    Ok((findings, risk))
}

fn map_contract_analysis_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    let message = error.to_string();
    if message.contains("MiniEVM JSON-RPC not configured")
        || message.contains("no deployed runtime bytecode")
        || message.contains("no modules found for contract")
    {
        return (StatusCode::BAD_REQUEST, message);
    }

    (
        StatusCode::BAD_GATEWAY,
        format!("Contract analysis failed: {message}"),
    )
}

fn api_error(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<ApiErrorResponse>) {
    (
        status,
        Json(ApiErrorResponse {
            error: message.into(),
        }),
    )
}

fn selected_evm_rpc(
    state: &AppState,
    analysis_network: Option<PreviewAnalysisNetwork>,
    contract_address: &str,
) -> Result<Option<String>, String> {
    if !contract_address.starts_with("0x") {
        return Ok(None);
    }

    match analysis_network.unwrap_or(PreviewAnalysisNetwork::Auto) {
        PreviewAnalysisNetwork::Auto | PreviewAnalysisNetwork::InitiaMinievm => state
            .config
            .initia_json_rpc
            .clone()
            .ok_or_else(|| {
                "Initia MiniEVM JSON-RPC is not configured. Set INITIA_JSON_RPC to analyze Initia 0x... contracts."
                    .to_string()
            })
            .map(Some),
        PreviewAnalysisNetwork::Sepolia => state
            .config
            .sepolia_json_rpc
            .clone()
            .ok_or_else(|| {
                "Sepolia JSON-RPC is not configured. Set SEPOLIA_JSON_RPC to analyze Sepolia 0x... contracts."
                    .to_string()
            })
            .map(Some),
        PreviewAnalysisNetwork::WasmMove => Ok(None),
    }
}

fn validate_analysis_network(
    network: Option<PreviewAnalysisNetwork>,
    contract_address: &str,
) -> Result<(), (StatusCode, String)> {
    let is_evm = contract_address.starts_with("0x");
    match network.unwrap_or(PreviewAnalysisNetwork::Auto) {
        PreviewAnalysisNetwork::Auto => Ok(()),
        PreviewAnalysisNetwork::InitiaMinievm if !is_evm => Err((
            StatusCode::BAD_REQUEST,
            "Initia MiniEVM analysis expects a 0x... contract address.".to_string(),
        )),
        PreviewAnalysisNetwork::Sepolia if !is_evm => Err((
            StatusCode::BAD_REQUEST,
            "Sepolia analysis expects a 0x... contract address.".to_string(),
        )),
        PreviewAnalysisNetwork::WasmMove if is_evm => Err((
            StatusCode::BAD_REQUEST,
            "Guardian Wasm/Move analysis expects an init1... contract address.".to_string(),
        )),
        _ => Ok(()),
    }
}

fn select_scenario(id: &str) -> Option<ScenarioResult> {
    match id {
        "address_poisoning" => Some(address_poisoning_scenario()),
        "dust_attack" => Some(dust_attack_scenario()),
        "approval_attack" => Some(approval_attack_scenario()),
        "behavioral_anomaly" => Some(anomaly_attack_scenario()),
        "ica_abuse" => Some(ica_attack_scenario()),
        "low_liquidity" => Some(low_liquidity_scenario()),
        "high_slippage" => Some(high_slippage_scenario()),
        "simulated_contract_abuse" => Some(simulated_contract_abuse_scenario()),
        "reentrancy_pattern" => Some(reentrancy_pattern_scenario()),
        _ => None,
    }
}

fn classify_preview_findings(findings: Vec<RiskFinding>) -> GuardianDecision {
    let total = findings.iter().map(|finding| finding.weight).sum::<i32>();
    let auto_revoke = findings.iter().any(|finding| finding.module == "approval") && total >= 80;

    if total < 30 {
        GuardianDecision::Allow
    } else if total < 60 {
        GuardianDecision::Warn { findings }
    } else if total < 80 {
        GuardianDecision::Confirm { findings }
    } else {
        GuardianDecision::Block {
            findings,
            auto_revoke,
        }
    }
}

fn retarget_scenario(scenario: &mut ScenarioResult, target_address: &str) {
    let previous_target = scenario.target_address.clone();
    scenario.target_address = target_address.to_string();

    for finding in &mut scenario.findings {
        if let Some(payload_address) = finding
            .payload
            .get_mut("address")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
        {
            if payload_address == previous_target {
                finding.payload["address"] = serde_json::Value::String(target_address.to_string());
            }
        }

        if let Some(payload_owner) = finding
            .payload
            .get_mut("owner")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
        {
            if payload_owner == previous_target {
                finding.payload["owner"] = serde_json::Value::String(target_address.to_string());
            }
        }
    }
}

async fn load_demo_approval_lab_approvals(
    state: &AppState,
    owner: &str,
) -> anyhow::Result<Vec<ApprovalRecord>> {
    let Some(contract_address) = state.config.demo_approval_lab_contract_address.as_deref() else {
        return Ok(Vec::new());
    };

    let msg = serde_json::json!({
        "allowances_by_owner": {
            "owner": owner
        }
    });
    let encoded = STANDARD.encode(serde_json::to_vec(&msg)?);
    let encoded = byte_serialize(encoded.as_bytes()).collect::<String>();
    let endpoint = format!(
        "{}/cosmwasm/wasm/v1/contract/{}/smart/{}",
        state.config.initia_lcd.trim_end_matches('/'),
        contract_address,
        encoded
    );

    let response = Client::new()
        .get(endpoint)
        .send()
        .await?
        .error_for_status()?
        .json::<DemoApprovalAllowancesEnvelope>()
        .await?;

    let current_height = 0_i64;

    Ok(response
        .data
        .allowances
        .into_iter()
        .filter(|entry| entry.amount != "0")
        .map(|entry| {
            let amount = entry.amount;
            let revoke_messages = serde_json::json!([
                {
                    "typeUrl": "/cosmwasm.wasm.v1.MsgExecuteContract",
                    "value": {
                        "sender": owner,
                        "contract": contract_address,
                        "funds": [],
                        "msg_json": {
                            "decrease_allowance": {
                                "spender": entry.spender,
                                "amount": amount
                            }
                        }
                    }
                }
            ]);

            let mut record = ApprovalRecord {
                id: Uuid::new_v4(),
                owner: owner.to_string(),
                spender: entry.spender,
                token_denom: response.data.symbol.clone(),
                amount,
                granted_at_height: 0,
                revoked: false,
                risk_score: 0,
                approval_type: Some("cw20".to_string()),
                contract_address: Some(contract_address.to_string()),
                revoke_messages,
                created_at: chrono::Utc::now(),
            };
            record.risk_score = guardian_analyzer::approvals::score_approval(
                &record,
                current_height,
                &state.config.known_protocols,
            );
            record
        })
        .collect())
}

fn merge_approval_records(
    mut primary: Vec<ApprovalRecord>,
    secondary: Vec<ApprovalRecord>,
) -> Vec<ApprovalRecord> {
    for candidate in secondary {
        if let Some(existing) = primary.iter_mut().find(|entry| {
            entry.owner == candidate.owner
                && entry.spender == candidate.spender
                && entry.contract_address == candidate.contract_address
                && entry.approval_type == candidate.approval_type
        }) {
            *existing = candidate;
        } else {
            primary.push(candidate);
        }
    }

    primary.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    primary
}

async fn ensure_primary_watched_address(state: &AppState, owner: &str) -> Result<(), StatusCode> {
    let watched_addresses = state
        .repository
        .watched_addresses(owner)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if watched_addresses.iter().any(|entry| entry.address == owner) {
        return Ok(());
    }

    let should_be_primary = watched_addresses
        .iter()
        .all(|entry| !entry.is_simulation_target);

    state
        .repository
        .upsert_watched_address(owner, owner, Some("Primary wallet"), should_be_primary)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ListApprovalsQuery {
    pub refresh: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ListRiskEventsQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertWatchedAddressRequest {
    pub owner_address: String,
    pub address: String,
    pub label: Option<String>,
    pub is_simulation_target: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterEmailRequest {
    pub address: String,
    pub email_address: String,
    pub email_display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendTestEmailRequest {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct RunSimulationRequest {
    pub address: String,
    pub scenario_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreviewAnalysisMode {
    Demo,
    Inspect,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreviewAnalysisNetwork {
    Auto,
    WasmMove,
    InitiaMinievm,
    Sepolia,
}

#[derive(Debug, Deserialize)]
pub struct PreviewRiskLabRequest {
    pub address: String,
    pub contract_address: String,
    pub amount: Option<String>,
    pub denom: Option<String>,
    pub analysis_mode: Option<PreviewAnalysisMode>,
    pub analysis_network: Option<PreviewAnalysisNetwork>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeApprovalPlanRequest {
    pub owner: String,
    pub spender: String,
}

#[derive(Debug, Serialize)]
pub struct ApiStatus {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub user: Option<RegisteredUser>,
    pub simulation_target: Option<WatchedAddress>,
}

#[derive(Debug, Serialize)]
pub struct PolicyOverviewResponse {
    pub configured: bool,
    pub contract_address: Option<String>,
    pub reporting_enabled: bool,
    pub policy: Option<GuardianPolicyView>,
    pub incidents: Vec<GuardianPolicyIncident>,
    pub quarantined: Vec<GuardianQuarantineEntry>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RevokeApprovalPlanResponse {
    pub summary: String,
    pub messages: Vec<ProtoMessage>,
}

#[derive(Debug, Serialize)]
pub struct RunSimulationResponse {
    pub scenario_id: String,
    pub attack_surface: String,
    pub target_address: String,
    pub findings: Vec<RiskFinding>,
    pub available_scenarios: Vec<String>,
    pub ran_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct PreviewRiskLabResponse {
    pub contract_address: String,
    pub decision: GuardianDecision,
    pub execute_message: serde_json::Value,
    pub inspection: Option<contract::ContractRisk>,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorResponse {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoMessage {
    #[serde(rename = "typeUrl")]
    pub type_url: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct DemoApprovalAllowancesEnvelope {
    data: DemoApprovalAllowancesResponse,
}

#[derive(Debug, Deserialize)]
struct DemoApprovalAllowancesResponse {
    symbol: String,
    allowances: Vec<DemoApprovalAllowanceEntry>,
}

#[derive(Debug, Deserialize)]
struct DemoApprovalAllowanceEntry {
    spender: String,
    amount: String,
}
