use std::convert::Infallible;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use futures_util::StreamExt;
use guardian_core::{
    models::{ApprovalRecord, RegisteredUser, StoredRiskEvent, WatchedAddress},
    GuardianDecision, GuardianPolicyClient, GuardianPolicyIncident, GuardianPolicyView,
    GuardianQuarantineEntry, IncomingTx, RiskFinding, Severity,
};
use guardian_simulations::{
    address_poisoning_scenario, all_scenarios, anomaly_attack_scenario, approval_attack_scenario,
    dust_attack_scenario, ica_attack_scenario, reentrancy_pattern_scenario,
    simulated_contract_abuse_scenario, ScenarioResult,
};
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;

use crate::AppState;

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

    if params.refresh.unwrap_or(false) {
        let approvals =
            match guardian_analyzer::approvals::scan_approvals(&state.config.initia_lcd, &owner)
                .await
            {
                Ok(approvals) => approvals,
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
        return Ok(Json(stored));
    }

    let approvals = match guardian_analyzer::approvals::scan_approvals(
        &state.config.initia_lcd,
        &owner,
    )
    .await
    {
        Ok(approvals) => approvals,
        Err(error) if guardian_analyzer::approvals::scan_is_unavailable(&error) => Vec::new(),
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
) -> Result<Json<PreviewRiskLabResponse>, StatusCode> {
    let contract_address = payload.contract_address.trim();
    if contract_address.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
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
    }))
}

fn select_scenario(id: &str) -> Option<ScenarioResult> {
    match id {
        "address_poisoning" => Some(address_poisoning_scenario()),
        "dust_attack" => Some(dust_attack_scenario()),
        "approval_attack" => Some(approval_attack_scenario()),
        "behavioral_anomaly" => Some(anomaly_attack_scenario()),
        "ica_abuse" => Some(ica_attack_scenario()),
        "simulated_contract_abuse" => Some(simulated_contract_abuse_scenario()),
        "reentrancy_pattern" => Some(reentrancy_pattern_scenario()),
        _ => None,
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

#[derive(Debug, Deserialize)]
pub struct PreviewRiskLabRequest {
    pub address: String,
    pub contract_address: String,
    pub amount: Option<String>,
    pub denom: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoMessage {
    #[serde(rename = "typeUrl")]
    pub type_url: String,
    pub value: serde_json::Value,
}
