use cosmwasm_std::{
    entry_point, to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response,
    StdResult,
};
use cw2::set_contract_version;
use cw_storage_plus::Bound;

use crate::{
    error::ContractError,
    msg::{
        ConfigResponse, ExecuteMsg, IncidentListResponse, IncidentView, InstantiateMsg, PolicyResponse,
        PolicyView, QuarantineListResponse, QuarantineResponse, QuarantineView, QueryMsg,
        TrustedContractEntry, TrustedContractListResponse, TrustedContractResponse,
    },
    state::{
        Config, Incident, Policy, QuarantineEntry, CONFIG, INCIDENTS, INCIDENT_SEQ, POLICIES,
        QUARANTINES, REPORTERS, TRUSTED_CONTRACTS,
    },
};

const CONTRACT_NAME: &str = "guardian-policy";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_LIMIT: u32 = 25;
const MAX_LIMIT: u32 = 100;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = match msg.admin {
        Some(admin) => deps.api.addr_validate(&admin)?,
        None => info.sender.clone(),
    };

    CONFIG.save(deps.storage, &Config { admin: admin.clone() })?;
    INCIDENT_SEQ.save(deps.storage, &0)?;
    REPORTERS.save(deps.storage, &admin, &true)?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", admin))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::UpdatePolicy {
            warn_threshold,
            confirm_threshold,
            block_threshold,
            trusted_contracts,
            trusted_recipients,
            auto_block_new_contracts,
        } => execute_update_policy(
            deps,
            env,
            info,
            warn_threshold,
            confirm_threshold,
            block_threshold,
            trusted_contracts,
            trusted_recipients,
            auto_block_new_contracts,
        ),
        ExecuteMsg::SetReporter { reporter, enabled } => {
            execute_set_reporter(deps, info, reporter, enabled)
        }
        ExecuteMsg::SetTrustedContract { address, trusted } => {
            execute_set_trusted_contract(deps, info, address, trusted)
        }
        ExecuteMsg::QuarantineAddress {
            owner,
            address,
            reason,
            risk_score,
        } => execute_quarantine(deps, env, info, owner, address, reason, risk_score),
        ExecuteMsg::ClearQuarantine { owner, address } => {
            execute_clear_quarantine(deps, info, owner, address)
        }
        ExecuteMsg::RecordIncident {
            owner,
            event_type,
            severity,
            tx_hash,
            summary,
            details_json,
        } => execute_record_incident(
            deps,
            env,
            info,
            owner,
            event_type,
            severity,
            tx_hash,
            summary,
            details_json,
        ),
    }
}

fn execute_update_policy(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    warn_threshold: u8,
    confirm_threshold: u8,
    block_threshold: u8,
    trusted_contracts: Vec<String>,
    trusted_recipients: Vec<String>,
    auto_block_new_contracts: bool,
) -> Result<Response, ContractError> {
    if !(warn_threshold < confirm_threshold && confirm_threshold < block_threshold) {
        return Err(ContractError::InvalidThresholds);
    }

    let owner = info.sender.clone();
    let policy = Policy {
        warn_threshold,
        confirm_threshold,
        block_threshold,
        trusted_contracts,
        trusted_recipients,
        auto_block_new_contracts,
        updated_at: env.block.time.seconds(),
    };
    POLICIES.save(deps.storage, &owner, &policy)?;

    Ok(Response::new()
        .add_attribute("action", "update_policy")
        .add_attribute("owner", owner))
}

fn execute_set_reporter(
    deps: DepsMut,
    info: MessageInfo,
    reporter: String,
    enabled: bool,
) -> Result<Response, ContractError> {
    ensure_admin(deps.as_ref(), &info.sender)?;
    let reporter = deps.api.addr_validate(&reporter)?;
    REPORTERS.save(deps.storage, &reporter, &enabled)?;

    Ok(Response::new()
        .add_attribute("action", "set_reporter")
        .add_attribute("reporter", reporter)
        .add_attribute("enabled", enabled.to_string()))
}

fn execute_set_trusted_contract(
    deps: DepsMut,
    info: MessageInfo,
    address: String,
    trusted: bool,
) -> Result<Response, ContractError> {
    ensure_admin(deps.as_ref(), &info.sender)?;
    if trusted {
        TRUSTED_CONTRACTS.save(deps.storage, &address, &true)?;
    } else {
        TRUSTED_CONTRACTS.remove(deps.storage, &address);
    }

    Ok(Response::new()
        .add_attribute("action", "set_trusted_contract")
        .add_attribute("address", address)
        .add_attribute("trusted", trusted.to_string()))
}

fn execute_quarantine(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    owner: String,
    address: String,
    reason: String,
    risk_score: u8,
) -> Result<Response, ContractError> {
    if risk_score > 100 {
        return Err(ContractError::InvalidRiskScore);
    }
    ensure_reporter_or_owner(deps.as_ref(), &info.sender, &owner)?;
    let owner = deps.api.addr_validate(&owner)?;
    let entry = QuarantineEntry {
        owner: owner.clone(),
        address: address.clone(),
        reason,
        risk_score,
        quarantined_at: env.block.time.seconds(),
    };
    QUARANTINES.save(deps.storage, (&owner, address.as_str()), &entry)?;

    Ok(Response::new()
        .add_attribute("action", "quarantine_address")
        .add_attribute("owner", owner)
        .add_attribute("address", address))
}

fn execute_clear_quarantine(
    deps: DepsMut,
    info: MessageInfo,
    owner: String,
    address: String,
) -> Result<Response, ContractError> {
    ensure_reporter_or_owner(deps.as_ref(), &info.sender, &owner)?;
    let owner = deps.api.addr_validate(&owner)?;
    QUARANTINES.remove(deps.storage, (&owner, address.as_str()));

    Ok(Response::new()
        .add_attribute("action", "clear_quarantine")
        .add_attribute("owner", owner)
        .add_attribute("address", address))
}

#[allow(clippy::too_many_arguments)]
fn execute_record_incident(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    owner: String,
    event_type: String,
    severity: String,
    tx_hash: Option<String>,
    summary: String,
    details_json: String,
) -> Result<Response, ContractError> {
    ensure_reporter_or_owner(deps.as_ref(), &info.sender, &owner)?;
    let owner = deps.api.addr_validate(&owner)?;
    let id = INCIDENT_SEQ.update(deps.storage, |id| -> StdResult<_> { Ok(id + 1) })?;
    let incident = Incident {
        id,
        owner: owner.clone(),
        reporter: info.sender.clone(),
        event_type,
        severity,
        tx_hash,
        summary,
        details_json,
        created_at: env.block.time.seconds(),
    };
    INCIDENTS.save(deps.storage, (&owner, id), &incident)?;

    Ok(Response::new()
        .add_attribute("action", "record_incident")
        .add_attribute("owner", owner)
        .add_attribute("incident_id", id.to_string()))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&query_config(deps)?),
        QueryMsg::GetPolicy { owner } => to_json_binary(&query_policy(deps, owner)?),
        QueryMsg::ListIncidents {
            owner,
            start_after,
            limit,
        } => to_json_binary(&query_incidents(deps, owner, start_after, limit)?),
        QueryMsg::GetQuarantine { owner, address } => {
            to_json_binary(&query_quarantine(deps, owner, address)?)
        }
        QueryMsg::ListQuarantined {
            owner,
            start_after,
            limit,
        } => to_json_binary(&query_quarantined(deps, owner, start_after, limit)?),
        QueryMsg::IsTrustedContract { address } => {
            to_json_binary(&query_trusted_contract(deps, address)?)
        }
        QueryMsg::ListTrustedContracts { start_after, limit } => {
            to_json_binary(&query_trusted_contracts(deps, start_after, limit)?)
        }
    }
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    let reporters = REPORTERS
        .range(deps.storage, None, None, Order::Ascending)
        .filter_map(|item| match item {
            Ok((reporter, enabled)) if enabled => Some(Ok(reporter.to_string())),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(ConfigResponse {
        admin: config.admin.to_string(),
        reporters,
    })
}

fn query_policy(deps: Deps, owner: String) -> StdResult<PolicyResponse> {
    let owner = deps.api.addr_validate(&owner)?;
    let policy = POLICIES.may_load(deps.storage, &owner)?;

    Ok(PolicyResponse {
        policy: policy.map(|policy| PolicyView {
            owner: owner.to_string(),
            warn_threshold: policy.warn_threshold,
            confirm_threshold: policy.confirm_threshold,
            block_threshold: policy.block_threshold,
            trusted_contracts: policy.trusted_contracts,
            trusted_recipients: policy.trusted_recipients,
            auto_block_new_contracts: policy.auto_block_new_contracts,
            updated_at: policy.updated_at,
        }),
    })
}

fn query_incidents(
    deps: Deps,
    owner: String,
    start_after: Option<u64>,
    limit: Option<u32>,
) -> StdResult<IncidentListResponse> {
    let owner = deps.api.addr_validate(&owner)?;
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);
    let incidents = INCIDENTS
        .prefix(&owner)
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            let (_, incident) = item?;
            Ok(IncidentView {
                id: incident.id,
                owner: incident.owner.to_string(),
                reporter: incident.reporter.to_string(),
                event_type: incident.event_type,
                severity: incident.severity,
                tx_hash: incident.tx_hash,
                summary: incident.summary,
                details_json: incident.details_json,
                created_at: incident.created_at,
            })
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(IncidentListResponse { incidents })
}

fn query_quarantine(deps: Deps, owner: String, address: String) -> StdResult<QuarantineResponse> {
    let owner = deps.api.addr_validate(&owner)?;
    let entry = QUARANTINES
        .may_load(deps.storage, (&owner, address.as_str()))?
        .map(|entry| QuarantineView {
            owner: entry.owner.to_string(),
            address: entry.address,
            reason: entry.reason,
            risk_score: entry.risk_score,
            quarantined_at: entry.quarantined_at,
        });

    Ok(QuarantineResponse { entry })
}

fn query_quarantined(
    deps: Deps,
    owner: String,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<QuarantineListResponse> {
    let owner = deps.api.addr_validate(&owner)?;
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after
        .as_deref()
        .map(Bound::exclusive);

    let entries = QUARANTINES
        .prefix(&owner)
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            let (_, entry) = item?;
            Ok(QuarantineView {
                owner: entry.owner.to_string(),
                address: entry.address,
                reason: entry.reason,
                risk_score: entry.risk_score,
                quarantined_at: entry.quarantined_at,
            })
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(QuarantineListResponse { entries })
}

fn query_trusted_contract(deps: Deps, address: String) -> StdResult<TrustedContractResponse> {
    let trusted = TRUSTED_CONTRACTS
        .may_load(deps.storage, &address)?
        .unwrap_or(false);
    Ok(TrustedContractResponse { address, trusted })
}

fn query_trusted_contracts(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<TrustedContractListResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after
        .as_deref()
        .map(Bound::exclusive);

    let entries = TRUSTED_CONTRACTS
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            let (address, trusted) = item?;
            Ok(TrustedContractEntry { address, trusted })
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(TrustedContractListResponse { entries })
}

fn ensure_admin(deps: Deps, sender: &Addr) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if sender == &config.admin {
        Ok(())
    } else {
        Err(ContractError::Unauthorized)
    }
}

fn ensure_reporter_or_owner(deps: Deps, sender: &Addr, owner: &str) -> Result<(), ContractError> {
    if sender == &deps.api.addr_validate(owner)? {
        return Ok(());
    }

    if REPORTERS.may_load(deps.storage, sender)?.unwrap_or(false) {
        return Ok(());
    }

    let config = CONFIG.load(deps.storage)?;
    if sender == &config.admin {
        return Ok(());
    }

    Err(ContractError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{
        from_json,
        testing::{message_info, mock_dependencies, mock_env},
    };

    use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

    use super::{execute, instantiate, query};

    #[test]
    fn owner_can_store_policy_and_reporter_can_record_incident() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let owner = deps.api.addr_make("owner");
        let reporter = deps.api.addr_make("reporter");

        instantiate(
            deps.as_mut(),
            env.clone(),
            message_info(&owner, &[]),
            InstantiateMsg { admin: None },
        )
        .unwrap();

        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&owner, &[]),
            ExecuteMsg::SetReporter {
                reporter: reporter.to_string(),
                enabled: true,
            },
        )
        .unwrap();

        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&owner, &[]),
            ExecuteMsg::UpdatePolicy {
                warn_threshold: 30,
                confirm_threshold: 60,
                block_threshold: 80,
                trusted_contracts: vec!["init1safecontract".to_string()],
                trusted_recipients: vec!["init1friend".to_string()],
                auto_block_new_contracts: true,
            },
        )
        .unwrap();

        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&reporter, &[]),
            ExecuteMsg::RecordIncident {
                owner: owner.to_string(),
                event_type: "approval_intent".to_string(),
                severity: "high".to_string(),
                tx_hash: Some("ABC123".to_string()),
                summary: "blocked suspicious approval".to_string(),
                details_json: "{\"weight\":95}".to_string(),
            },
        )
        .unwrap();

        let policy: crate::msg::PolicyResponse = from_json(
            query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::GetPolicy {
                    owner: owner.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(policy.policy.is_some());

        let incidents: crate::msg::IncidentListResponse = from_json(
            query(
                deps.as_ref(),
                env,
                QueryMsg::ListIncidents {
                    owner: owner.to_string(),
                    start_after: None,
                    limit: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(incidents.incidents.len(), 1);
        assert_eq!(incidents.incidents[0].reporter, reporter.to_string());
    }
}
