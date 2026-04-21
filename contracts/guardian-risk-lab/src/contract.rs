use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use cw2::set_contract_version;

use crate::{
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, ProfileResponse, QueryMsg},
    state::{Config, CONFIG},
};

const CONTRACT_NAME: &str = "guardian-risk-lab";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_LABEL: &str = "Guardian Risk Lab";

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = match msg.admin {
        Some(admin) => deps.api.addr_validate(&admin)?,
        None => info.sender.clone(),
    };
    let label = msg
        .label
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_LABEL.to_string());

    CONFIG.save(
        deps.storage,
        &Config {
            admin: admin.clone(),
            label: label.clone(),
            created_at: env.block.time.seconds(),
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", admin)
        .add_attribute("label", label))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ExecuteAttack { callback, note } => Ok(Response::new()
            .add_attribute("action", "execute_attack")
            .add_attribute("sender", info.sender)
            .add_attribute("callback", callback)
            .add_attribute("note", note.unwrap_or_else(|| "risk-lab-demo".to_string()))),
        ExecuteMsg::DrainThenCall { receiver, callback } => Ok(Response::new()
            .add_attribute("action", "drain_then_call")
            .add_attribute("sender", info.sender)
            .add_attribute("receiver", receiver)
            .add_attribute("callback", callback)),
        ExecuteMsg::UpdateAdminScenario { new_admin } => {
            let mut config = CONFIG.load(deps.storage)?;
            if info.sender != config.admin {
                return Err(ContractError::Unauthorized);
            }

            let validated = deps.api.addr_validate(&new_admin)?;
            config.admin = validated.clone();
            CONFIG.save(deps.storage, &config)?;

            Ok(Response::new()
                .add_attribute("action", "update_admin_scenario")
                .add_attribute("new_admin", validated))
        }
        ExecuteMsg::Ping {} => Ok(Response::new().add_attribute("action", "ping")),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Profile {} => to_json_binary(&query_profile(deps)?),
    }
}

fn query_profile(deps: Deps) -> StdResult<ProfileResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ProfileResponse {
        admin: config.admin.to_string(),
        label: config.label,
        created_at: config.created_at,
    })
}
