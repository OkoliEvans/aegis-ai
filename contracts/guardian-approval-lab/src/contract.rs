use cosmwasm_std::{
    entry_point, to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response,
    StdResult, Uint128,
};
use cw2::set_contract_version;

use crate::{
    error::ContractError,
    msg::{
        AllowanceEntry, AllowanceResponse, AllowancesByOwnerResponse, BalanceResponse, ExecuteMsg,
        InstantiateMsg, ProfileResponse, QueryMsg, TokenInfoResponse,
    },
    state::{ALLOWANCES, BALANCES, CONFIG, FAUCET_CLAIMS, Config},
};

const CONTRACT_NAME: &str = "guardian-approval-lab";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_NAME: &str = "Guardian Demo Token";
const DEFAULT_SYMBOL: &str = "AGD";
const DEFAULT_DECIMALS: u8 = 6;
const DEFAULT_FAUCET_AMOUNT: &str = "50000000";

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
    let faucet_amount = parse_amount(msg.faucet_amount.as_deref())?;

    CONFIG.save(
        deps.storage,
        &Config {
            admin: admin.clone(),
            name: clean_string(msg.name, DEFAULT_NAME),
            symbol: clean_string(msg.symbol, DEFAULT_SYMBOL),
            decimals: msg.decimals.unwrap_or(DEFAULT_DECIMALS),
            faucet_amount,
            created_at: env.block.time.seconds(),
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", admin)
        .add_attribute("faucet_amount", faucet_amount))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ClaimDemoBalance {} => claim_demo_balance(deps, info),
        ExecuteMsg::MintDemo { recipient, amount } => mint_demo(deps, info, recipient, amount),
        ExecuteMsg::Transfer { recipient, amount } => transfer(deps, info, recipient, amount),
        ExecuteMsg::SeedAllowance {
            owner,
            spender,
            amount,
        } => seed_allowance(deps, info, owner, spender, amount),
        ExecuteMsg::IncreaseAllowance { spender, amount } => {
            increase_allowance(deps, env, info, spender, amount)
        }
        ExecuteMsg::DecreaseAllowance { spender, amount } => {
            decrease_allowance(deps, env, info, spender, amount)
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Profile {} => to_json_binary(&query_profile(deps)?),
        QueryMsg::TokenInfo {} => to_json_binary(&query_token_info(deps)?),
        QueryMsg::Balance { address } => to_json_binary(&query_balance(deps, address)?),
        QueryMsg::Allowance { owner, spender } => {
            to_json_binary(&query_allowance(deps, owner, spender)?)
        }
        QueryMsg::AllowancesByOwner { owner } => to_json_binary(&query_allowances_by_owner(deps, owner)?),
    }
}

fn claim_demo_balance(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
    if FAUCET_CLAIMS
        .may_load(deps.storage, &info.sender)?
        .unwrap_or(false)
    {
        return Err(ContractError::AlreadyClaimed);
    }

    let config = CONFIG.load(deps.storage)?;
    let balance = BALANCES
        .may_load(deps.storage, &info.sender)?
        .unwrap_or_default()
        .checked_add(config.faucet_amount)?;
    BALANCES.save(deps.storage, &info.sender, &balance)?;
    FAUCET_CLAIMS.save(deps.storage, &info.sender, &true)?;

    Ok(Response::new()
        .add_attribute("action", "claim_demo_balance")
        .add_attribute("owner", info.sender)
        .add_attribute("amount", config.faucet_amount))
}

fn mint_demo(
    deps: DepsMut,
    info: MessageInfo,
    recipient: String,
    amount: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    ensure_admin(&config, &info.sender)?;
    let recipient = deps.api.addr_validate(&recipient)?;
    let amount = parse_amount(Some(amount.as_str()))?;
    let balance = BALANCES
        .may_load(deps.storage, &recipient)?
        .unwrap_or_default()
        .checked_add(amount)?;
    BALANCES.save(deps.storage, &recipient, &balance)?;

    Ok(Response::new()
        .add_attribute("action", "mint_demo")
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount))
}

fn transfer(
    deps: DepsMut,
    info: MessageInfo,
    recipient: String,
    amount: String,
) -> Result<Response, ContractError> {
    let recipient = deps.api.addr_validate(&recipient)?;
    let amount = parse_amount(Some(amount.as_str()))?;

    BALANCES.update(deps.storage, &info.sender, |balance| -> Result<_, ContractError> {
        let balance = balance.unwrap_or_default();
        if balance < amount {
            return Err(ContractError::InsufficientBalance);
        }
        Ok(balance.checked_sub(amount)?)
    })?;

    let recipient_balance = BALANCES
        .may_load(deps.storage, &recipient)?
        .unwrap_or_default()
        .checked_add(amount)?;
    BALANCES.save(deps.storage, &recipient, &recipient_balance)?;

    Ok(Response::new()
        .add_attribute("action", "transfer")
        .add_attribute("sender", info.sender)
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount))
}

fn seed_allowance(
    deps: DepsMut,
    info: MessageInfo,
    owner: String,
    spender: String,
    amount: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    ensure_admin(&config, &info.sender)?;
    let owner = deps.api.addr_validate(&owner)?;
    let spender = deps.api.addr_validate(&spender)?;
    let amount = parse_amount(Some(amount.as_str()))?;
    if amount.is_zero() {
        ALLOWANCES.remove(deps.storage, (&owner, &spender));
    } else {
        ALLOWANCES.save(deps.storage, (&owner, &spender), &amount)?;
    }

    Ok(Response::new()
        .add_attribute("action", "seed_allowance")
        .add_attribute("owner", owner)
        .add_attribute("spender", spender)
        .add_attribute("amount", amount))
}

fn increase_allowance(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: String,
) -> Result<Response, ContractError> {
    let spender = deps.api.addr_validate(&spender)?;
    let amount = parse_amount(Some(amount.as_str()))?;
    let current = ALLOWANCES
        .may_load(deps.storage, (&info.sender, &spender))?
        .unwrap_or_default();
    let updated = current.checked_add(amount)?;
    ALLOWANCES.save(deps.storage, (&info.sender, &spender), &updated)?;

    Ok(Response::new()
        .add_attribute("action", "increase_allowance")
        .add_attribute("owner", info.sender)
        .add_attribute("spender", spender)
        .add_attribute("amount", updated))
}

fn decrease_allowance(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: String,
) -> Result<Response, ContractError> {
    let spender = deps.api.addr_validate(&spender)?;
    let amount = parse_amount(Some(amount.as_str()))?;
    let current = ALLOWANCES
        .may_load(deps.storage, (&info.sender, &spender))?
        .unwrap_or_default();

    if current.is_zero() {
        return Err(ContractError::AllowanceMissing {
            spender: spender.to_string(),
        });
    }

    let updated = current
        .checked_sub(amount)
        .map_err(|_| ContractError::AllowanceUnderflow { current, delta: amount })?;

    if updated.is_zero() {
        ALLOWANCES.remove(deps.storage, (&info.sender, &spender));
    } else {
        ALLOWANCES.save(deps.storage, (&info.sender, &spender), &updated)?;
    }

    Ok(Response::new()
        .add_attribute("action", "decrease_allowance")
        .add_attribute("owner", info.sender)
        .add_attribute("spender", spender)
        .add_attribute("amount", updated))
}

fn query_profile(deps: Deps) -> StdResult<ProfileResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ProfileResponse {
        admin: config.admin.to_string(),
        name: config.name,
        symbol: config.symbol,
        decimals: config.decimals,
        faucet_amount: config.faucet_amount.to_string(),
        created_at: config.created_at,
    })
}

fn query_token_info(deps: Deps) -> StdResult<TokenInfoResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(TokenInfoResponse {
        name: config.name,
        symbol: config.symbol,
        decimals: config.decimals,
    })
}

fn query_balance(deps: Deps, address: String) -> StdResult<BalanceResponse> {
    let address = deps.api.addr_validate(&address)?;
    let balance = BALANCES.may_load(deps.storage, &address)?.unwrap_or_default();
    Ok(BalanceResponse {
        address: address.to_string(),
        amount: balance.to_string(),
    })
}

fn query_allowance(deps: Deps, owner: String, spender: String) -> StdResult<AllowanceResponse> {
    let owner = deps.api.addr_validate(&owner)?;
    let spender = deps.api.addr_validate(&spender)?;
    let amount = ALLOWANCES
        .may_load(deps.storage, (&owner, &spender))?
        .unwrap_or_default();
    Ok(AllowanceResponse {
        owner: owner.to_string(),
        spender: spender.to_string(),
        amount: amount.to_string(),
    })
}

fn query_allowances_by_owner(deps: Deps, owner: String) -> StdResult<AllowancesByOwnerResponse> {
    let owner = deps.api.addr_validate(&owner)?;
    let config = CONFIG.load(deps.storage)?;
    let allowances = ALLOWANCES
        .prefix(&owner)
        .range(deps.storage, None, None, Order::Ascending)
        .map(|item| {
            let (spender, amount) = item?;
            Ok(AllowanceEntry {
                spender: spender.to_string(),
                amount: amount.to_string(),
            })
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(AllowancesByOwnerResponse {
        symbol: config.symbol,
        allowances,
    })
}

fn ensure_admin(config: &Config, sender: &Addr) -> Result<(), ContractError> {
    if sender != &config.admin {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

fn clean_string(value: Option<String>, fallback: &str) -> String {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn parse_amount(value: Option<&str>) -> Result<Uint128, ContractError> {
    let raw = value.unwrap_or(DEFAULT_FAUCET_AMOUNT).trim();
    if raw.is_empty() {
        return Err(ContractError::InvalidAmount);
    }
    raw.parse::<Uint128>()
        .map_err(|_| ContractError::InvalidAmount)
}
