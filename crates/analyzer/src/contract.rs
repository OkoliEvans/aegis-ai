use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRisk {
    pub score: i32,
    pub age_blocks: i64,
    pub is_verified: bool,
    pub is_upgradeable: bool,
    pub suspicious_opcodes: Vec<String>,
    pub unexpected_flow: bool,
    pub drain_fn_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ModulesResponse {
    #[serde(default)]
    modules: Vec<ModuleEnvelope>,
}

#[derive(Debug, Deserialize)]
struct ModuleEnvelope {
    #[serde(default)]
    raw_bytes: String,
    #[serde(default)]
    exposed_functions: Vec<AbiFunction>,
    #[serde(default)]
    raw_source: Option<RawSource>,
}

#[derive(Debug, Clone, Deserialize)]
struct AbiFunction {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawSource {
    #[serde(default)]
    version: i64,
}

const DANGEROUS_OPCODES: &[(&str, &[u8])] = &[("SELFDESTRUCT", &[0xff]), ("DELEGATECALL", &[0xf4])];

const UPGRADE_SIGNATURES: &[&str] = &["upgradeTo", "upgradeToAndCall", "implementation"];
const DRAIN_NAME_HINTS: &[&str] = &[
    "withdraw_all",
    "drain",
    "sweep",
    "migrate",
    "emergency_exit",
    "rug",
    "set_owner",
];
const SUSPICIOUS_LABEL_HINTS: &[&str] = &["test", "drain", "rug", "exploit", "admin"];

pub async fn score_contract(
    lcd: &str,
    module_addr: &str,
    current_height: i64,
    sim_fund_destination: Option<&str>,
    known_protocols: &[String],
    called_function: Option<&str>,
) -> Result<ContractRisk> {
    if let Ok(risk) = score_wasm_contract(
        lcd,
        module_addr,
        sim_fund_destination,
        known_protocols,
        called_function,
    )
    .await
    {
        return Ok(risk);
    }

    let module = fetch_primary_module(lcd, module_addr).await?;
    let age_blocks = current_height.saturating_sub(
        module
            .raw_source
            .as_ref()
            .map(|source| source.version)
            .unwrap_or_default(),
    );

    let bytecode = STANDARD
        .decode(module.raw_bytes.as_bytes())
        .unwrap_or_default();
    let suspicious_opcodes = DANGEROUS_OPCODES
        .iter()
        .filter(|(_, sequence)| contains_sequence(&bytecode, sequence))
        .map(|(name, _)| (*name).to_string())
        .collect::<Vec<_>>();

    let drain_fn_names = module
        .exposed_functions
        .iter()
        .filter(|function| {
            DRAIN_NAME_HINTS
                .iter()
                .any(|hint| function.name.contains(hint))
        })
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();

    let is_upgradeable = module.exposed_functions.iter().any(|function| {
        UPGRADE_SIGNATURES
            .iter()
            .any(|hint| function.name.contains(hint))
    });
    let is_verified = check_verified(module_addr, known_protocols);
    let unexpected_flow = sim_fund_destination
        .map(|destination| {
            !known_protocols
                .iter()
                .any(|protocol| protocol == destination)
        })
        .unwrap_or(false);

    let mut score = 0;
    if age_blocks < 2_880 {
        score += 40;
    } else if age_blocks < 14_400 {
        score += 20;
    }
    if !is_verified {
        score += 25;
    }
    score += (suspicious_opcodes.len() as i32) * 20;
    if unexpected_flow {
        score += 50;
    }
    if is_upgradeable {
        score += 20;
    }
    if !drain_fn_names.is_empty() {
        score += 10;
    }
    if called_function
        .map(|function| {
            DRAIN_NAME_HINTS
                .iter()
                .any(|hint| function.to_ascii_lowercase().contains(hint))
        })
        .unwrap_or(false)
    {
        score += 20;
    }

    Ok(ContractRisk {
        score: score.min(100),
        age_blocks,
        is_verified,
        is_upgradeable,
        suspicious_opcodes,
        unexpected_flow,
        drain_fn_names,
    })
}

pub async fn fetch_module_bytecode_pub(lcd: &str, addr: &str) -> Result<Vec<u8>> {
    if let Ok(contract_info) = fetch_wasm_contract_info(lcd, addr).await {
        return fetch_wasm_code_bytes(
            lcd,
            contract_info.code_id.parse::<u64>().unwrap_or_default(),
        )
        .await;
    }
    let module = fetch_primary_module(lcd, addr).await?;
    Ok(STANDARD
        .decode(module.raw_bytes.as_bytes())
        .unwrap_or_default())
}

pub fn decompile_to_pseudocode(bytecode: &[u8]) -> String {
    if bytecode.is_empty() {
        return "empty bytecode".to_string();
    }

    let preview = bytecode
        .iter()
        .take(64)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("bytecode_preview: {preview}")
}

async fn fetch_primary_module(lcd: &str, addr: &str) -> Result<ModuleEnvelope> {
    let endpoint = format!(
        "{}/initia/move/v1/accounts/{addr}/modules",
        lcd.trim_end_matches('/')
    );
    let response: ModulesResponse = Client::new()
        .get(endpoint)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed to decode module listing")?;

    response
        .modules
        .into_iter()
        .next()
        .context("no modules found for contract")
}

fn check_verified(addr: &str, known_protocols: &[String]) -> bool {
    known_protocols.iter().any(|protocol| protocol == addr)
}

fn contains_sequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[derive(Debug, Deserialize)]
struct WasmContractInfoEnvelope {
    contract_info: WasmContractInfo,
}

#[derive(Debug, Deserialize)]
struct WasmContractInfo {
    code_id: String,
    creator: String,
    admin: String,
    label: String,
}

#[derive(Debug, Deserialize)]
struct WasmCodeBytesEnvelope {
    data: String,
}

async fn score_wasm_contract(
    lcd: &str,
    contract_addr: &str,
    sim_fund_destination: Option<&str>,
    known_protocols: &[String],
    called_function: Option<&str>,
) -> Result<ContractRisk> {
    let info = fetch_wasm_contract_info(lcd, contract_addr).await?;
    let code_id = info.code_id.parse::<u64>().unwrap_or_default();
    let is_verified = check_verified(contract_addr, known_protocols)
        || known_protocols
            .iter()
            .any(|protocol| protocol == &info.creator);
    let is_upgradeable = !info.admin.is_empty();
    let unexpected_flow = sim_fund_destination
        .map(|destination| {
            destination != contract_addr
                && !known_protocols
                    .iter()
                    .any(|protocol| protocol == destination)
        })
        .unwrap_or(false);

    let mut suspicious_opcodes = Vec::new();
    if is_upgradeable {
        suspicious_opcodes.push("WASM_ADMIN_PRESENT".to_string());
    }
    if SUSPICIOUS_LABEL_HINTS
        .iter()
        .any(|hint| info.label.to_ascii_lowercase().contains(hint))
    {
        suspicious_opcodes.push("SUSPICIOUS_LABEL".to_string());
    }

    let mut drain_fn_names = Vec::new();
    if let Some(function) = called_function {
        if DRAIN_NAME_HINTS
            .iter()
            .any(|hint| function.to_ascii_lowercase().contains(hint))
        {
            drain_fn_names.push(function.to_string());
        }
    }

    let mut score = 0;
    if !is_verified {
        score += 25;
    }
    if is_upgradeable {
        score += 25;
    }
    if !drain_fn_names.is_empty() {
        score += 20;
    }
    if unexpected_flow {
        score += 50;
    }
    if code_id <= 3 {
        score += 10;
    }
    score += (suspicious_opcodes.len() as i32) * 10;

    Ok(ContractRisk {
        score: score.min(100),
        age_blocks: 0,
        is_verified,
        is_upgradeable,
        suspicious_opcodes,
        unexpected_flow,
        drain_fn_names,
    })
}

async fn fetch_wasm_contract_info(lcd: &str, addr: &str) -> Result<WasmContractInfo> {
    let endpoint = format!(
        "{}/cosmwasm/wasm/v1/contract/{addr}",
        lcd.trim_end_matches('/')
    );
    let response: WasmContractInfoEnvelope = Client::new()
        .get(endpoint)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed to decode wasm contract info")?;
    Ok(response.contract_info)
}

async fn fetch_wasm_code_bytes(lcd: &str, code_id: u64) -> Result<Vec<u8>> {
    let endpoint = format!(
        "{}/cosmwasm/wasm/v1/code/{code_id}/download",
        lcd.trim_end_matches('/')
    );
    let response: WasmCodeBytesEnvelope = Client::new()
        .get(endpoint)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed to decode wasm code bytes response")?;
    STANDARD
        .decode(response.data.as_bytes())
        .context("failed to decode wasm code bytes")
}
