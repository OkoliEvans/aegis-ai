use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
}

#[cw_serde]
pub struct Policy {
    pub warn_threshold: u8,
    pub confirm_threshold: u8,
    pub block_threshold: u8,
    pub trusted_contracts: Vec<String>,
    pub trusted_recipients: Vec<String>,
    pub auto_block_new_contracts: bool,
    pub updated_at: u64,
}

#[cw_serde]
pub struct Incident {
    pub id: u64,
    pub owner: Addr,
    pub reporter: Addr,
    pub event_type: String,
    pub severity: String,
    pub tx_hash: Option<String>,
    pub summary: String,
    pub details_json: String,
    pub created_at: u64,
}

#[cw_serde]
pub struct QuarantineEntry {
    pub owner: Addr,
    pub address: String,
    pub reason: String,
    pub risk_score: u8,
    pub quarantined_at: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const INCIDENT_SEQ: Item<u64> = Item::new("incident_seq");
pub const REPORTERS: Map<&Addr, bool> = Map::new("reporters");
pub const POLICIES: Map<&Addr, Policy> = Map::new("policies");
pub const INCIDENTS: Map<(&Addr, u64), Incident> = Map::new("incidents");
pub const QUARANTINES: Map<(&Addr, &str), QuarantineEntry> = Map::new("quarantines");
pub const TRUSTED_CONTRACTS: Map<&str, bool> = Map::new("trusted_contracts");
