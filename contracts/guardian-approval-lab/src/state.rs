use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub faucet_amount: Uint128,
    pub created_at: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const BALANCES: Map<&Addr, Uint128> = Map::new("balances");
pub const ALLOWANCES: Map<(&Addr, &Addr), Uint128> = Map::new("allowances");
pub const FAUCET_CLAIMS: Map<&Addr, bool> = Map::new("faucet_claims");
