use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<String>,
    pub name: Option<String>,
    pub symbol: Option<String>,
    pub decimals: Option<u8>,
    pub faucet_amount: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    ClaimDemoBalance {},
    MintDemo {
        recipient: String,
        amount: String,
    },
    Transfer {
        recipient: String,
        amount: String,
    },
    SeedAllowance {
        owner: String,
        spender: String,
        amount: String,
    },
    IncreaseAllowance {
        spender: String,
        amount: String,
    },
    DecreaseAllowance {
        spender: String,
        amount: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ProfileResponse)]
    Profile {},
    #[returns(TokenInfoResponse)]
    TokenInfo {},
    #[returns(BalanceResponse)]
    Balance { address: String },
    #[returns(AllowanceResponse)]
    Allowance { owner: String, spender: String },
    #[returns(AllowancesByOwnerResponse)]
    AllowancesByOwner { owner: String },
}

#[cw_serde]
pub struct ProfileResponse {
    pub admin: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub faucet_amount: String,
    pub created_at: u64,
}

#[cw_serde]
pub struct TokenInfoResponse {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

#[cw_serde]
pub struct BalanceResponse {
    pub address: String,
    pub amount: String,
}

#[cw_serde]
pub struct AllowanceResponse {
    pub owner: String,
    pub spender: String,
    pub amount: String,
}

#[cw_serde]
pub struct AllowancesByOwnerResponse {
    pub symbol: String,
    pub allowances: Vec<AllowanceEntry>,
}

#[cw_serde]
pub struct AllowanceEntry {
    pub spender: String,
    pub amount: String,
}
