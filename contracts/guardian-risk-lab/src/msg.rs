use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<String>,
    pub label: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    ExecuteAttack {
        callback: String,
        note: Option<String>,
    },
    DrainThenCall {
        receiver: String,
        callback: String,
    },
    UpdateAdminScenario {
        new_admin: String,
    },
    Ping {},
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ProfileResponse)]
    Profile {},
}

#[cw_serde]
pub struct ProfileResponse {
    pub admin: String,
    pub label: String,
    pub created_at: u64,
}
