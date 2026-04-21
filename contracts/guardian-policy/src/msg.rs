use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    UpdatePolicy {
        warn_threshold: u8,
        confirm_threshold: u8,
        block_threshold: u8,
        trusted_contracts: Vec<String>,
        trusted_recipients: Vec<String>,
        auto_block_new_contracts: bool,
    },
    SetReporter {
        reporter: String,
        enabled: bool,
    },
    SetTrustedContract {
        address: String,
        trusted: bool,
    },
    QuarantineAddress {
        owner: String,
        address: String,
        reason: String,
        risk_score: u8,
    },
    ClearQuarantine {
        owner: String,
        address: String,
    },
    RecordIncident {
        owner: String,
        event_type: String,
        severity: String,
        tx_hash: Option<String>,
        summary: String,
        details_json: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    GetConfig {},
    #[returns(PolicyResponse)]
    GetPolicy { owner: String },
    #[returns(IncidentListResponse)]
    ListIncidents {
        owner: String,
        start_after: Option<u64>,
        limit: Option<u32>,
    },
    #[returns(QuarantineResponse)]
    GetQuarantine { owner: String, address: String },
    #[returns(QuarantineListResponse)]
    ListQuarantined {
        owner: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(TrustedContractResponse)]
    IsTrustedContract { address: String },
    #[returns(TrustedContractListResponse)]
    ListTrustedContracts {
        start_after: Option<String>,
        limit: Option<u32>,
    },
}

#[cw_serde]
pub struct ConfigResponse {
    pub admin: String,
    pub reporters: Vec<String>,
}

#[cw_serde]
pub struct PolicyResponse {
    pub policy: Option<PolicyView>,
}

#[cw_serde]
pub struct PolicyView {
    pub owner: String,
    pub warn_threshold: u8,
    pub confirm_threshold: u8,
    pub block_threshold: u8,
    pub trusted_contracts: Vec<String>,
    pub trusted_recipients: Vec<String>,
    pub auto_block_new_contracts: bool,
    pub updated_at: u64,
}

#[cw_serde]
pub struct IncidentListResponse {
    pub incidents: Vec<IncidentView>,
}

#[cw_serde]
pub struct IncidentView {
    pub id: u64,
    pub owner: String,
    pub reporter: String,
    pub event_type: String,
    pub severity: String,
    pub tx_hash: Option<String>,
    pub summary: String,
    pub details_json: String,
    pub created_at: u64,
}

#[cw_serde]
pub struct QuarantineResponse {
    pub entry: Option<QuarantineView>,
}

#[cw_serde]
pub struct QuarantineListResponse {
    pub entries: Vec<QuarantineView>,
}

#[cw_serde]
pub struct QuarantineView {
    pub owner: String,
    pub address: String,
    pub reason: String,
    pub risk_score: u8,
    pub quarantined_at: u64,
}

#[cw_serde]
pub struct TrustedContractResponse {
    pub address: String,
    pub trusted: bool,
}

#[cw_serde]
pub struct TrustedContractListResponse {
    pub entries: Vec<TrustedContractEntry>,
}

#[cw_serde]
pub struct TrustedContractEntry {
    pub address: String,
    pub trusted: bool,
}
