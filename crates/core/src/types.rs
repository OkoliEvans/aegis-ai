use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEvent {
    pub tx_hash: String,
    pub sender: String,
    pub height: i64,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingTx {
    pub sender: String,
    pub recipient: String,
    pub amount: String,
    pub denom: String,
    pub contract_address: Option<String>,
    pub function_name: Option<String>,
    pub contract_msg: Option<serde_json::Value>,
    pub controller_chain: Option<String>,
    pub message_type: Option<String>,
    pub raw_bytes: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

impl IncomingTx {
    pub fn hour_utc(&self) -> i32 {
        self.timestamp.hour() as i32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceDelta {
    pub address: String,
    pub denom: String,
    pub delta: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapExecutionInsight {
    pub offered_amount: Option<i128>,
    pub return_amount: Option<i128>,
    pub spread_amount: Option<i128>,
    pub commission_amount: Option<i128>,
    pub offer_pool: Option<i128>,
    pub ask_pool: Option<i128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub will_fail: bool,
    pub fail_reason: Option<String>,
    pub gas_estimate: u64,
    pub balance_deltas: Vec<BalanceDelta>,
    pub observed_actions: Vec<String>,
    pub touched_contracts: Vec<String>,
    pub swap_execution: Option<SwapExecutionInsight>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub module: String,
    pub severity: Severity,
    pub weight: i32,
    pub description: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum GuardianDecision {
    Allow,
    Warn {
        findings: Vec<RiskFinding>,
    },
    Confirm {
        findings: Vec<RiskFinding>,
    },
    Block {
        findings: Vec<RiskFinding>,
        auto_revoke: bool,
    },
}
