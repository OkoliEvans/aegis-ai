use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedAddress {
    pub id: Uuid,
    pub address: String,
    pub label: Option<String>,
    pub owner_address: String,
    pub is_poisoned: bool,
    pub risk_score: i32,
    pub first_seen: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: Uuid,
    pub owner: String,
    pub spender: String,
    pub token_denom: String,
    pub amount: String,
    pub granted_at_height: i64,
    pub revoked: bool,
    pub risk_score: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRiskEvent {
    pub id: Uuid,
    pub address: String,
    pub event_type: String,
    pub severity: String,
    pub tx_hash: Option<String>,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPattern {
    pub address: String,
    pub avg_value_uinit: i64,
    pub typical_recipients: serde_json::Value,
    pub typical_hour_utc: i32,
    pub sample_count: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredUser {
    pub id: Uuid,
    pub address: String,
    pub telegram_chat_id: Option<i64>,
    pub created_at: DateTime<Utc>,
}
