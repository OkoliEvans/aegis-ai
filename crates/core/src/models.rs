use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::watched_addresses)]
pub struct WatchedAddress {
    pub id: Uuid,
    pub address: String,
    pub label: Option<String>,
    pub owner_address: String,
    pub is_simulation_target: bool,
    pub is_poisoned: bool,
    pub risk_score: i32,
    pub first_seen: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::approval_records)]
pub struct ApprovalRecord {
    pub id: Uuid,
    pub owner: String,
    pub spender: String,
    pub token_denom: String,
    pub amount: String,
    pub granted_at_height: i64,
    pub revoked: bool,
    pub risk_score: i32,
    pub approval_type: Option<String>,
    pub contract_address: Option<String>,
    pub revoke_messages: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::risk_events)]
pub struct StoredRiskEvent {
    pub id: Uuid,
    pub address: String,
    pub event_type: String,
    pub severity: String,
    pub tx_hash: Option<String>,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::tx_patterns)]
pub struct TxPattern {
    pub address: String,
    pub avg_value_uinit: i64,
    pub typical_recipients: serde_json::Value,
    pub typical_hour_utc: i32,
    pub sample_count: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::registered_users)]
pub struct RegisteredUser {
    pub id: Uuid,
    pub address: String,
    pub telegram_chat_id: Option<i64>,
    pub telegram_handle: Option<String>,
    pub email_address: Option<String>,
    pub email_display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}
