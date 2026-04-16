use std::collections::HashMap;

use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    models::{ApprovalRecord, RegisteredUser, StoredRiskEvent, TxPattern, WatchedAddress},
    types::RiskFinding,
};

#[derive(Debug, Default)]
pub struct GuardianStore {
    watched_addresses: RwLock<HashMap<String, Vec<WatchedAddress>>>,
    approvals: RwLock<HashMap<String, Vec<ApprovalRecord>>>,
    tx_patterns: RwLock<HashMap<String, TxPattern>>,
    registered_users: RwLock<HashMap<String, RegisteredUser>>,
    risk_events: RwLock<Vec<StoredRiskEvent>>,
}

impl GuardianStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn known_addresses(&self, owner: &str) -> Vec<String> {
        self.watched_addresses
            .read()
            .await
            .get(owner)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|entry| entry.address)
            .collect()
    }

    pub async fn tx_pattern(&self, address: &str) -> Option<TxPattern> {
        self.tx_patterns.read().await.get(address).cloned()
    }

    pub async fn upsert_tx_pattern(&self, pattern: TxPattern) {
        self.tx_patterns
            .write()
            .await
            .insert(pattern.address.clone(), pattern);
    }

    pub async fn approval_records(&self, owner: &str) -> Vec<ApprovalRecord> {
        self.approvals
            .read()
            .await
            .get(owner)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn set_approval_records(&self, owner: &str, approvals: Vec<ApprovalRecord>) {
        self.approvals
            .write()
            .await
            .insert(owner.to_string(), approvals);
    }

    pub async fn register_telegram(&self, address: &str, chat_id: i64) {
        let user = RegisteredUser {
            id: Uuid::new_v4(),
            address: address.to_string(),
            telegram_chat_id: Some(chat_id),
            created_at: Utc::now(),
        };
        self.registered_users
            .write()
            .await
            .insert(address.to_string(), user);
    }

    pub async fn telegram_chat_id(&self, address: &str) -> Option<i64> {
        self.registered_users
            .read()
            .await
            .get(address)
            .and_then(|user| user.telegram_chat_id)
    }

    pub async fn store_risk_event(
        &self,
        address: &str,
        finding: &RiskFinding,
        tx_hash: Option<&str>,
    ) {
        self.risk_events.write().await.push(StoredRiskEvent {
            id: Uuid::new_v4(),
            address: address.to_string(),
            event_type: finding.module.clone(),
            severity: finding.severity.as_str().to_string(),
            tx_hash: tx_hash.map(ToOwned::to_owned),
            payload: finding.payload.clone(),
            created_at: Utc::now(),
        });
    }
}
