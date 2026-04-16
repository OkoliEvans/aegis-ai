use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;
use tokio_postgres::{Client, NoTls, Row};
use uuid::Uuid;

use crate::{
    models::{ApprovalRecord, RegisteredUser, StoredRiskEvent, TxPattern, WatchedAddress},
    types::RiskFinding,
};

#[async_trait]
pub trait GuardianRepository: Send + Sync {
    async fn known_addresses(&self, owner: &str) -> Result<Vec<String>>;
    async fn tx_pattern(&self, address: &str) -> Result<Option<TxPattern>>;
    async fn upsert_tx_pattern(&self, pattern: TxPattern) -> Result<()>;
    async fn approval_records(&self, owner: &str) -> Result<Vec<ApprovalRecord>>;
    async fn set_approval_records(&self, owner: &str, approvals: Vec<ApprovalRecord>)
        -> Result<()>;
    async fn register_telegram(&self, address: &str, chat_id: i64) -> Result<()>;
    async fn telegram_chat_id(&self, address: &str) -> Result<Option<i64>>;
    async fn store_risk_event(
        &self,
        address: &str,
        finding: &RiskFinding,
        tx_hash: Option<&str>,
    ) -> Result<()>;
}

pub async fn build_repository(database_url: Option<&str>) -> Result<Arc<dyn GuardianRepository>> {
    match database_url.filter(|value| !value.is_empty()) {
        Some(url) => Ok(Arc::new(PostgresRepository::connect(url).await?)),
        None => Ok(Arc::new(InMemoryRepository::default())),
    }
}

#[derive(Debug, Default)]
pub struct InMemoryRepository {
    watched_addresses: RwLock<HashMap<String, Vec<WatchedAddress>>>,
    approvals: RwLock<HashMap<String, Vec<ApprovalRecord>>>,
    tx_patterns: RwLock<HashMap<String, TxPattern>>,
    registered_users: RwLock<HashMap<String, RegisteredUser>>,
    risk_events: RwLock<Vec<StoredRiskEvent>>,
}

#[async_trait]
impl GuardianRepository for InMemoryRepository {
    async fn known_addresses(&self, owner: &str) -> Result<Vec<String>> {
        Ok(self
            .watched_addresses
            .read()
            .await
            .get(owner)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|entry| entry.address)
            .collect())
    }

    async fn tx_pattern(&self, address: &str) -> Result<Option<TxPattern>> {
        Ok(self.tx_patterns.read().await.get(address).cloned())
    }

    async fn upsert_tx_pattern(&self, pattern: TxPattern) -> Result<()> {
        self.tx_patterns
            .write()
            .await
            .insert(pattern.address.clone(), pattern);
        Ok(())
    }

    async fn approval_records(&self, owner: &str) -> Result<Vec<ApprovalRecord>> {
        Ok(self
            .approvals
            .read()
            .await
            .get(owner)
            .cloned()
            .unwrap_or_default())
    }

    async fn set_approval_records(
        &self,
        owner: &str,
        approvals: Vec<ApprovalRecord>,
    ) -> Result<()> {
        self.approvals
            .write()
            .await
            .insert(owner.to_string(), approvals);
        Ok(())
    }

    async fn register_telegram(&self, address: &str, chat_id: i64) -> Result<()> {
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
        Ok(())
    }

    async fn telegram_chat_id(&self, address: &str) -> Result<Option<i64>> {
        Ok(self
            .registered_users
            .read()
            .await
            .get(address)
            .and_then(|user| user.telegram_chat_id))
    }

    async fn store_risk_event(
        &self,
        address: &str,
        finding: &RiskFinding,
        tx_hash: Option<&str>,
    ) -> Result<()> {
        self.risk_events.write().await.push(StoredRiskEvent {
            id: Uuid::new_v4(),
            address: address.to_string(),
            event_type: finding.module.clone(),
            severity: finding.severity.as_str().to_string(),
            tx_hash: tx_hash.map(ToOwned::to_owned),
            payload: finding.payload.clone(),
            created_at: Utc::now(),
        });
        Ok(())
    }
}

#[derive(Debug)]
pub struct PostgresRepository {
    client: Client,
}

impl PostgresRepository {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .context("failed to connect to postgres")?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!(?error, "postgres connection terminated");
            }
        });
        Ok(Self { client })
    }
}

#[async_trait]
impl GuardianRepository for PostgresRepository {
    async fn known_addresses(&self, owner: &str) -> Result<Vec<String>> {
        let rows = self
            .client
            .query(
                "SELECT address FROM watched_addresses WHERE owner_address = $1 ORDER BY last_activity DESC",
                &[&owner],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect())
    }

    async fn tx_pattern(&self, address: &str) -> Result<Option<TxPattern>> {
        let row = self
            .client
            .query_opt(
                "SELECT address, avg_value_uinit, typical_recipients, typical_hour_utc, sample_count, updated_at
                 FROM tx_patterns WHERE address = $1",
                &[&address],
            )
            .await?;
        Ok(row.map(map_tx_pattern))
    }

    async fn upsert_tx_pattern(&self, pattern: TxPattern) -> Result<()> {
        self.client
            .execute(
                "INSERT INTO tx_patterns (address, avg_value_uinit, typical_recipients, typical_hour_utc, sample_count, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (address) DO UPDATE SET
                   avg_value_uinit = EXCLUDED.avg_value_uinit,
                   typical_recipients = EXCLUDED.typical_recipients,
                   typical_hour_utc = EXCLUDED.typical_hour_utc,
                   sample_count = EXCLUDED.sample_count,
                   updated_at = EXCLUDED.updated_at",
                &[
                    &pattern.address,
                    &pattern.avg_value_uinit,
                    &pattern.typical_recipients,
                    &pattern.typical_hour_utc,
                    &pattern.sample_count,
                    &pattern.updated_at,
                ],
            )
            .await?;
        Ok(())
    }

    async fn approval_records(&self, owner: &str) -> Result<Vec<ApprovalRecord>> {
        let rows = self
            .client
            .query(
                "SELECT id, owner, spender, token_denom, amount, granted_at_height, revoked, risk_score, created_at
                 FROM approval_records WHERE owner = $1 ORDER BY created_at DESC",
                &[&owner],
            )
            .await?;
        Ok(rows.into_iter().map(map_approval_record).collect())
    }

    async fn set_approval_records(
        &self,
        owner: &str,
        approvals: Vec<ApprovalRecord>,
    ) -> Result<()> {
        self.client
            .execute("DELETE FROM approval_records WHERE owner = $1", &[&owner])
            .await?;
        for approval in approvals {
            self.client
                .execute(
                    "INSERT INTO approval_records
                     (id, owner, spender, token_denom, amount, granted_at_height, revoked, risk_score, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    &[
                        &approval.id,
                        &approval.owner,
                        &approval.spender,
                        &approval.token_denom,
                        &approval.amount,
                        &approval.granted_at_height,
                        &approval.revoked,
                        &approval.risk_score,
                        &approval.created_at,
                    ],
                )
                .await?;
        }
        Ok(())
    }

    async fn register_telegram(&self, address: &str, chat_id: i64) -> Result<()> {
        self.client
            .execute(
                "INSERT INTO registered_users (id, address, telegram_chat_id, created_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (address) DO UPDATE SET telegram_chat_id = EXCLUDED.telegram_chat_id",
                &[&Uuid::new_v4(), &address, &chat_id, &Utc::now()],
            )
            .await?;
        Ok(())
    }

    async fn telegram_chat_id(&self, address: &str) -> Result<Option<i64>> {
        Ok(self
            .client
            .query_opt(
                "SELECT telegram_chat_id FROM registered_users WHERE address = $1",
                &[&address],
            )
            .await?
            .and_then(|row| row.get::<_, Option<i64>>(0)))
    }

    async fn store_risk_event(
        &self,
        address: &str,
        finding: &RiskFinding,
        tx_hash: Option<&str>,
    ) -> Result<()> {
        self.client
            .execute(
                "INSERT INTO risk_events (id, address, event_type, severity, tx_hash, payload, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &Uuid::new_v4(),
                    &address,
                    &finding.module,
                    &finding.severity.as_str(),
                    &tx_hash.map(ToOwned::to_owned),
                    &finding.payload,
                    &Utc::now(),
                ],
            )
            .await?;
        Ok(())
    }
}

fn map_tx_pattern(row: Row) -> TxPattern {
    TxPattern {
        address: row.get("address"),
        avg_value_uinit: row.get("avg_value_uinit"),
        typical_recipients: row.get("typical_recipients"),
        typical_hour_utc: row.get("typical_hour_utc"),
        sample_count: row.get("sample_count"),
        updated_at: row.get("updated_at"),
    }
}

fn map_approval_record(row: Row) -> ApprovalRecord {
    ApprovalRecord {
        id: row.get("id"),
        owner: row.get("owner"),
        spender: row.get("spender"),
        token_denom: row.get("token_denom"),
        amount: row.get("amount"),
        granted_at_height: row.get("granted_at_height"),
        revoked: row.get("revoked"),
        risk_score: row.get("risk_score"),
        created_at: row.get("created_at"),
    }
}
