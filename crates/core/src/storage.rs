use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bb8::Pool;
use chrono::Utc;
use diesel::{delete, insert_into, pg::upsert::excluded, prelude::*, QueryDsl, SelectableHelper};
use diesel_async::{
    pooled_connection::AsyncDieselConnectionManager, AsyncPgConnection, RunQueryDsl,
};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    models::{ApprovalRecord, RegisteredUser, StoredRiskEvent, TxPattern, WatchedAddress},
    schema::{approval_records, registered_users, risk_events, tx_patterns, watched_addresses},
    types::RiskFinding,
};

type PgPool = Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

#[async_trait]
pub trait GuardianRepository: Send + Sync {
    async fn known_addresses(&self, owner: &str) -> Result<Vec<String>>;
    async fn all_watched_addresses(&self) -> Result<Vec<WatchedAddress>>;
    async fn watched_addresses(&self, owner: &str) -> Result<Vec<WatchedAddress>>;
    async fn simulation_target(&self, owner: &str) -> Result<Option<WatchedAddress>>;
    async fn upsert_watched_address(
        &self,
        owner: &str,
        address: &str,
        label: Option<&str>,
        is_simulation_target: bool,
    ) -> Result<WatchedAddress>;
    async fn tx_pattern(&self, address: &str) -> Result<Option<TxPattern>>;
    async fn upsert_tx_pattern(&self, pattern: TxPattern) -> Result<()>;
    async fn approval_records(&self, owner: &str) -> Result<Vec<ApprovalRecord>>;
    async fn set_approval_records(&self, owner: &str, approvals: Vec<ApprovalRecord>)
        -> Result<()>;
    async fn register_email(
        &self,
        address: &str,
        email_address: &str,
        email_display_name: Option<&str>,
    ) -> Result<()>;
    async fn notification_email(&self, address: &str) -> Result<Option<String>>;
    async fn user_profile(&self, address: &str) -> Result<Option<RegisteredUser>>;
    async fn store_risk_event(
        &self,
        address: &str,
        finding: &RiskFinding,
        tx_hash: Option<&str>,
    ) -> Result<()>;
    async fn risk_events(&self, address: &str, limit: i64) -> Result<Vec<StoredRiskEvent>>;
}

pub async fn build_repository(database_url: Option<&str>) -> Result<Arc<dyn GuardianRepository>> {
    let repository: Arc<dyn GuardianRepository> =
        match database_url.filter(|value| !value.is_empty()) {
            Some(url) => Arc::new(PostgresRepository::connect(url).await?),
            None => Arc::new(InMemoryRepository::default()),
        };

    Ok(repository)
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

    async fn all_watched_addresses(&self) -> Result<Vec<WatchedAddress>> {
        Ok(self
            .watched_addresses
            .read()
            .await
            .values()
            .flat_map(|entries| entries.clone())
            .collect())
    }

    async fn watched_addresses(&self, owner: &str) -> Result<Vec<WatchedAddress>> {
        Ok(self
            .watched_addresses
            .read()
            .await
            .get(owner)
            .cloned()
            .unwrap_or_default())
    }

    async fn simulation_target(&self, owner: &str) -> Result<Option<WatchedAddress>> {
        Ok(self
            .watched_addresses
            .read()
            .await
            .get(owner)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.is_simulation_target)
                    .cloned()
            }))
    }

    async fn upsert_watched_address(
        &self,
        owner: &str,
        address: &str,
        label: Option<&str>,
        is_simulation_target: bool,
    ) -> Result<WatchedAddress> {
        let mut watched = self.watched_addresses.write().await;
        let entries = watched.entry(owner.to_string()).or_default();
        if is_simulation_target {
            for entry in entries.iter_mut() {
                entry.is_simulation_target = false;
            }
        }
        if let Some(existing) = entries.iter_mut().find(|entry| entry.address == address) {
            existing.label = label.map(ToOwned::to_owned);
            existing.is_simulation_target = is_simulation_target;
            existing.last_activity = Utc::now();
            return Ok(existing.clone());
        }

        let record = WatchedAddress {
            id: Uuid::new_v4(),
            address: address.to_string(),
            label: label.map(ToOwned::to_owned),
            owner_address: owner.to_string(),
            is_simulation_target,
            is_poisoned: false,
            risk_score: 0,
            first_seen: Utc::now(),
            last_activity: Utc::now(),
        };
        entries.push(record.clone());
        Ok(record)
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

    async fn register_email(
        &self,
        address: &str,
        email_address: &str,
        email_display_name: Option<&str>,
    ) -> Result<()> {
        let user = RegisteredUser {
            id: Uuid::new_v4(),
            address: address.to_string(),
            telegram_chat_id: None,
            telegram_handle: None,
            email_address: Some(email_address.to_string()),
            email_display_name: email_display_name.map(ToOwned::to_owned),
            created_at: Utc::now(),
        };
        self.registered_users
            .write()
            .await
            .insert(address.to_string(), user);
        Ok(())
    }

    async fn notification_email(&self, address: &str) -> Result<Option<String>> {
        Ok(self
            .registered_users
            .read()
            .await
            .get(address)
            .and_then(|user| user.email_address.clone()))
    }

    async fn user_profile(&self, address: &str) -> Result<Option<RegisteredUser>> {
        Ok(self.registered_users.read().await.get(address).cloned())
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

    async fn risk_events(&self, address: &str, limit: i64) -> Result<Vec<StoredRiskEvent>> {
        let mut events = self
            .risk_events
            .read()
            .await
            .iter()
            .filter(|event| event.address == address)
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        events.truncate(limit.max(0) as usize);
        Ok(events)
    }
}

#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pool: PgPool,
}

impl PostgresRepository {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool = Pool::builder()
            .build(manager)
            .await
            .context("failed to connect to postgres with diesel")?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl GuardianRepository for PostgresRepository {
    async fn known_addresses(&self, owner: &str) -> Result<Vec<String>> {
        let mut conn = self.pool.get().await?;
        watched_addresses::table
            .filter(watched_addresses::owner_address.eq(owner))
            .order(watched_addresses::last_activity.desc())
            .select(watched_addresses::address)
            .load(&mut conn)
            .await
            .map_err(Into::into)
    }

    async fn all_watched_addresses(&self) -> Result<Vec<WatchedAddress>> {
        let mut conn = self.pool.get().await?;
        watched_addresses::table
            .order(watched_addresses::last_activity.desc())
            .select(WatchedAddress::as_select())
            .load(&mut conn)
            .await
            .map_err(Into::into)
    }

    async fn watched_addresses(&self, owner: &str) -> Result<Vec<WatchedAddress>> {
        let mut conn = self.pool.get().await?;
        watched_addresses::table
            .filter(watched_addresses::owner_address.eq(owner))
            .order(watched_addresses::last_activity.desc())
            .select(WatchedAddress::as_select())
            .load(&mut conn)
            .await
            .map_err(Into::into)
    }

    async fn simulation_target(&self, owner: &str) -> Result<Option<WatchedAddress>> {
        let mut conn = self.pool.get().await?;
        watched_addresses::table
            .filter(watched_addresses::owner_address.eq(owner))
            .filter(watched_addresses::is_simulation_target.eq(true))
            .order(watched_addresses::last_activity.desc())
            .select(WatchedAddress::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(Into::into)
    }

    async fn upsert_watched_address(
        &self,
        owner: &str,
        address: &str,
        label: Option<&str>,
        is_simulation_target: bool,
    ) -> Result<WatchedAddress> {
        let now = Utc::now();
        let record = WatchedAddress {
            id: Uuid::new_v4(),
            address: address.to_string(),
            label: label.map(ToOwned::to_owned),
            owner_address: owner.to_string(),
            is_simulation_target,
            is_poisoned: false,
            risk_score: 0,
            first_seen: now,
            last_activity: now,
        };

        let mut conn = self.pool.get().await?;
        if is_simulation_target {
            diesel::update(
                watched_addresses::table.filter(watched_addresses::owner_address.eq(owner)),
            )
            .set(watched_addresses::is_simulation_target.eq(false))
            .execute(&mut conn)
            .await?;
        }

        insert_into(watched_addresses::table)
            .values(&record)
            .on_conflict((watched_addresses::owner_address, watched_addresses::address))
            .do_update()
            .set((
                watched_addresses::label.eq(excluded(watched_addresses::label)),
                watched_addresses::is_simulation_target
                    .eq(excluded(watched_addresses::is_simulation_target)),
                watched_addresses::last_activity.eq(excluded(watched_addresses::last_activity)),
            ))
            .returning(WatchedAddress::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(Into::into)
    }

    async fn tx_pattern(&self, address: &str) -> Result<Option<TxPattern>> {
        let mut conn = self.pool.get().await?;
        tx_patterns::table
            .find(address)
            .select(TxPattern::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(Into::into)
    }

    async fn upsert_tx_pattern(&self, pattern: TxPattern) -> Result<()> {
        let mut conn = self.pool.get().await?;
        insert_into(tx_patterns::table)
            .values(&pattern)
            .on_conflict(tx_patterns::address)
            .do_update()
            .set((
                tx_patterns::avg_value_uinit.eq(excluded(tx_patterns::avg_value_uinit)),
                tx_patterns::typical_recipients.eq(excluded(tx_patterns::typical_recipients)),
                tx_patterns::typical_hour_utc.eq(excluded(tx_patterns::typical_hour_utc)),
                tx_patterns::sample_count.eq(excluded(tx_patterns::sample_count)),
                tx_patterns::updated_at.eq(excluded(tx_patterns::updated_at)),
            ))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn approval_records(&self, owner: &str) -> Result<Vec<ApprovalRecord>> {
        let mut conn = self.pool.get().await?;
        approval_records::table
            .filter(approval_records::owner.eq(owner))
            .order(approval_records::created_at.desc())
            .select(ApprovalRecord::as_select())
            .load(&mut conn)
            .await
            .map_err(Into::into)
    }

    async fn set_approval_records(
        &self,
        owner: &str,
        approvals: Vec<ApprovalRecord>,
    ) -> Result<()> {
        let mut conn = self.pool.get().await?;
        delete(approval_records::table.filter(approval_records::owner.eq(owner)))
            .execute(&mut conn)
            .await?;

        if !approvals.is_empty() {
            insert_into(approval_records::table)
                .values(&approvals)
                .execute(&mut conn)
                .await?;
        }

        Ok(())
    }

    async fn register_email(
        &self,
        address: &str,
        email_address: &str,
        email_display_name: Option<&str>,
    ) -> Result<()> {
        let user = RegisteredUser {
            id: Uuid::new_v4(),
            address: address.to_string(),
            telegram_chat_id: None,
            telegram_handle: None,
            email_address: Some(email_address.to_string()),
            email_display_name: email_display_name.map(ToOwned::to_owned),
            created_at: Utc::now(),
        };

        let mut conn = self.pool.get().await?;
        insert_into(registered_users::table)
            .values(&user)
            .on_conflict(registered_users::address)
            .do_update()
            .set((
                registered_users::email_address.eq(email_address),
                registered_users::email_display_name.eq(email_display_name),
            ))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn notification_email(&self, address: &str) -> Result<Option<String>> {
        let mut conn = self.pool.get().await?;
        registered_users::table
            .filter(registered_users::address.eq(address))
            .select(registered_users::email_address)
            .first::<Option<String>>(&mut conn)
            .await
            .optional()
            .map(|value| value.flatten())
            .map_err(Into::into)
    }

    async fn user_profile(&self, address: &str) -> Result<Option<RegisteredUser>> {
        let mut conn = self.pool.get().await?;
        registered_users::table
            .filter(registered_users::address.eq(address))
            .select(RegisteredUser::as_select())
            .first(&mut conn)
            .await
            .optional()
            .map_err(Into::into)
    }

    async fn store_risk_event(
        &self,
        address: &str,
        finding: &RiskFinding,
        tx_hash: Option<&str>,
    ) -> Result<()> {
        let event = StoredRiskEvent {
            id: Uuid::new_v4(),
            address: address.to_string(),
            event_type: finding.module.clone(),
            severity: finding.severity.as_str().to_string(),
            tx_hash: tx_hash.map(ToOwned::to_owned),
            payload: finding.payload.clone(),
            created_at: Utc::now(),
        };

        let mut conn = self.pool.get().await?;
        insert_into(risk_events::table)
            .values(&event)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    async fn risk_events(&self, address: &str, limit: i64) -> Result<Vec<StoredRiskEvent>> {
        let mut conn = self.pool.get().await?;
        risk_events::table
            .filter(risk_events::address.eq(address))
            .order(risk_events::created_at.desc())
            .limit(limit.max(0))
            .select(StoredRiskEvent::as_select())
            .load(&mut conn)
            .await
            .map_err(Into::into)
    }
}
