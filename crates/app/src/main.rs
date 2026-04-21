use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::Result;
use diesel::{pg::PgConnection, Connection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use guardian_agent::GuardianAgent;
use guardian_analyzer::dust;
use guardian_api::{build_router, AppState};
use guardian_core::{
    build_repository, models::ApprovalRecord, GuardianConfig, RiskFinding, Severity,
};
use guardian_monitor::stream_events;
use guardian_notifier::Notifier;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");
const APPROVAL_SCAN_INTERVAL_SECS: u64 = 86_400;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "guardian_app=info,guardian_agent=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = GuardianConfig::from_env()?;
    if std::env::args().any(|arg| arg == "migrate") {
        run_migrations(config.database_url.as_deref())?;
        info!("database migrations completed");
        return Ok(());
    }

    let bind_addr = config.bind_addr()?;
    let repository = build_repository(config.database_url.as_deref()).await?;
    let notifier = Arc::new(Notifier::new(&config, repository.clone()));
    let agent = Arc::new(GuardianAgent::new(config.clone(), repository.clone()));

    let state = AppState {
        config: config.clone(),
        agent,
        notifier,
        repository,
    };

    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("guardian listening on {}", bind_addr);

    let (tx, mut rx) = mpsc::channel(128);
    let ws_url = config.initia_ws.clone();
    tokio::spawn(async move {
        if let Err(error) = stream_events(&ws_url, tx).await {
            error!(?error, "monitor task terminated");
        }
    });

    let repository = state.repository.clone();
    let notifier = state.notifier.clone();
    let known_protocols = config.known_protocols.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            info!(
                tx_hash = %event.tx_hash,
                sender = %event.sender,
                height = event.height,
                "observed chain event"
            );

            let watched_addresses = match repository.all_watched_addresses().await {
                Ok(addresses) => addresses,
                Err(error) => {
                    error!(?error, "failed to load watched addresses for dust analysis");
                    continue;
                }
            };

            let findings = dust::detect_dust_events(&event, &watched_addresses, &known_protocols);
            for (owner, finding) in findings {
                notifier
                    .notify_security_update(
                        &owner,
                        &[finding],
                        Some(&event.tx_hash),
                        "Dust monitoring",
                    )
                    .await;
            }
        }
    });

    let repository = state.repository.clone();
    let notifier = state.notifier.clone();
    let config_for_scanner = config.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(APPROVAL_SCAN_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;

            let watched_addresses = match repository.all_watched_addresses().await {
                Ok(addresses) => addresses,
                Err(error) => {
                    error!(?error, "failed to load watched addresses for approval scan");
                    continue;
                }
            };

            let current_height = current_height(&config_for_scanner.initia_rpc).await;
            let mut scanned = HashSet::new();

            for watched in watched_addresses {
                if !scanned.insert(watched.address.clone()) {
                    continue;
                }

                let approvals = match guardian_analyzer::approvals::scan_approvals(
                    &config_for_scanner.initia_lcd,
                    &watched.address,
                )
                .await
                {
                    Ok(approvals) => approvals,
                    Err(error) if guardian_analyzer::approvals::scan_is_unavailable(&error) => {
                        match repository.approval_records(&watched.address).await {
                            Ok(approvals) => approvals,
                            Err(repo_error) => {
                                error!(
                                    ?repo_error,
                                    address = %watched.address,
                                    "approval scan unavailable and stored approvals could not be loaded"
                                );
                                continue;
                            }
                        }
                    }
                    Err(error) => {
                        error!(
                            ?error,
                            address = %watched.address,
                            "background approval scan failed"
                        );
                        continue;
                    }
                };

                let mut approvals = approvals;
                let flagged = approvals
                    .iter_mut()
                    .filter_map(|approval| {
                        let score = guardian_analyzer::approvals::score_approval(
                            approval,
                            current_height,
                            &config_for_scanner.known_protocols,
                        );
                        approval.risk_score = score;
                        (score >= 50).then_some((approval.spender.clone(), score))
                    })
                    .collect::<Vec<_>>();

                if let Err(error) = repository
                    .set_approval_records(&watched.address, approvals.clone())
                    .await
                {
                    error!(
                        ?error,
                        address = %watched.address,
                        "failed to persist scored approvals"
                    );
                    continue;
                }

                if !flagged.is_empty() {
                    let summary = approval_review_finding(&watched.address, &approvals, &flagged);
                    notifier
                        .notify_approval_review(&watched.address, &[summary], None, flagged.len())
                        .await;
                    info!(
                        address = %watched.address,
                        flagged_approvals = flagged.len(),
                        "background approval scan refreshed risky approvals"
                    );
                }
            }
        }
    });

    axum::serve(listener, app).await?;
    Ok(())
}

fn approval_review_finding(
    owner: &str,
    approvals: &[ApprovalRecord],
    flagged: &[(String, i32)],
) -> RiskFinding {
    let highest_score = flagged
        .iter()
        .map(|(_, score)| *score)
        .max()
        .unwrap_or_default();
    let leading = flagged
        .first()
        .map(|(spender, _)| spender.as_str())
        .unwrap_or("unknown");
    let flagged_details = approvals
        .iter()
        .filter(|approval| approval.risk_score >= 50)
        .take(5)
        .map(|approval| {
            serde_json::json!({
                "spender": approval.spender,
                "score": approval.risk_score,
                "amount": approval.amount,
                "token_denom": approval.token_denom,
                "contract_address": approval.contract_address,
                "approval_type": approval.approval_type,
            })
        })
        .collect::<Vec<_>>();

    RiskFinding {
        module: "approval_review".to_string(),
        severity: if highest_score >= 80 {
            Severity::High
        } else {
            Severity::Medium
        },
        weight: highest_score,
        description: format!(
            "Guardian found {} approval{} that should be reviewed, led by spender {}",
            flagged.len(),
            if flagged.len() == 1 { "" } else { "s" },
            leading
        ),
        payload: serde_json::json!({
            "owner": owner,
            "flagged_approvals": flagged_details,
            "count": flagged.len(),
        }),
    }
}

async fn current_height(rpc_url: &str) -> i64 {
    let endpoint = format!("{}/status", rpc_url.trim_end_matches('/'));
    match reqwest::Client::new().get(endpoint).send().await {
        Ok(response) => {
            let body: serde_json::Value = match response.json().await {
                Ok(body) => body,
                Err(_) => return 0,
            };
            body.pointer("/result/sync_info/latest_block_height")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_default()
        }
        Err(_) => 0,
    }
}

fn run_migrations(database_url: Option<&str>) -> Result<()> {
    let database_url = database_url
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL must be set to run migrations"))?;
    let mut connection = PgConnection::establish(database_url)?;
    connection
        .run_pending_migrations(MIGRATIONS)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(())
}
