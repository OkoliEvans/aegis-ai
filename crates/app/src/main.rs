use std::sync::Arc;

use anyhow::Result;
use guardian_agent::GuardianAgent;
use guardian_api::{build_router, AppState};
use guardian_core::{GuardianConfig, GuardianStore};
use guardian_monitor::stream_events;
use guardian_notifier::Notifier;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    let bind_addr = config.bind_addr()?;
    let store = Arc::new(GuardianStore::new());
    let notifier = Arc::new(Notifier::new(
        config.telegram_bot_token.as_deref(),
        store.clone(),
    ));
    let agent = Arc::new(GuardianAgent::new(config.clone(), store));

    let state = AppState {
        config: config.clone(),
        agent,
        notifier,
    };

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("guardian listening on {}", bind_addr);

    let (tx, mut rx) = mpsc::channel(128);
    let ws_url = config.initia_ws.clone();
    tokio::spawn(async move {
        if let Err(error) = stream_events(&ws_url, tx).await {
            error!(?error, "monitor task terminated");
        }
    });

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            info!(
                tx_hash = %event.tx_hash,
                sender = %event.sender,
                height = event.height,
                "observed chain event"
            );
        }
    });

    axum::serve(listener, app).await?;
    Ok(())
}
