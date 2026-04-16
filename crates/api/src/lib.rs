mod dashboard;
mod proxy;

use std::sync::Arc;

use axum::{routing::get, Router};
use guardian_agent::GuardianAgent;
use guardian_core::GuardianConfig;
use guardian_notifier::Notifier;

#[derive(Clone)]
pub struct AppState {
    pub config: GuardianConfig,
    pub agent: Arc<GuardianAgent>,
    pub notifier: Arc<Notifier>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/events", get(dashboard::sse_feed))
        .route("/rpc", axum::routing::any(proxy::proxy_handler))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
