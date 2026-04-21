mod dashboard;
mod proxy;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use guardian_agent::GuardianAgent;
use guardian_core::{GuardianConfig, GuardianRepository};
use guardian_notifier::Notifier;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct AppState {
    pub config: GuardianConfig,
    pub agent: Arc<GuardianAgent>,
    pub notifier: Arc<Notifier>,
    pub repository: Arc<dyn GuardianRepository>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/events", get(dashboard::sse_feed))
        .route("/api/approvals/:owner", get(dashboard::list_approvals))
        .route(
            "/api/approval-actions/revoke-plan",
            post(dashboard::revoke_approval_plan),
        )
        .route(
            "/api/risk-events/:address",
            get(dashboard::list_risk_events),
        )
        .route(
            "/api/watched-addresses/:owner",
            get(dashboard::list_watched_addresses),
        )
        .route("/api/profile/:address", get(dashboard::get_user_profile))
        .route("/api/policy/:owner", get(dashboard::get_policy_overview))
        .route(
            "/api/watched-addresses",
            post(dashboard::upsert_watched_address),
        )
        .route(
            "/api/demo/risk-lab/preview",
            post(dashboard::preview_risk_lab_contract),
        )
        .route("/api/simulations/run", post(dashboard::run_simulation))
        .route("/api/email/register", post(dashboard::register_email))
        .route("/api/email/test", post(dashboard::send_test_email))
        .route("/rpc", axum::routing::any(proxy::proxy_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        )
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
