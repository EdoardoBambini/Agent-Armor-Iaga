use std::env;
use std::sync::Arc;

use agent_armor::config::env::load_env;
use agent_armor::events::bus::EventBus;
use agent_armor::events::webhooks::{self, WebhookManager};
use agent_armor::modules::fingerprint::behavioral::BehavioralEngine;
use agent_armor::modules::rate_limit::limiter::RateLimiter;
use agent_armor::modules::threat_intel::feed::ThreatFeed;
use agent_armor::server::app_state::AppState;
use agent_armor::server::create_server::create_router;
use agent_armor::storage::sqlite::SqliteStorage;
use agent_armor::storage::traits::PolicyStore;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Agent Armor Enterprise Edition starting...");

    let app_env = load_env();
    let db_url =
        env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:agent_armor.db?mode=rwc".into());

    let storage = SqliteStorage::new(&db_url)
        .await
        .expect("Failed to initialize database");
    let storage = Arc::new(storage);

    // Seed demo data if empty
    let profiles = storage.list_profiles().await.unwrap_or_default();
    if profiles.is_empty() {
        tracing::info!("Seeding demo data...");
        use agent_armor::demo::scenarios::{demo_profiles, demo_workspace_policies};
        for p in demo_profiles() {
            if let Err(e) = storage.upsert_profile(&p).await {
                tracing::warn!(agent_id = %p.agent_id, error = %e, "Failed to seed demo profile");
            }
        }
        for w in demo_workspace_policies() {
            if let Err(e) = storage.upsert_workspace(&w).await {
                tracing::warn!(workspace_id = %w.workspace_id, error = %e, "Failed to seed demo workspace");
            }
        }
    }

    let event_bus = EventBus::new(1024);
    let webhook_manager = Arc::new(WebhookManager::new(Arc::new(
        webhooks::DeadLetterQueue::new(),
    )));
    webhooks::spawn_webhook_worker(event_bus.clone(), webhook_manager.clone());

    let state = Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        event_bus,
        webhook_manager,
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(Default::default())),
        threat_feed: Arc::new(ThreatFeed::with_builtin_indicators()),
        env: app_env,
    });

    // Enterprise uses the same community router as base
    // Future: add enterprise-specific routes (SSO, RBAC, SIEM, etc.)
    let router = create_router(state.clone());

    let addr = format!("0.0.0.0:{}", state.env.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    tracing::info!(
        port = state.env.port,
        edition = "enterprise",
        "Agent Armor Enterprise listening"
    );

    axum::serve(listener, router).await.unwrap();
}
