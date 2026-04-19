use std::sync::Arc;

use crate::config::env::AppEnv;
use crate::events::bus::EventBus;
use crate::events::webhooks::WebhookManager;
use crate::modules::fingerprint::behavioral::BehavioralEngine;
use crate::modules::rate_limit::limiter::RateLimiter;
use crate::modules::threat_intel::feed::ThreatFeed;
use crate::plugins::PluginRegistry;
use crate::storage::traits::*;

pub struct AppState {
    pub audit_store: Arc<dyn AuditStore>,
    pub review_store: Arc<dyn ReviewStore>,
    pub policy_store: Arc<dyn PolicyStore>,
    pub api_key_store: Arc<dyn ApiKeyStore>,
    pub tenant_store: Arc<dyn TenantStore>,
    // v0.4.0 — Durable State stores
    pub nhi_store: Arc<dyn NhiStore>,
    pub session_store: Arc<dyn SessionStore>,
    pub taint_store: Arc<dyn TaintStore>,
    pub fingerprint_store: Arc<dyn FingerprintStore>,
    pub rate_limit_store: Arc<dyn RateLimitStore>,
    pub event_bus: EventBus,
    pub webhook_manager: Arc<WebhookManager>,
    pub behavioral_engine: Arc<BehavioralEngine>,
    pub rate_limiter: Arc<RateLimiter>,
    pub threat_feed: Arc<ThreatFeed>,
    pub plugin_registry: Arc<PluginRegistry>,
    pub storage_backend: StorageBackend,
    pub env: AppEnv,
}
