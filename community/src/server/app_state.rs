use std::sync::Arc;

use crate::config::env::AppEnv;
use crate::events::bus::EventBus;
use crate::events::webhooks::WebhookManager;
use crate::modules::fingerprint::behavioral::BehavioralEngine;
use crate::modules::rate_limit::limiter::RateLimiter;
use crate::modules::threat_intel::feed::ThreatFeed;
use crate::storage::traits::*;

pub struct AppState {
    pub audit_store: Arc<dyn AuditStore>,
    pub review_store: Arc<dyn ReviewStore>,
    pub policy_store: Arc<dyn PolicyStore>,
    pub api_key_store: Arc<dyn ApiKeyStore>,
    pub event_bus: EventBus,
    pub webhook_manager: Arc<WebhookManager>,
    pub behavioral_engine: Arc<BehavioralEngine>,
    pub rate_limiter: Arc<RateLimiter>,
    pub threat_feed: Arc<ThreatFeed>,
    pub env: AppEnv,
}
