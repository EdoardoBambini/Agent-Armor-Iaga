use std::sync::Arc;

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::RwLock;

use super::bus::ArmorEvent;
use crate::core::errors::ArmorError;

type HmacSha256 = Hmac<Sha256>;

/// A registered webhook endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookConfig {
    pub id: String,
    pub url: String,
    #[serde(skip_serializing)]
    pub secret: String,
    /// Filter: only send events matching these types. Empty = send all.
    #[serde(default)]
    pub event_filter: Vec<String>,
    pub created_at: String,
    pub active: bool,
}

/// Manages webhook registrations and delivery.
pub struct WebhookManager {
    hooks: RwLock<Vec<WebhookConfig>>,
    client: reqwest::Client,
}

impl Default for WebhookManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookManager {
    pub fn new() -> Self {
        Self {
            hooks: RwLock::new(Vec::new()),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn register(
        &self,
        url: String,
        secret: String,
        event_filter: Vec<String>,
    ) -> WebhookConfig {
        let config = WebhookConfig {
            id: uuid::Uuid::new_v4().to_string(),
            url,
            secret,
            event_filter,
            created_at: Utc::now().to_rfc3339(),
            active: true,
        };
        self.hooks.write().await.push(config.clone());
        config
    }

    pub async fn unregister(&self, id: &str) -> Result<(), ArmorError> {
        let mut hooks = self.hooks.write().await;
        let before = hooks.len();
        hooks.retain(|h| h.id != id);
        if hooks.len() == before {
            return Err(ArmorError::InvalidRequest(format!(
                "Webhook not found: {id}"
            )));
        }
        Ok(())
    }

    pub async fn list(&self) -> Vec<WebhookConfig> {
        self.hooks.read().await.clone()
    }

    /// Deliver an event to all matching webhooks (fire-and-forget with retries).
    pub async fn deliver(&self, event: &ArmorEvent) {
        let hooks = self.hooks.read().await.clone();
        let event_type = event_type_name(event);

        for hook in hooks {
            if !hook.active {
                continue;
            }
            if !hook.event_filter.is_empty() && !hook.event_filter.contains(&event_type.to_string())
            {
                continue;
            }

            let client = self.client.clone();
            let event = event.clone();
            let hook = hook.clone();

            // Fire-and-forget with retry
            tokio::spawn(async move {
                deliver_with_retry(&client, &hook, &event, 3).await;
            });
        }
    }
}

fn event_type_name(event: &ArmorEvent) -> &'static str {
    match event {
        ArmorEvent::ActionGoverned { .. } => "action_governed",
        ArmorEvent::ReviewCreated { .. } => "review_created",
        ArmorEvent::ReviewResolved { .. } => "review_resolved",
    }
}

fn sign_payload(secret: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

async fn deliver_with_retry(
    client: &reqwest::Client,
    hook: &WebhookConfig,
    event: &ArmorEvent,
    max_retries: u32,
) {
    let payload = match serde_json::to_vec(event) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(webhook_id = %hook.id, error = %e, "Failed to serialize webhook payload");
            return;
        }
    };

    let signature = sign_payload(&hook.secret, &payload);

    for attempt in 0..=max_retries {
        let result = client
            .post(&hook.url)
            .header("Content-Type", "application/json")
            .header("X-Armor-Signature", &signature)
            .header("X-Armor-Event", event_type_name(event))
            .body(payload.clone())
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    webhook_id = %hook.id,
                    status = %resp.status(),
                    "Webhook delivered"
                );
                return;
            }
            Ok(resp) => {
                tracing::warn!(
                    webhook_id = %hook.id,
                    status = %resp.status(),
                    attempt = attempt + 1,
                    "Webhook delivery failed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    webhook_id = %hook.id,
                    error = %e,
                    attempt = attempt + 1,
                    "Webhook delivery error"
                );
            }
        }

        if attempt < max_retries {
            // Exponential backoff: 1s, 2s, 4s
            let delay = std::time::Duration::from_secs(1 << attempt);
            tokio::time::sleep(delay).await;
        }
    }

    tracing::error!(
        webhook_id = %hook.id,
        url = %hook.url,
        "Webhook delivery failed after all retries"
    );
}

/// Stand-alone event bus → webhook bridge.
/// Spawns a background task that reads from the event bus and delivers to webhooks.
pub fn spawn_webhook_worker(bus: super::bus::EventBus, manager: Arc<WebhookManager>) {
    tokio::spawn(async move {
        let mut rx = bus.subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    manager.deliver(&event).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "Webhook worker lagged behind event bus");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::info!("Event bus closed, webhook worker stopping");
                    break;
                }
            }
        }
    });
}
