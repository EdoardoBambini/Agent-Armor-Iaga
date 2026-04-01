use async_trait::async_trait;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use super::traits::*;
use crate::core::errors::ArmorError;
use crate::core::types::*;

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn new(database_url: &str) -> Result<Self, ArmorError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| ArmorError::Storage(format!("Failed to connect to SQLite: {e}")))?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    async fn run_migrations(&self) -> Result<(), ArmorError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                framework TEXT NOT NULL,
                action_type TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                review_status TEXT NOT NULL,
                reasons TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS review_requests (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                risk_score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS agent_profiles (
                agent_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                framework TEXT NOT NULL,
                role TEXT NOT NULL,
                approved_tools TEXT NOT NULL,
                approved_secrets TEXT NOT NULL,
                baseline_action_types TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS workspace_policies (
                workspace_id TEXT PRIMARY KEY,
                allowed_protocols TEXT NOT NULL,
                allowed_domains TEXT NOT NULL,
                tools TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL DEFAULT '',
                label TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&self.pool)
        .await?;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_review_status ON review_requests(status)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

// ── AuditStore ──

#[async_trait]
impl AuditStore for SqliteStorage {
    async fn append(&self, event: &StoredAuditEvent) -> Result<(), ArmorError> {
        let reasons = serde_json::to_string(&event.reasons).unwrap_or_default();
        let decision = serde_json::to_value(event.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("allow")
            .to_string();
        let action_type = serde_json::to_value(event.action_type)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("custom")
            .to_string();
        let review_status = serde_json::to_value(event.review_status)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("not_required")
            .to_string();

        sqlx::query(
            "INSERT INTO audit_events (event_id, agent_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&event.event_id)
        .bind(&event.agent_id)
        .bind(&event.framework)
        .bind(&action_type)
        .bind(&event.tool_name)
        .bind(&decision)
        .bind(event.risk_score as i64)
        .bind(&review_status)
        .bind(&reasons)
        .bind(&event.timestamp)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list(&self, limit: u32) -> Result<Vec<StoredAuditEvent>, ArmorError> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT event_id, agent_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp
             FROM audit_events ORDER BY created_at DESC LIMIT ?"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_stored()).collect())
    }
}

struct AuditRow {
    event_id: String,
    agent_id: String,
    framework: String,
    action_type: String,
    tool_name: String,
    decision: String,
    risk_score: i64,
    review_status: String,
    reasons: String,
    timestamp: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for AuditRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            event_id: row.try_get("event_id")?,
            agent_id: row.try_get("agent_id")?,
            framework: row.try_get("framework")?,
            action_type: row.try_get("action_type")?,
            tool_name: row.try_get("tool_name")?,
            decision: row.try_get("decision")?,
            risk_score: row.try_get("risk_score")?,
            review_status: row.try_get("review_status")?,
            reasons: row.try_get("reasons")?,
            timestamp: row.try_get("timestamp")?,
        })
    }
}

impl AuditRow {
    fn into_stored(self) -> StoredAuditEvent {
        StoredAuditEvent {
            event_id: self.event_id,
            agent_id: self.agent_id,
            framework: self.framework,
            action_type: serde_json::from_value(serde_json::Value::String(self.action_type))
                .unwrap_or(ActionType::Custom),
            tool_name: self.tool_name,
            decision: serde_json::from_value(serde_json::Value::String(self.decision))
                .unwrap_or(GovernanceDecision::Block),
            risk_score: self.risk_score as u32,
            review_status: serde_json::from_value(serde_json::Value::String(self.review_status))
                .unwrap_or(ReviewStatus::NotRequired),
            reasons: serde_json::from_str(&self.reasons).unwrap_or_default(),
            timestamp: self.timestamp,
        }
    }
}

// ── ReviewStore ──

#[async_trait]
impl ReviewStore for SqliteStorage {
    async fn create(&self, review: &ReviewRequest) -> Result<(), ArmorError> {
        let reasons = serde_json::to_string(&review.reasons).unwrap_or_default();
        let decision = serde_json::to_value(review.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("review")
            .to_string();

        sqlx::query(
            "INSERT INTO review_requests (id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&review.id)
        .bind(&review.agent_id)
        .bind(&review.workspace_id)
        .bind(&review.tool_name)
        .bind(&decision)
        .bind(&review.status)
        .bind(review.risk_score as i64)
        .bind(&reasons)
        .bind(&review.created_at)
        .bind(&review.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get(&self, id: &str) -> Result<ReviewRequest, ArmorError> {
        let row = sqlx::query_as::<_, ReviewRow>(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at
             FROM review_requests WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ArmorError::ReviewNotFound(id.to_string()))?;

        Ok(row.into_review())
    }

    async fn update_status(&self, id: &str, status: &str) -> Result<ReviewRequest, ArmorError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE review_requests SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        self.get(id).await
    }

    async fn list(&self) -> Result<Vec<ReviewRequest>, ArmorError> {
        let rows = sqlx::query_as::<_, ReviewRow>(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at
             FROM review_requests ORDER BY created_at ASC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_review()).collect())
    }
}

struct ReviewRow {
    id: String,
    agent_id: String,
    workspace_id: String,
    tool_name: String,
    decision: String,
    status: String,
    risk_score: i64,
    reasons: String,
    created_at: String,
    updated_at: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ReviewRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            agent_id: row.try_get("agent_id")?,
            workspace_id: row.try_get("workspace_id")?,
            tool_name: row.try_get("tool_name")?,
            decision: row.try_get("decision")?,
            status: row.try_get("status")?,
            risk_score: row.try_get("risk_score")?,
            reasons: row.try_get("reasons")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl ReviewRow {
    fn into_review(self) -> ReviewRequest {
        ReviewRequest {
            id: self.id,
            agent_id: self.agent_id,
            workspace_id: self.workspace_id,
            tool_name: self.tool_name,
            decision: serde_json::from_value(serde_json::Value::String(self.decision))
                .unwrap_or(GovernanceDecision::Review),
            status: self.status,
            risk_score: self.risk_score as u32,
            reasons: serde_json::from_str(&self.reasons).unwrap_or_default(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ── PolicyStore ──

#[async_trait]
impl PolicyStore for SqliteStorage {
    async fn get_agent_profile(&self, agent_id: &str) -> Result<AgentProfile, ArmorError> {
        let row = sqlx::query_as::<_, ProfileRow>(
            "SELECT agent_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types
             FROM agent_profiles WHERE agent_id = ?"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ArmorError::AgentNotFound(agent_id.to_string()))?;

        Ok(row.into_profile())
    }

    async fn get_workspace_policy(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspacePolicy, ArmorError> {
        let row = sqlx::query_as::<_, WorkspaceRow>(
            "SELECT workspace_id, allowed_protocols, allowed_domains, tools
             FROM workspace_policies WHERE workspace_id = ?",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ArmorError::WorkspaceNotFound(workspace_id.to_string()))?;

        Ok(row.into_policy())
    }

    async fn list_profiles(&self) -> Result<Vec<AgentProfile>, ArmorError> {
        let rows = sqlx::query_as::<_, ProfileRow>(
            "SELECT agent_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types
             FROM agent_profiles ORDER BY agent_id"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_profile()).collect())
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspacePolicy>, ArmorError> {
        let rows = sqlx::query_as::<_, WorkspaceRow>(
            "SELECT workspace_id, allowed_protocols, allowed_domains, tools
             FROM workspace_policies ORDER BY workspace_id",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_policy()).collect())
    }

    async fn upsert_profile(&self, profile: &AgentProfile) -> Result<(), ArmorError> {
        let tools = serde_json::to_string(&profile.approved_tools).unwrap_or_default();
        let secrets = serde_json::to_string(&profile.approved_secrets).unwrap_or_default();
        let baselines = serde_json::to_string(&profile.baseline_action_types).unwrap_or_default();
        let role = serde_json::to_value(profile.role)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("builder")
            .to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO agent_profiles (agent_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                framework = excluded.framework,
                role = excluded.role,
                approved_tools = excluded.approved_tools,
                approved_secrets = excluded.approved_secrets,
                baseline_action_types = excluded.baseline_action_types,
                updated_at = excluded.updated_at"
        )
        .bind(&profile.agent_id)
        .bind(&profile.workspace_id)
        .bind(&profile.framework)
        .bind(&role)
        .bind(&tools)
        .bind(&secrets)
        .bind(&baselines)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_workspace(&self, policy: &WorkspacePolicy) -> Result<(), ArmorError> {
        let protocols = serde_json::to_string(&policy.allowed_protocols).unwrap_or_default();
        let domains = serde_json::to_string(&policy.allowed_domains).unwrap_or_default();
        let tools = serde_json::to_string(&policy.tools).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO workspace_policies (workspace_id, allowed_protocols, allowed_domains, tools, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id) DO UPDATE SET
                allowed_protocols = excluded.allowed_protocols,
                allowed_domains = excluded.allowed_domains,
                tools = excluded.tools,
                updated_at = excluded.updated_at"
        )
        .bind(&policy.workspace_id)
        .bind(&protocols)
        .bind(&domains)
        .bind(&tools)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_profile(&self, agent_id: &str) -> Result<(), ArmorError> {
        sqlx::query("DELETE FROM agent_profiles WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_workspace(&self, workspace_id: &str) -> Result<(), ArmorError> {
        sqlx::query("DELETE FROM workspace_policies WHERE workspace_id = ?")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

struct ProfileRow {
    agent_id: String,
    workspace_id: String,
    framework: String,
    role: String,
    approved_tools: String,
    approved_secrets: String,
    baseline_action_types: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ProfileRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            agent_id: row.try_get("agent_id")?,
            workspace_id: row.try_get("workspace_id")?,
            framework: row.try_get("framework")?,
            role: row.try_get("role")?,
            approved_tools: row.try_get("approved_tools")?,
            approved_secrets: row.try_get("approved_secrets")?,
            baseline_action_types: row.try_get("baseline_action_types")?,
        })
    }
}

impl ProfileRow {
    fn into_profile(self) -> AgentProfile {
        AgentProfile {
            agent_id: self.agent_id,
            workspace_id: self.workspace_id,
            framework: self.framework,
            role: serde_json::from_value(serde_json::Value::String(self.role))
                .unwrap_or(AgentRole::Builder),
            approved_tools: serde_json::from_str(&self.approved_tools).unwrap_or_default(),
            approved_secrets: serde_json::from_str(&self.approved_secrets).unwrap_or_default(),
            baseline_action_types: serde_json::from_str(&self.baseline_action_types)
                .unwrap_or_default(),
            tool_trust: 0.7,
        }
    }
}

struct WorkspaceRow {
    workspace_id: String,
    allowed_protocols: String,
    allowed_domains: String,
    tools: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for WorkspaceRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            workspace_id: row.try_get("workspace_id")?,
            allowed_protocols: row.try_get("allowed_protocols")?,
            allowed_domains: row.try_get("allowed_domains")?,
            tools: row.try_get("tools")?,
        })
    }
}

impl WorkspaceRow {
    fn into_policy(self) -> WorkspacePolicy {
        WorkspacePolicy {
            workspace_id: self.workspace_id,
            allowed_protocols: serde_json::from_str(&self.allowed_protocols).unwrap_or_default(),
            allowed_domains: serde_json::from_str(&self.allowed_domains).unwrap_or_default(),
            tools: serde_json::from_str(&self.tools).unwrap_or_default(),
        }
    }
}

// ── ApiKeyStore ──

#[async_trait]
impl ApiKeyStore for SqliteStorage {
    async fn store_key(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
    ) -> Result<(), ArmorError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        sqlx::query("INSERT INTO api_keys (id, key_hash, key_prefix, label) VALUES (?, ?, ?, ?)")
            .bind(key_id)
            .bind(key_hash)
            .bind(prefix)
            .bind(label)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn verify_raw_key(&self, raw_key: &str) -> Result<bool, ArmorError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        let hashes =
            sqlx::query_scalar::<_, String>("SELECT key_hash FROM api_keys WHERE key_prefix = ?")
                .bind(prefix)
                .fetch_all(&self.pool)
                .await?;

        for stored_hash in &hashes {
            if crate::auth::api_keys::verify_key(raw_key, stored_hash) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), ArmorError> {
        sqlx::query("DELETE FROM api_keys WHERE id = ?")
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, ArmorError> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, label, created_at FROM api_keys ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ApiKeyRecord {
                id: r.id,
                label: r.label,
                created_at: r.created_at,
            })
            .collect())
    }
}

struct ApiKeyRow {
    id: String,
    label: String,
    created_at: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ApiKeyRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            label: row.try_get("label")?,
            created_at: row.try_get("created_at")?,
        })
    }
}
