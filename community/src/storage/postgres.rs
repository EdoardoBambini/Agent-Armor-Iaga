use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};

use super::migrations::run_postgres_migrations;
use super::traits::*;
use crate::core::errors::ArmorError;
use crate::core::types::*;

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> Result<Self, ArmorError> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .idle_timeout(std::time::Duration::from_secs(300))
            .connect(database_url)
            .await
            .map_err(|e| ArmorError::Storage(format!("Failed to connect to PostgreSQL: {e}")))?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    async fn run_migrations(&self) -> Result<(), ArmorError> {
        run_postgres_migrations(&self.pool).await
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// ── AuditStore ──

#[async_trait]
impl AuditStore for PostgresStorage {
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
            "INSERT INTO audit_events (event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)"
        )
        .bind(&event.event_id)
        .bind(&event.agent_id)
        .bind(&event.tenant_id)
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
        let rows = sqlx::query(
            "SELECT event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons::text, timestamp
             FROM audit_events ORDER BY created_at DESC LIMIT $1"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| pg_row_to_audit(r)).collect())
    }

    async fn list_filtered(
        &self,
        filter: &AuditExportFilter,
    ) -> Result<Vec<StoredAuditEvent>, ArmorError> {
        let limit = filter.limit.unwrap_or(1000) as i64;
        let agent = filter.agent_id.clone().unwrap_or_default();
        let decision = filter.decision.clone().unwrap_or_default();
        let from = filter.from_date.clone().unwrap_or_default();
        let to = filter.to_date.clone().unwrap_or_default();
        let tenant = filter.tenant_id.clone().unwrap_or_default();

        let rows = sqlx::query(
            "SELECT event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons::text, timestamp
             FROM audit_events
             WHERE ($1 = '' OR agent_id = $1)
               AND ($2 = '' OR decision = $2)
               AND ($3 = '' OR timestamp >= $3)
               AND ($4 = '' OR timestamp <= $4)
               AND ($5 = '' OR tenant_id = $5)
             ORDER BY created_at DESC LIMIT $6"
        )
        .bind(&agent)
        .bind(&decision)
        .bind(&from)
        .bind(&to)
        .bind(&tenant)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| pg_row_to_audit(r)).collect())
    }

    async fn stats(&self) -> Result<AuditStats, ArmorError> {
        use sqlx::Row;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await?;

        let avg: f64 =
            sqlx::query_scalar("SELECT COALESCE(AVG(risk_score), 0.0) FROM audit_events")
                .fetch_one(&self.pool)
                .await?;

        let decision_rows = sqlx::query(
            "SELECT decision, COUNT(*) as cnt FROM audit_events GROUP BY decision ORDER BY cnt DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut decisions = std::collections::HashMap::new();
        for row in &decision_rows {
            let d: String = row.try_get("decision")?;
            let c: i64 = row.try_get("cnt")?;
            decisions.insert(d, c as u64);
        }

        let agent_rows = sqlx::query(
            "SELECT agent_id, COUNT(*) as cnt FROM audit_events GROUP BY agent_id ORDER BY cnt DESC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let top_agents: Vec<(String, u64)> = agent_rows
            .iter()
            .map(|r| {
                let a: String = r.try_get("agent_id").unwrap_or_default();
                let c: i64 = r.try_get("cnt").unwrap_or(0);
                (a, c as u64)
            })
            .collect();

        let tool_rows = sqlx::query(
            "SELECT tool_name, COUNT(*) as cnt FROM audit_events GROUP BY tool_name ORDER BY cnt DESC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let top_tools: Vec<(String, u64)> = tool_rows
            .iter()
            .map(|r| {
                let t: String = r.try_get("tool_name").unwrap_or_default();
                let c: i64 = r.try_get("cnt").unwrap_or(0);
                (t, c as u64)
            })
            .collect();

        Ok(AuditStats {
            total_events: total as u64,
            decisions,
            top_agents,
            top_tools,
            avg_risk_score: avg,
        })
    }

    async fn agent_analytics(
        &self,
        agent_id: Option<&str>,
    ) -> Result<Vec<AgentAnalytics>, ArmorError> {
        use sqlx::Row;

        let agent_filter = agent_id.unwrap_or("");

        let rows = sqlx::query(
            "SELECT agent_id,
                    COUNT(*) as total,
                    AVG(risk_score) as avg_risk,
                    MAX(timestamp) as last_ts,
                    STRING_AGG(DISTINCT decision, ',') as decisions_csv,
                    STRING_AGG(tool_name, ',') as tools_csv
             FROM audit_events
             WHERE $1 = '' OR agent_id = $1
             GROUP BY agent_id
             ORDER BY total DESC",
        )
        .bind(agent_filter)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in &rows {
            let aid: String = row.try_get("agent_id").unwrap_or_default();
            let total: i64 = row.try_get("total").unwrap_or(0);
            let avg_risk: f64 = row.try_get("avg_risk").unwrap_or(0.0);
            let last_ts: String = row.try_get("last_ts").unwrap_or_default();
            let tools_csv: String = row.try_get("tools_csv").unwrap_or_default();

            let decision_rows = sqlx::query(
                "SELECT decision, COUNT(*) as cnt FROM audit_events WHERE agent_id = $1 GROUP BY decision",
            )
            .bind(&aid)
            .fetch_all(&self.pool)
            .await?;

            let mut decisions = std::collections::HashMap::new();
            for dr in &decision_rows {
                let d: String = dr.try_get("decision").unwrap_or_default();
                let c: i64 = dr.try_get("cnt").unwrap_or(0);
                decisions.insert(d, c as u64);
            }

            let mut tool_counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for tool in tools_csv.split(',') {
                let t = tool.trim().to_string();
                if !t.is_empty() {
                    *tool_counts.entry(t).or_insert(0) += 1;
                }
            }
            let mut top_tools: Vec<(String, u64)> = tool_counts.into_iter().collect();
            top_tools.sort_by(|a, b| b.1.cmp(&a.1));
            top_tools.truncate(5);

            let trust = crate::modules::nhi::crypto_identity::get_agent_trust(&aid);

            results.push(AgentAnalytics {
                agent_id: aid,
                total_requests: total as u64,
                decisions,
                avg_risk_score: avg_risk,
                top_tools,
                last_activity: last_ts,
                trust_score: trust,
            });
        }

        Ok(results)
    }
}

// ── ReviewStore ──

#[async_trait]
impl ReviewStore for PostgresStorage {
    async fn create(&self, review: &ReviewRequest) -> Result<(), ArmorError> {
        let reasons = serde_json::to_string(&review.reasons).unwrap_or_default();
        let decision = serde_json::to_value(review.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("review")
            .to_string();

        sqlx::query(
            "INSERT INTO review_requests (id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)"
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
        let row = sqlx::query(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons::text, created_at, updated_at
             FROM review_requests WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ArmorError::ReviewNotFound(id.to_string()))?;

        Ok(pg_row_to_review(&row))
    }

    async fn update_status(&self, id: &str, status: &str) -> Result<ReviewRequest, ArmorError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE review_requests SET status = $1, updated_at = $2 WHERE id = $3")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        self.get(id).await
    }

    async fn list(&self) -> Result<Vec<ReviewRequest>, ArmorError> {
        let rows = sqlx::query(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons::text, created_at, updated_at
             FROM review_requests ORDER BY created_at ASC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| pg_row_to_review(r)).collect())
    }
}

// ── PolicyStore ──

#[async_trait]
impl PolicyStore for PostgresStorage {
    async fn get_agent_profile(&self, agent_id: &str) -> Result<AgentProfile, ArmorError> {
        let row = sqlx::query(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools::text, approved_secrets::text, baseline_action_types::text
             FROM agent_profiles WHERE agent_id = $1"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ArmorError::AgentNotFound(agent_id.to_string()))?;

        Ok(pg_row_to_profile(&row))
    }

    async fn get_workspace_policy(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspacePolicy, ArmorError> {
        let row = sqlx::query(
            "SELECT workspace_id, tenant_id, allowed_protocols::text, allowed_domains::text, tools::text, threshold_block, threshold_review
             FROM workspace_policies WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ArmorError::WorkspaceNotFound(workspace_id.to_string()))?;

        Ok(pg_row_to_workspace(&row))
    }

    async fn list_profiles(&self) -> Result<Vec<AgentProfile>, ArmorError> {
        let rows = sqlx::query(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools::text, approved_secrets::text, baseline_action_types::text
             FROM agent_profiles ORDER BY agent_id"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| pg_row_to_profile(r)).collect())
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspacePolicy>, ArmorError> {
        let rows = sqlx::query(
            "SELECT workspace_id, tenant_id, allowed_protocols::text, allowed_domains::text, tools::text, threshold_block, threshold_review
             FROM workspace_policies ORDER BY workspace_id",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| pg_row_to_workspace(r)).collect())
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

        sqlx::query(
            "INSERT INTO agent_profiles (agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, NOW())
             ON CONFLICT(agent_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                workspace_id = EXCLUDED.workspace_id,
                framework = EXCLUDED.framework,
                role = EXCLUDED.role,
                approved_tools = EXCLUDED.approved_tools,
                approved_secrets = EXCLUDED.approved_secrets,
                baseline_action_types = EXCLUDED.baseline_action_types,
                updated_at = NOW()"
        )
        .bind(&profile.agent_id)
        .bind(&profile.tenant_id)
        .bind(&profile.workspace_id)
        .bind(&profile.framework)
        .bind(&role)
        .bind(&tools)
        .bind(&secrets)
        .bind(&baselines)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_workspace(&self, policy: &WorkspacePolicy) -> Result<(), ArmorError> {
        let protocols = serde_json::to_string(&policy.allowed_protocols).unwrap_or_default();
        let domains = serde_json::to_string(&policy.allowed_domains).unwrap_or_default();
        let tools = serde_json::to_string(&policy.tools).unwrap_or_default();

        sqlx::query(
            "INSERT INTO workspace_policies (workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review, updated_at)
             VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7, NOW())
             ON CONFLICT(workspace_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                allowed_protocols = EXCLUDED.allowed_protocols,
                allowed_domains = EXCLUDED.allowed_domains,
                tools = EXCLUDED.tools,
                threshold_block = EXCLUDED.threshold_block,
                threshold_review = EXCLUDED.threshold_review,
                updated_at = NOW()"
        )
        .bind(&policy.workspace_id)
        .bind(&policy.tenant_id)
        .bind(&protocols)
        .bind(&domains)
        .bind(&tools)
        .bind(policy.threshold_block as i64)
        .bind(policy.threshold_review as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_profile(&self, agent_id: &str) -> Result<(), ArmorError> {
        sqlx::query("DELETE FROM agent_profiles WHERE agent_id = $1")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_workspace(&self, workspace_id: &str) -> Result<(), ArmorError> {
        sqlx::query("DELETE FROM workspace_policies WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── ApiKeyStore ──

#[async_trait]
impl ApiKeyStore for PostgresStorage {
    async fn store_key(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
    ) -> Result<(), ArmorError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, key_prefix, label) VALUES ($1, $2, $3, $4)",
        )
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
            sqlx::query_scalar::<_, String>("SELECT key_hash FROM api_keys WHERE key_prefix = $1")
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
        sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, ArmorError> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT id, label, created_at::text FROM api_keys ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| ApiKeyRecord {
                id: r.try_get("id").unwrap_or_default(),
                label: r.try_get("label").unwrap_or_default(),
                created_at: r.try_get("created_at").unwrap_or_default(),
            })
            .collect())
    }
}

// ── TenantStore ──

#[async_trait]
impl TenantStore for PostgresStorage {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), ArmorError> {
        let metadata = tenant
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());
        sqlx::query(
            "INSERT INTO tenants (tenant_id, name, enabled, metadata, created_at) VALUES ($1, $2, $3, $4::jsonb, $5)",
        )
        .bind(&tenant.tenant_id)
        .bind(&tenant.name)
        .bind(tenant.enabled)
        .bind(&metadata)
        .bind(&tenant.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_tenant(&self, tenant_id: &str) -> Result<Tenant, ArmorError> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT tenant_id, name, enabled, metadata::text, created_at::text FROM tenants WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ArmorError::Storage(format!("Tenant not found: {tenant_id}")))?;

        let metadata_str: Option<String> = row.try_get("metadata").unwrap_or(None);
        Ok(Tenant {
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            enabled: row.try_get::<bool, _>("enabled").unwrap_or(true),
            created_at: row.try_get("created_at")?,
            metadata: metadata_str.and_then(|s| serde_json::from_str(&s).ok()),
        })
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, ArmorError> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT tenant_id, name, enabled, metadata::text, created_at::text FROM tenants ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut tenants = Vec::new();
        for row in &rows {
            let metadata_str: Option<String> = row.try_get("metadata").unwrap_or(None);
            tenants.push(Tenant {
                tenant_id: row.try_get("tenant_id")?,
                name: row.try_get("name")?,
                enabled: row.try_get::<bool, _>("enabled").unwrap_or(true),
                created_at: row.try_get("created_at")?,
                metadata: metadata_str.and_then(|s| serde_json::from_str(&s).ok()),
            });
        }
        Ok(tenants)
    }

    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), ArmorError> {
        sqlx::query("DELETE FROM tenants WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Helper functions ──

fn pg_row_to_audit(row: &sqlx::postgres::PgRow) -> StoredAuditEvent {
    use sqlx::Row;
    StoredAuditEvent {
        event_id: row.try_get("event_id").unwrap_or_default(),
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        framework: row.try_get("framework").unwrap_or_default(),
        action_type: {
            let s: String = row.try_get("action_type").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s)).unwrap_or(ActionType::Custom)
        },
        tool_name: row.try_get("tool_name").unwrap_or_default(),
        decision: {
            let s: String = row.try_get("decision").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s))
                .unwrap_or(GovernanceDecision::Block)
        },
        risk_score: {
            let v: i64 = row.try_get("risk_score").unwrap_or(0);
            v as u32
        },
        review_status: {
            let s: String = row.try_get("review_status").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s))
                .unwrap_or(ReviewStatus::NotRequired)
        },
        reasons: {
            let s: String = row.try_get("reasons").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        timestamp: row.try_get("timestamp").unwrap_or_default(),
    }
}

fn pg_row_to_review(row: &sqlx::postgres::PgRow) -> ReviewRequest {
    use sqlx::Row;
    ReviewRequest {
        id: row.try_get("id").unwrap_or_default(),
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        workspace_id: row.try_get("workspace_id").unwrap_or_default(),
        tool_name: row.try_get("tool_name").unwrap_or_default(),
        decision: {
            let s: String = row.try_get("decision").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s))
                .unwrap_or(GovernanceDecision::Review)
        },
        status: row.try_get("status").unwrap_or_default(),
        risk_score: {
            let v: i64 = row.try_get("risk_score").unwrap_or(0);
            v as u32
        },
        reasons: {
            let s: String = row.try_get("reasons").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        created_at: row.try_get("created_at").unwrap_or_default(),
        updated_at: row.try_get("updated_at").unwrap_or_default(),
    }
}

fn pg_row_to_profile(row: &sqlx::postgres::PgRow) -> AgentProfile {
    use sqlx::Row;
    AgentProfile {
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        workspace_id: row.try_get("workspace_id").unwrap_or_default(),
        framework: row.try_get("framework").unwrap_or_default(),
        role: {
            let s: String = row.try_get("role").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s)).unwrap_or(AgentRole::Builder)
        },
        approved_tools: {
            let s: String = row.try_get("approved_tools").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        approved_secrets: {
            let s: String = row.try_get("approved_secrets").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        baseline_action_types: {
            let s: String = row.try_get("baseline_action_types").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        tool_trust: 0.7,
    }
}

fn pg_row_to_workspace(row: &sqlx::postgres::PgRow) -> WorkspacePolicy {
    use sqlx::Row;
    WorkspacePolicy {
        workspace_id: row.try_get("workspace_id").unwrap_or_default(),
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        allowed_protocols: {
            let s: String = row.try_get("allowed_protocols").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        allowed_domains: {
            let s: String = row.try_get("allowed_domains").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        tools: {
            let s: String = row.try_get("tools").unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        },
        threshold_block: {
            let v: i64 = row.try_get("threshold_block").unwrap_or(70);
            v as u32
        },
        threshold_review: {
            let v: i64 = row.try_get("threshold_review").unwrap_or(35);
            v as u32
        },
    }
}
