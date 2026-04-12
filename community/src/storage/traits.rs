use async_trait::async_trait;

use crate::core::errors::ArmorError;
use crate::core::types::*;

// Re-export async_trait for enterprise to use
pub use async_trait::async_trait as storage_async_trait;

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, event: &StoredAuditEvent) -> Result<(), ArmorError>;
    async fn list(&self, limit: u32) -> Result<Vec<StoredAuditEvent>, ArmorError>;
    async fn list_filtered(
        &self,
        filter: &AuditExportFilter,
    ) -> Result<Vec<StoredAuditEvent>, ArmorError>;
    async fn stats(&self) -> Result<AuditStats, ArmorError>;
    async fn agent_analytics(
        &self,
        agent_id: Option<&str>,
    ) -> Result<Vec<AgentAnalytics>, ArmorError>;
}

#[async_trait]
pub trait ReviewStore: Send + Sync {
    async fn create(&self, review: &ReviewRequest) -> Result<(), ArmorError>;
    async fn get(&self, id: &str) -> Result<ReviewRequest, ArmorError>;
    async fn update_status(&self, id: &str, status: &str) -> Result<ReviewRequest, ArmorError>;
    async fn list(&self) -> Result<Vec<ReviewRequest>, ArmorError>;
}

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn get_agent_profile(&self, agent_id: &str) -> Result<AgentProfile, ArmorError>;
    async fn get_workspace_policy(&self, workspace_id: &str)
        -> Result<WorkspacePolicy, ArmorError>;
    async fn list_profiles(&self) -> Result<Vec<AgentProfile>, ArmorError>;
    async fn list_workspaces(&self) -> Result<Vec<WorkspacePolicy>, ArmorError>;
    async fn upsert_profile(&self, profile: &AgentProfile) -> Result<(), ArmorError>;
    async fn upsert_workspace(&self, policy: &WorkspacePolicy) -> Result<(), ArmorError>;
    async fn delete_profile(&self, agent_id: &str) -> Result<(), ArmorError>;
    async fn delete_workspace(&self, workspace_id: &str) -> Result<(), ArmorError>;
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn store_key(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
    ) -> Result<(), ArmorError>;
    /// Verify a raw API key against all stored hashes. Returns true if any match.
    async fn verify_raw_key(&self, raw_key: &str) -> Result<bool, ArmorError>;
    async fn delete_key(&self, key_id: &str) -> Result<(), ArmorError>;
    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, ArmorError>;
}

/// Tenant management store (enterprise multi-tenancy support).
#[async_trait]
pub trait TenantStore: Send + Sync {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), ArmorError>;
    async fn get_tenant(&self, tenant_id: &str) -> Result<Tenant, ArmorError>;
    async fn list_tenants(&self) -> Result<Vec<Tenant>, ArmorError>;
    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), ArmorError>;
}

/// Describes which database backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyRecord {
    pub id: String,
    pub label: String,
    pub created_at: String,
}
