use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ArmorError {
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Workspace not found: {0}")]
    WorkspaceNotFound(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Authentication required")]
    AuthRequired,

    #[error("Invalid API key")]
    InvalidApiKey,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Review not found: {0}")]
    ReviewNotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Proxy error: {0}")]
    Proxy(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

impl IntoResponse for ArmorError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_type) = match &self {
            ArmorError::AgentNotFound(_) => (StatusCode::NOT_FOUND, "agent_not_found"),
            ArmorError::WorkspaceNotFound(_) => (StatusCode::NOT_FOUND, "workspace_not_found"),
            ArmorError::PolicyViolation(_) => (StatusCode::FORBIDDEN, "policy_violation"),
            ArmorError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
            ArmorError::AuthRequired => (StatusCode::UNAUTHORIZED, "auth_required"),
            ArmorError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "invalid_api_key"),
            ArmorError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            ArmorError::ReviewNotFound(_) => (StatusCode::NOT_FOUND, "review_not_found"),
            ArmorError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
            ArmorError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config_error"),
            ArmorError::Proxy(_) => (StatusCode::INTERNAL_SERVER_ERROR, "proxy_error"),
        };

        let body = ErrorBody {
            error: error_type.to_string(),
            message: self.to_string(),
        };

        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ArmorError {
    fn from(e: sqlx::Error) -> Self {
        ArmorError::Storage(e.to_string())
    }
}

impl From<std::io::Error> for ArmorError {
    fn from(e: std::io::Error) -> Self {
        ArmorError::Config(e.to_string())
    }
}

impl From<serde_yaml::Error> for ArmorError {
    fn from(e: serde_yaml::Error) -> Self {
        ArmorError::Config(e.to_string())
    }
}
