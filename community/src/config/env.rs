use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEnv {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    Sidecar,
    Gateway,
}

impl std::fmt::Display for ServiceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceMode::Sidecar => write!(f, "sidecar"),
            ServiceMode::Gateway => write!(f, "gateway"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppEnv {
    pub port: u16,
    pub node_env: NodeEnv,
    pub default_mode: ServiceMode,
}

pub fn load_env() -> AppEnv {
    let port = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4010);

    let node_env = match env::var("NODE_ENV").unwrap_or_default().as_str() {
        "production" => NodeEnv::Production,
        "test" => NodeEnv::Test,
        _ => NodeEnv::Development,
    };

    let default_mode = match env::var("AGENT_ARMOR_DEFAULT_MODE")
        .unwrap_or_default()
        .as_str()
    {
        "sidecar" => ServiceMode::Sidecar,
        _ => ServiceMode::Gateway,
    };

    AppEnv {
        port,
        node_env,
        default_mode,
    }
}
