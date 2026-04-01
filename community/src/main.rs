use std::env;
use std::process;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use agent_armor::config::env::load_env;
use agent_armor::core::types::RateLimitConfig;
use agent_armor::events::bus::EventBus;
use agent_armor::events::webhooks::{self, WebhookManager};
use agent_armor::modules::fingerprint::behavioral::BehavioralEngine;
use agent_armor::modules::rate_limit::limiter::RateLimiter;
use agent_armor::modules::threat_intel::feed::ThreatFeed;
use agent_armor::server::app_state::AppState;
use agent_armor::server::create_server::create_router;
use agent_armor::storage::sqlite::SqliteStorage;
use agent_armor::storage::traits::PolicyStore;

/// IAGA Agent Armor — Zero-trust governance for autonomous AI agents
#[derive(Parser)]
#[command(name = "agent-armor", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Database URL (overrides DATABASE_URL env var)
    #[arg(long, global = true)]
    db: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the governance server (default if no subcommand)
    Serve {
        /// Port to listen on (overrides PORT env var)
        #[arg(short, long)]
        port: Option<u16>,

        /// Seed demo data on first boot
        #[arg(long, default_value_t = true)]
        seed_demo: bool,
    },

    /// Inspect a single payload through the governance pipeline
    Inspect {
        /// Path to JSON payload file, or --stdin
        source: String,
    },

    /// Validate a policy YAML/JSON config file without starting the server
    Validate {
        /// Path to policy config file (YAML or JSON)
        config: String,
    },

    /// Run database migrations
    Migrate,

    /// Import policies from a YAML/JSON config file into the database
    Import {
        /// Path to policy config file (YAML or JSON)
        config: String,
    },

    /// Export current policies from the database to YAML
    Export {
        /// Output file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Generate a new API key
    #[command(name = "gen-key")]
    GenKey {
        /// Label for the API key
        #[arg(short, long, default_value = "cli-generated")]
        label: String,
    },

    /// Show audit trail
    Audit {
        /// Max number of events to show
        #[arg(short, long, default_value_t = 50)]
        limit: u32,

        /// Output format: json or table
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Run as MCP proxy: intercept tool calls between MCP client and downstream server
    Proxy {
        /// Agent ID for governance checks
        #[arg(short, long)]
        agent_id: String,

        /// Downstream MCP server command (e.g. "npx -y @modelcontextprotocol/server-filesystem")
        #[arg(short, long)]
        command: String,

        /// Arguments for the downstream command
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let db_url = cli
        .db
        .clone()
        .or_else(|| env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| "sqlite:agent_armor.db?mode=rwc".into());

    match cli.command {
        None | Some(Commands::Serve { .. }) => {
            let (port_override, seed_demo) = match &cli.command {
                Some(Commands::Serve {
                    port, seed_demo, ..
                }) => (*port, *seed_demo),
                _ => (None, true),
            };
            cmd_serve(&db_url, port_override, seed_demo).await;
        }
        Some(Commands::Inspect { source }) => {
            let code = cmd_inspect(&source, &db_url).await;
            process::exit(code);
        }
        Some(Commands::Validate { config }) => {
            cmd_validate(&config);
        }
        Some(Commands::Migrate) => {
            cmd_migrate(&db_url).await;
        }
        Some(Commands::Import { config }) => {
            cmd_import(&config, &db_url).await;
        }
        Some(Commands::Export { output }) => {
            cmd_export(&db_url, output.as_deref()).await;
        }
        Some(Commands::GenKey { label }) => {
            cmd_gen_key(&db_url, &label).await;
        }
        Some(Commands::Audit { limit, format }) => {
            cmd_audit(&db_url, limit, &format).await;
        }
        Some(Commands::Proxy {
            agent_id,
            command,
            args,
        }) => {
            cmd_proxy(&db_url, &agent_id, &command, args).await;
        }
    }
}

// ── serve ──

fn print_banner(port: u16) {
    let green = "\x1b[38;2;0;255;136m";
    let cyan = "\x1b[38;2;0;212;255m";
    let dim = "\x1b[38;2;102;102;102m";
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";

    eprintln!("{green}{bold}");
    eprintln!("    ╔══════════════════════════════════════════╗");
    eprintln!("    ║  ░█▀█░█▀▀░█▀▀░█▀█░▀█▀░░░░░░░░░░░░░░░░ ║");
    eprintln!("    ║  ░█▀█░█░█░█▀▀░█░█░░█░░░░░░░░░░░░░░░░░ ║");
    eprintln!("    ║  ░▀░▀░▀▀▀░▀▀▀░▀░▀░░▀░░░░░░░░░░░░░░░░░ ║");
    eprintln!("    ║  ░█▀█░█▀▄░█▄█░█▀█░█▀▄░░░░░░░░░░░░░░░░ ║");
    eprintln!("    ║  ░█▀█░█▀▄░█░█░█░█░█▀▄░░░░░░░░░░░░░░░░ ║");
    eprintln!("    ║  ░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀░░░░░░░░░░░░░░░░ ║");
    eprintln!("    ╚══════════════════════════════════════════╝{reset}");
    eprintln!();
    eprintln!("    {cyan}Zero-Trust Security Runtime for AI Agents{reset}");
    eprintln!("    {dim}v{}{reset}", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("    {green}▸{reset} Port        {bold}{port}{reset}");
    eprintln!("    {green}▸{reset} Dashboard   {cyan}http://localhost:{port}{reset}");
    eprintln!("    {green}▸{reset} API         {cyan}http://localhost:{port}/v1/inspect{reset}");
    eprintln!("    {green}▸{reset} 8 Layers    {green}ARMED{reset}");
    eprintln!();
    eprintln!("    {dim}Press Ctrl+C to shut down{reset}");
    eprintln!();
}

async fn cmd_serve(db_url: &str, port_override: Option<u16>, seed_demo: bool) {
    let mut app_env = load_env();
    if let Some(p) = port_override {
        app_env.port = p;
    }

    print_banner(app_env.port);

    let storage = match SqliteStorage::new(db_url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize SQLite database: {e}");
            process::exit(1);
        }
    };
    let storage = Arc::new(storage);

    if seed_demo {
        seed_demo_data(&storage).await;
    }

    // Auto-import agent-armor.yaml if it exists and DB is fresh
    auto_import_config(&storage).await;

    let event_bus = EventBus::new(1024);
    let webhook_manager = Arc::new(WebhookManager::new());
    let behavioral_engine = Arc::new(BehavioralEngine::new());

    // Spawn webhook delivery worker
    webhooks::spawn_webhook_worker(event_bus.clone(), webhook_manager.clone());

    // Spawn periodic TTL cleanup for session/taint data (every 5 minutes)
    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(300);
        let ttl = std::time::Duration::from_secs(3600); // 1 hour TTL
        let ttl_ms = 3_600_000u64;
        loop {
            tokio::time::sleep(interval).await;
            let taint_pruned =
                agent_armor::modules::taint::taint_tracker::prune_stale_sessions(ttl);
            let session_pruned =
                agent_armor::modules::session_graph::session_dag::prune_stale_sessions(ttl_ms);
            if taint_pruned > 0 || session_pruned > 0 {
                tracing::debug!(taint_pruned, session_pruned, "TTL cleanup completed");
            }
        }
    });

    let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
    let threat_feed = Arc::new(ThreatFeed::with_builtin_indicators());
    tracing::info!(
        indicators = threat_feed.get_stats().total_indicators,
        "Threat intelligence feed loaded"
    );

    let state = Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        event_bus,
        webhook_manager,
        behavioral_engine,
        rate_limiter,
        threat_feed,
        env: app_env,
    });

    let router = create_router(state.clone());

    let addr = format!("0.0.0.0:{}", state.env.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            process::exit(1);
        }
    };

    tracing::info!(port = state.env.port, db = %db_url, "Agent Armor listening");

    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("Server error: {e}");
        process::exit(1);
    }

    tracing::info!("Agent Armor shut down gracefully");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received Ctrl+C, shutting down..."); },
        _ = terminate => { tracing::info!("received SIGTERM, shutting down..."); },
    }
}

// ── inspect ──

async fn cmd_inspect(source: &str, db_url: &str) -> i32 {
    use agent_armor::core::types::*;
    use agent_armor::pipeline::execute_pipeline::execute_pipeline;
    use std::io::Read;

    let raw = if source == "--stdin" {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("Failed to read stdin: {e}");
            return 3;
        }
        buf
    } else {
        match std::fs::read_to_string(source) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read file {source}: {e}");
                return 3;
            }
        }
    };

    let payload: InspectRequest = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Invalid JSON input: {e}");
            return 3;
        }
    };

    let storage = match SqliteStorage::new(db_url).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Failed to open database: {e}");
            return 3;
        }
    };

    let state = Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        event_bus: EventBus::new(16),
        webhook_manager: Arc::new(WebhookManager::new()),
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: Arc::new(ThreatFeed::with_builtin_indicators()),
        env: load_env(),
    });

    match execute_pipeline(&payload, &state).await {
        Ok(result) => {
            // Cyberpunk styled output
            let green = "\x1b[38;2;0;255;136m";
            let red = "\x1b[38;2;255;0;85m";
            let cyan = "\x1b[38;2;0;212;255m";
            let yellow = "\x1b[38;2;255;204;0m";
            let dim = "\x1b[38;2;102;102;102m";
            let bold = "\x1b[1m";
            let reset = "\x1b[0m";

            let (decision_color, decision_icon) = match result.decision {
                GovernanceDecision::Allow => (green, "✓ ALLOW"),
                GovernanceDecision::Review => (yellow, "⚠ REVIEW"),
                GovernanceDecision::Block => (red, "✗ BLOCK"),
            };

            eprintln!();
            eprintln!("  {dim}┌─────────────────────────────────────────────┐{reset}");
            eprintln!("  {dim}│{reset} {cyan}AGENT ARMOR{reset} {dim}// governance result{reset}          {dim}│{reset}");
            eprintln!("  {dim}├─────────────────────────────────────────────┤{reset}");

            // Decision
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");
            eprintln!("  {dim}│{reset}   {bold}{decision_color}{decision_icon}{reset}                            {dim}│{reset}");
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");

            // Risk score bar
            let score = result.risk.score;
            let bar_len = 30;
            let filled = ((score as f64 / 100.0) * bar_len as f64) as usize;
            let bar_color = if score >= 80 {
                red
            } else if score >= 50 {
                yellow
            } else {
                green
            };
            let bar: String = format!(
                "{}{}{}{}",
                bar_color,
                "█".repeat(filled),
                dim,
                "░".repeat(bar_len - filled),
            );
            eprintln!("  {dim}│{reset}   Risk  {bar}{reset} {bold}{score}/100{reset}        {dim}│{reset}");
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");

            // Details
            eprintln!(
                "  {dim}│{reset}   {dim}Agent{reset}     {}",
                result.audit_event.agent_id
            );
            eprintln!(
                "  {dim}│{reset}   {dim}Tool{reset}      {}",
                result.audit_event.tool_name
            );
            eprintln!(
                "  {dim}│{reset}   {dim}Protocol{reset}  {:?}",
                result.protocol
            );
            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");

            // Reasons
            if !result.policy_findings.is_empty() {
                eprintln!("  {dim}│{reset}   {cyan}Findings:{reset}");
                for finding in &result.policy_findings {
                    eprintln!("  {dim}│{reset}   {dim}›{reset} {finding}");
                }
            }

            eprintln!("  {dim}│{reset}                                             {dim}│{reset}");
            eprintln!("  {dim}└─────────────────────────────────────────────┘{reset}");
            eprintln!();

            // Still output JSON to stdout for piping
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "decision": result.decision,
                    "reviewStatus": result.review_status,
                    "riskScore": result.risk.score,
                    "reasons": result.risk.reasons,
                    "policyFindings": result.policy_findings,
                    "schemaValidation": result.schema_validation,
                    "secretPlan": result.secret_plan,
                    "protocol": result.protocol,
                }))
                .unwrap()
            );

            match result.decision {
                GovernanceDecision::Block => 2,
                GovernanceDecision::Review => 1,
                GovernanceDecision::Allow => 0,
            }
        }
        Err(e) => {
            eprintln!("Pipeline error: {e}");
            3
        }
    }
}

// ── validate ──

fn cmd_validate(config_path: &str) {
    use agent_armor::core::types::ArmorConfig;

    let raw = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read config file: {e}");
            process::exit(1);
        }
    };

    let result: Result<ArmorConfig, String> =
        if config_path.ends_with(".yaml") || config_path.ends_with(".yml") {
            serde_yaml::from_str(&raw).map_err(|e| e.to_string())
        } else {
            serde_json::from_str(&raw).map_err(|e| e.to_string())
        };

    match result {
        Ok(config) => {
            println!("Config is valid!");
            println!("  {} agent profiles", config.profiles.len());
            println!("  {} workspace policies", config.workspaces.len());
            let total_tools: usize = config.workspaces.iter().map(|w| w.tools.len()).sum();
            println!("  {} tool policies", total_tools);
        }
        Err(e) => {
            eprintln!("Invalid config: {e}");
            process::exit(1);
        }
    }
}

// ── migrate ──

async fn cmd_migrate(db_url: &str) {
    match SqliteStorage::new(db_url).await {
        Ok(_) => println!("Migrations completed successfully."),
        Err(e) => {
            eprintln!("Migration failed: {e}");
            process::exit(1);
        }
    }
}

// ── import ──

async fn cmd_import(config_path: &str, db_url: &str) {
    use agent_armor::core::types::ArmorConfig;

    let raw = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read config file: {e}");
            process::exit(1);
        }
    };

    let config: ArmorConfig = if config_path.ends_with(".yaml") || config_path.ends_with(".yml") {
        serde_yaml::from_str(&raw).unwrap_or_else(|e| {
            eprintln!("Invalid YAML: {e}");
            process::exit(1);
        })
    } else {
        serde_json::from_str(&raw).unwrap_or_else(|e| {
            eprintln!("Invalid JSON: {e}");
            process::exit(1);
        })
    };

    let storage = SqliteStorage::new(db_url).await.unwrap_or_else(|e| {
        eprintln!("Failed to open database: {e}");
        process::exit(1);
    });

    let mut imported = 0;
    for profile in &config.profiles {
        if let Err(e) = storage.upsert_profile(profile).await {
            eprintln!("Failed to import profile {}: {e}", profile.agent_id);
        } else {
            imported += 1;
        }
    }
    for workspace in &config.workspaces {
        if let Err(e) = storage.upsert_workspace(workspace).await {
            eprintln!("Failed to import workspace {}: {e}", workspace.workspace_id);
        } else {
            imported += 1;
        }
    }

    println!(
        "Imported {} items ({} profiles, {} workspaces)",
        imported,
        config.profiles.len(),
        config.workspaces.len()
    );
}

// ── export ──

async fn cmd_export(db_url: &str, output: Option<&str>) {
    use agent_armor::core::types::ArmorConfig;

    let storage = SqliteStorage::new(db_url).await.unwrap_or_else(|e| {
        eprintln!("Failed to open database: {e}");
        process::exit(1);
    });

    let profiles = storage.list_profiles().await.unwrap_or_default();
    let workspaces = storage.list_workspaces().await.unwrap_or_default();

    let config = ArmorConfig {
        profiles,
        workspaces,
        vault: vec![],
    };

    let yaml = serde_yaml::to_string(&config).unwrap_or_else(|e| {
        eprintln!("Failed to serialize: {e}");
        process::exit(1);
    });

    match output {
        Some(path) => {
            std::fs::write(path, &yaml).unwrap_or_else(|e| {
                eprintln!("Failed to write {path}: {e}");
                process::exit(1);
            });
            println!("Exported to {path}");
        }
        None => print!("{yaml}"),
    }
}

// ── gen-key ──

async fn cmd_gen_key(db_url: &str, label: &str) {
    use agent_armor::auth::api_keys::generate_api_key;

    let storage = SqliteStorage::new(db_url).await.unwrap_or_else(|e| {
        eprintln!("Failed to open database: {e}");
        process::exit(1);
    });

    let (raw_key, key_hash) = generate_api_key();
    let key_id = uuid::Uuid::new_v4().to_string();

    use agent_armor::storage::traits::ApiKeyStore;
    storage
        .store_key(&key_id, &key_hash, label, &raw_key)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to store key: {e}");
            process::exit(1);
        });

    println!("API Key created:");
    println!("  ID:    {key_id}");
    println!("  Key:   {raw_key}");
    println!("  Label: {label}");
    println!();
    println!("Save this key now — it cannot be retrieved again.");
}

// ── audit ──

async fn cmd_audit(db_url: &str, limit: u32, format: &str) {
    use agent_armor::storage::traits::AuditStore;

    let storage = SqliteStorage::new(db_url).await.unwrap_or_else(|e| {
        eprintln!("Failed to open database: {e}");
        process::exit(1);
    });

    let events = storage.list(limit).await.unwrap_or_else(|e| {
        eprintln!("Failed to fetch audit events: {e}");
        process::exit(1);
    });

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&events).unwrap());
        }
        "table" => {
            let green = "\x1b[38;2;0;255;136m";
            let red = "\x1b[38;2;255;0;85m";
            let cyan = "\x1b[38;2;0;212;255m";
            let yellow = "\x1b[38;2;255;204;0m";
            let dim = "\x1b[38;2;102;102;102m";
            let bold = "\x1b[1m";
            let reset = "\x1b[0m";

            eprintln!();
            eprintln!("  {dim}┌─────────────────────────────────────────────┐{reset}");
            eprintln!("  {dim}│{reset} {cyan}AGENT ARMOR{reset} {dim}// audit trail{reset}                 {dim}│{reset}");
            eprintln!("  {dim}└─────────────────────────────────────────────┘{reset}");
            eprintln!();

            println!(
                "  {cyan}{bold}{:<36} {:<16} {:<20} {:<10} {:<6} TIMESTAMP{reset}",
                "EVENT_ID", "AGENT", "TOOL", "DECISION", "RISK"
            );
            println!("  {dim}{}{reset}", "─".repeat(110));
            for e in &events {
                use agent_armor::core::types::GovernanceDecision;
                let decision_color = match e.decision {
                    GovernanceDecision::Allow => green,
                    GovernanceDecision::Review => yellow,
                    GovernanceDecision::Block => red,
                };
                let risk_color = if e.risk_score >= 80 {
                    red
                } else if e.risk_score >= 50 {
                    yellow
                } else {
                    green
                };
                println!(
                    "  {:<36} {:<16} {:<20} {decision_color}{:<10?}{reset} {risk_color}{:<6}{reset} {dim}{}{reset}",
                    e.event_id, e.agent_id, e.tool_name, e.decision, e.risk_score, e.timestamp
                );
            }
            eprintln!();
            eprintln!("  {dim}{} events{reset}", events.len());
            eprintln!();
        }
        _ => {
            eprintln!("Unknown format: {format}. Use 'json' or 'table'.");
            process::exit(1);
        }
    }
}

// ── helpers ──

async fn seed_demo_data(storage: &Arc<SqliteStorage>) {
    use agent_armor::demo::scenarios::{demo_profiles, demo_workspace_policies};

    let profiles = storage.list_profiles().await.unwrap_or_default();
    if !profiles.is_empty() {
        return;
    }

    tracing::info!("Seeding demo data into database...");
    for profile in demo_profiles() {
        if let Err(e) = storage.upsert_profile(&profile).await {
            tracing::warn!(agent_id = %profile.agent_id, error = %e, "Failed to seed demo profile");
        }
    }
    for workspace in demo_workspace_policies() {
        if let Err(e) = storage.upsert_workspace(&workspace).await {
            tracing::warn!(workspace_id = %workspace.workspace_id, error = %e, "Failed to seed demo workspace");
        }
    }
    tracing::info!("Demo data seeded");
}

async fn cmd_proxy(db_url: &str, agent_id: &str, command: &str, args: Vec<String>) {
    use agent_armor::mcp_proxy::proxy_server::{run_mcp_proxy, McpProxyConfig};

    let storage = SqliteStorage::new(db_url).await.unwrap_or_else(|e| {
        eprintln!("Failed to open database: {e}");
        process::exit(1);
    });
    let storage = Arc::new(storage);
    seed_demo_data(&storage).await;

    let event_bus = EventBus::new(256);
    let webhook_manager = Arc::new(WebhookManager::new());

    let state = Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        event_bus,
        webhook_manager,
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: Arc::new(ThreatFeed::with_builtin_indicators()),
        env: load_env(),
    });

    let config = McpProxyConfig {
        agent_id: agent_id.to_string(),
        downstream_command: command.to_string(),
        downstream_args: args,
        downstream_env: std::collections::HashMap::new(),
    };

    if let Err(e) = run_mcp_proxy(config, state).await {
        eprintln!("MCP proxy error: {e}");
        process::exit(1);
    }
}

async fn auto_import_config(storage: &Arc<SqliteStorage>) {
    for name in &["agent-armor.yaml", "agent-armor.yml", "agent-armor.json"] {
        if std::path::Path::new(name).exists() {
            tracing::info!(file = name, "Found config file, auto-importing...");
            let raw = match std::fs::read_to_string(name) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let config: agent_armor::core::types::ArmorConfig =
                if name.ends_with(".yaml") || name.ends_with(".yml") {
                    match serde_yaml::from_str(&raw) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to parse config file");
                            continue;
                        }
                    }
                } else {
                    match serde_json::from_str(&raw) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to parse config file");
                            continue;
                        }
                    }
                };

            for p in &config.profiles {
                if let Err(e) = storage.upsert_profile(p).await {
                    tracing::warn!(agent_id = %p.agent_id, error = %e, "Failed to import profile from config");
                }
            }
            for w in &config.workspaces {
                if let Err(e) = storage.upsert_workspace(w).await {
                    tracing::warn!(workspace_id = %w.workspace_id, error = %e, "Failed to import workspace from config");
                }
            }
            tracing::info!(
                profiles = config.profiles.len(),
                workspaces = config.workspaces.len(),
                "Config imported"
            );
            break;
        }
    }
}
