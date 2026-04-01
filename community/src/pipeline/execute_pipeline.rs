use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use uuid::Uuid;

use crate::core::errors::ArmorError;
use crate::core::types::*;
use crate::modules::injection_firewall::prompt_firewall;
use crate::modules::nhi::crypto_identity;
use crate::modules::policy::evaluate_policy::evaluate_policy;
use crate::modules::policy::formal_verify;
use crate::modules::policy::tool_risk::{score_tool_risk, LayerRiskContributions};
use crate::modules::protocol::detect_protocol::detect_protocol;
use crate::modules::protocol::mcp_parser::normalize_mcp_payload;
use crate::modules::protocol::validate_mcp_tool::validate_mcp_tool;
use crate::modules::risk::adaptive_scorer::{self, AdaptiveScoreInput};
use crate::modules::sandbox::sandbox_executor;
use crate::modules::secrets::secret_references::plan_secret_injection;
use crate::modules::session_graph::session_dag;
use crate::modules::taint::taint_tracker;
use crate::modules::telemetry::otel_emitter;
use crate::server::app_state::AppState;

fn action_type_str(at: ActionType) -> &'static str {
    match at {
        ActionType::Shell => "shell",
        ActionType::FileRead => "file_read",
        ActionType::FileWrite => "file_write",
        ActionType::Http => "http",
        ActionType::DbQuery => "db_query",
        ActionType::Email => "email",
        ActionType::Custom => "custom",
    }
}

pub async fn execute_pipeline(
    input: &InspectRequest,
    state: &Arc<AppState>,
) -> Result<GovernanceResult, ArmorError> {
    let pipeline_start = std::time::Instant::now();

    let profile = state
        .policy_store
        .get_agent_profile(&input.agent_id)
        .await?;
    let workspace_id = input
        .workspace_id
        .as_deref()
        .unwrap_or(&profile.workspace_id);
    let workspace_policy = state
        .policy_store
        .get_workspace_policy(workspace_id)
        .await?;

    // ═══════════════════════════════════════════════════════════════
    // RATE LIMIT CHECK — runs before all security layers
    // ═══════════════════════════════════════════════════════════════
    let rate_result = state
        .rate_limiter
        .check_rate(&input.agent_id, Some(&input.action.tool_name))
        .await;

    if !rate_result.allowed {
        let now = Utc::now().to_rfc3339();
        let event_id = Uuid::new_v4().to_string();
        let finding = format!(
            "Rate limit exceeded (remaining={}, retry_after={}s)",
            rate_result.remaining,
            rate_result.retry_after_secs.unwrap_or(0)
        );

        let risk = RiskScore {
            score: 0,
            decision: GovernanceDecision::Block,
            reasons: vec![finding.clone()],
        };

        let audit_event = AuditEvent {
            event_id: event_id.clone(),
            agent_id: input.agent_id.clone(),
            framework: input.framework.clone(),
            action_type: input.action.action_type,
            tool_name: input.action.tool_name.clone(),
            decision: GovernanceDecision::Block,
            timestamp: now.clone(),
            reasons: vec![finding.clone()],
        };

        let stored = StoredAuditEvent {
            event_id: audit_event.event_id.clone(),
            agent_id: audit_event.agent_id.clone(),
            framework: audit_event.framework.clone(),
            action_type: audit_event.action_type,
            tool_name: audit_event.tool_name.clone(),
            decision: GovernanceDecision::Block,
            timestamp: audit_event.timestamp.clone(),
            reasons: audit_event.reasons.clone(),
            review_status: ReviewStatus::NotRequired,
            risk_score: 0,
        };
        let _ = state.audit_store.append(&stored).await;

        return Ok(GovernanceResult {
            protocol: detect_protocol(input),
            normalized_payload: input.action.payload.clone(),
            decision: GovernanceDecision::Block,
            review_status: ReviewStatus::NotRequired,
            risk,
            secret_plan: SecretInjectionPlan {
                approved: vec![],
                denied: vec![],
            },
            audit_event,
            profile,
            workspace_policy,
            policy_findings: vec![finding],
            schema_validation: SchemaValidation {
                tool_name: input.action.tool_name.clone(),
                valid: true,
                findings: vec![],
            },
            review_request_id: None,
            session_graph: None,
            taint_analysis: None,
            adaptive_risk: None,
            sandbox_result: None,
            injection_firewall: None,
            policy_verification: None,
            telemetry_span: None,
            behavioral_fingerprint: None,
            threat_intel: None,
        });
    }

    let protocol = detect_protocol(input);

    let normalized_payload = if protocol == ProtocolKind::Mcp {
        normalize_mcp_payload(input)
    } else {
        input.action.payload.clone()
    };

    let schema_validation = if protocol == ProtocolKind::Mcp {
        validate_mcp_tool(input)
    } else {
        SchemaValidation {
            tool_name: input.action.tool_name.clone(),
            valid: true,
            findings: vec!["non-MCP protocol, schema validation skipped".to_string()],
        }
    };

    let action_type_s = action_type_str(input.action.action_type);
    let payload_json = serde_json::Value::Object(
        input
            .action
            .payload
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    let payload_str = serde_json::to_string(&payload_json).unwrap_or_default();

    // ═══════════════════════════════════════════════════════════════
    // LAYER 7 — Prompt Injection Firewall (runs FIRST, fastest gate)
    // ═══════════════════════════════════════════════════════════════
    let firewall_result = prompt_firewall::scan_prompt(&payload_str);
    let firewall_json = serde_json::to_value(&firewall_result).ok();

    // ═══════════════════════════════════════════════════════════════
    // THREAT INTELLIGENCE — check payload against known IOCs
    // ═══════════════════════════════════════════════════════════════
    let threat_matches = state.threat_feed.check_threats(&payload_str);
    let threat_intel_json = if threat_matches.is_empty() {
        None
    } else {
        serde_json::to_value(serde_json::json!({
            "matches": threat_matches,
            "count": threat_matches.len(),
        }))
        .ok()
    };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 1 — Session Graph Analysis
    // ═══════════════════════════════════════════════════════════════
    let session_id = input
        .metadata
        .as_ref()
        .and_then(|m| m.get("sessionId"))
        .and_then(|v| v.as_str())
        .unwrap_or(&input.agent_id);

    // We need inherited taints for session graph too, so get them first
    let inherited_taints = taint_tracker::get_session_taint(session_id);

    let session_result = session_dag::add_tool_call_to_session(
        session_id,
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        inherited_taints.clone(),
    );
    let session_json = serde_json::to_value(&session_result).ok();

    // ═══════════════════════════════════════════════════════════════
    // LAYER 2 — Taint Tracking
    // ═══════════════════════════════════════════════════════════════
    let taint_result = taint_tracker::analyze_taint(
        action_type_s,
        &input.action.tool_name,
        &payload_str,
        &inherited_taints,
    );
    taint_tracker::update_session_taint(session_id, &taint_result.accumulated_labels);
    let taint_json = serde_json::to_value(&taint_result).ok();

    // ═══════════════════════════════════════════════════════════════
    // LAYER 3 — Crypto NHI (ensure agent identity exists)
    // ═══════════════════════════════════════════════════════════════
    if crypto_identity::get_identity(&input.agent_id).is_none() {
        crypto_identity::register_identity(
            &input.agent_id,
            Some(workspace_id),
            profile.approved_tools.clone(),
        );
    }
    let agent_trust = crypto_identity::get_agent_trust(&input.agent_id);

    // ═══════════════════════════════════════════════════════════════
    // LAYER 4 — Adaptive Risk Scoring (5-signal ensemble)
    // ═══════════════════════════════════════════════════════════════
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let call_timestamps = vec![now_ms]; // simplified; real system accumulates

    let adaptive_input = AdaptiveScoreInput {
        agent_id: &input.agent_id,
        action_type: action_type_s,
        tool_name: &input.action.tool_name,
        payload_str: &payload_str,
        taint_result: Some(&taint_result),
        session_call_count: 1, // each pipeline invocation is one call
        call_timestamps: &call_timestamps,
        agent_trust,
        tool_trust: profile.tool_trust,
    };
    let adaptive_result = adaptive_scorer::calculate_adaptive_risk(&adaptive_input);
    let adaptive_json = serde_json::to_value(&adaptive_result).ok();

    // Update baseline for future behavioral analysis
    adaptive_scorer::update_baseline(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        1, // single call per pipeline invocation
    );

    // ═══════════════════════════════════════════════════════════════
    // Behavioral Fingerprinting — record action & detect anomalies
    // ═══════════════════════════════════════════════════════════════
    state.behavioral_engine.record_action(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        adaptive_result.total_score as f64,
    );
    let fingerprint_anomalies = state.behavioral_engine.detect_anomalies(
        &input.agent_id,
        &input.action.tool_name,
        adaptive_result.total_score as f64,
    );

    // ═══════════════════════════════════════════════════════════════
    // LAYER 5 — Sandbox Execution (dry-run for high-risk)
    // ═══════════════════════════════════════════════════════════════
    let sandbox_json =
        if sandbox_executor::should_sandbox(action_type_s, adaptive_result.total_score) {
            let sb = sandbox_executor::sandbox_execute(
                &input.action.tool_name,
                action_type_s,
                &payload_json,
                adaptive_result.total_score,
            );
            serde_json::to_value(&sb).ok()
        } else {
            None
        };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 6 — Formal Policy Verification
    // ═══════════════════════════════════════════════════════════════
    let verification = formal_verify::verify_policy(&workspace_policy);
    let verification_json = serde_json::to_value(&verification).ok();

    // ═══════════════════════════════════════════════════════════════
    // Original policy evaluation + risk scoring
    // ═══════════════════════════════════════════════════════════════
    let policy_eval = evaluate_policy(input, &profile, &workspace_policy, protocol);
    let secret_plan = plan_secret_injection(input, &profile);
    let secret_denied = !secret_plan.denied.is_empty();

    let mut policy_findings = policy_eval.findings;

    if secret_denied {
        policy_findings
            .push("one or more requested secrets were denied by vault policy".to_string());
    }
    if !schema_validation.valid {
        policy_findings.push("MCP tool schema validation failed".to_string());
    }

    // ═══════════════════════════════════════════════════════════════
    // Integrate 8-layer signals into decision + layer risk scores
    // ═══════════════════════════════════════════════════════════════
    let mut minimum_decision = policy_eval.minimum_decision;
    let mut layer_risks = LayerRiskContributions {
        firewall: firewall_result.risk_score,
        ..Default::default()
    };

    // ── Firewall ──
    if firewall_result.blocked {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!("injection firewall: {}", firewall_result.summary));
    }

    // ── Threat Intelligence ──
    if !threat_matches.is_empty() {
        for tm in &threat_matches {
            policy_findings.push(format!(
                "threat intel [{}]: {} (severity={})",
                tm.indicator_type, tm.description, tm.severity
            ));
        }
        let has_critical = threat_matches.iter().any(|m| m.severity == "critical");
        let has_high = threat_matches.iter().any(|m| m.severity == "high");
        layer_risks.threat_intel = if has_critical {
            95
        } else if has_high {
            75
        } else {
            50
        };
        if has_critical {
            minimum_decision = GovernanceDecision::Block;
        } else if has_high && minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // ── Taint ──
    if taint_result.exfiltration_detected {
        layer_risks.taint = 100;
    } else if taint_result.blocked {
        layer_risks.taint = 90;
    } else if !taint_result.violations.is_empty() {
        layer_risks.taint = 60 + (taint_result.violations.len() as u32 * 10).min(30);
    }
    if taint_result.blocked {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!("taint tracking: {}", taint_result.summary));
    }

    // ── Session Graph ──
    layer_risks.session_graph = session_result.anomaly_score;
    if !session_result.attacks_detected.is_empty() || session_result.anomaly_score >= 50 {
        if minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
        for attack in &session_result.attacks_detected {
            policy_findings.push(format!("session graph attack: {}", attack.name));
        }
        for reason in &session_result.anomaly_reasons {
            policy_findings.push(format!("session graph: {}", reason));
        }
    }
    if !session_result.transition_allowed {
        minimum_decision = GovernanceDecision::Block;
        layer_risks.session_graph = layer_risks.session_graph.max(90);
        policy_findings.push("session graph: state transition blocked".into());
    }

    // ── Adaptive Risk ──
    layer_risks.adaptive = adaptive_result.total_score;
    if adaptive_result.decision == "block" {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!(
            "adaptive risk: score={} → block",
            adaptive_result.total_score
        ));
    } else if adaptive_result.decision == "human_review"
        && minimum_decision != GovernanceDecision::Block
    {
        minimum_decision = GovernanceDecision::Review;
        policy_findings.push(format!(
            "adaptive risk: score={} → review",
            adaptive_result.total_score
        ));
    }

    // ── Behavioral Fingerprint ──
    if !fingerprint_anomalies.is_empty() {
        layer_risks.behavioral = 60 + (fingerprint_anomalies.len() as u32 * 10).min(40);
        for flag in &fingerprint_anomalies {
            policy_findings.push(format!("behavioral fingerprint: {}", flag));
        }
        if minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // ── Policy ──
    // Score based on how many policy violations were found
    let policy_violation_count = policy_findings
        .iter()
        .filter(|f| {
            f.contains("not approved")
                || f.contains("outside baseline")
                || f.contains("requires human review")
                || f.contains("action type")
        })
        .count();
    if policy_violation_count > 0 {
        layer_risks.policy = (30 + policy_violation_count as u32 * 20).min(100);
    }

    // ── Secrets ──
    if secret_denied {
        layer_risks.secrets = 90;
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push("unauthorized secret access denied by vault policy".into());
    }
    if !schema_validation.valid && minimum_decision != GovernanceDecision::Block {
        minimum_decision = GovernanceDecision::Block;
    }

    let risk = score_tool_risk(input, minimum_decision, &policy_findings, &layer_risks);

    // Build audit event
    let mut reasons = risk.reasons.clone();
    reasons.push(format!("agent-role:{:?}", profile.role).to_lowercase());
    let audit_event = AuditEvent {
        event_id: Uuid::new_v4().to_string(),
        agent_id: input.agent_id.clone(),
        framework: input.framework.clone(),
        action_type: input.action.action_type,
        tool_name: input.action.tool_name.clone(),
        decision: risk.decision,
        timestamp: Utc::now().to_rfc3339(),
        reasons,
    };

    let review_status = if risk.decision == GovernanceDecision::Review {
        ReviewStatus::Pending
    } else {
        ReviewStatus::NotRequired
    };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 8 — Telemetry
    // ═══════════════════════════════════════════════════════════════
    let duration_ms = pipeline_start.elapsed().as_millis() as u64;
    let decision_str = format!("{:?}", risk.decision).to_lowercase();

    let mut layer_attrs = HashMap::new();
    layer_attrs.insert(
        "session_graph".into(),
        serde_json::json!(session_result.new_state),
    );
    layer_attrs.insert(
        "taint_blocked".into(),
        serde_json::json!(taint_result.blocked),
    );
    layer_attrs.insert(
        "firewall_score".into(),
        serde_json::json!(firewall_result.risk_score),
    );
    layer_attrs.insert(
        "adaptive_score".into(),
        serde_json::json!(adaptive_result.total_score),
    );

    let telemetry_span = otel_emitter::emit_governance_span(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        &decision_str,
        risk.score,
        duration_ms,
        layer_attrs,
    );
    otel_emitter::emit_pipeline_metrics(&decision_str, risk.score, duration_ms, action_type_s);
    let telemetry_json = serde_json::to_value(&telemetry_span).ok();

    // Update NHI trust based on outcome (severity-aware)
    crypto_identity::update_trust_from_decision(&input.agent_id, &decision_str, risk.score);

    let mut result = GovernanceResult {
        protocol,
        normalized_payload,
        decision: risk.decision,
        review_status,
        risk,
        secret_plan,
        audit_event,
        profile,
        workspace_policy,
        policy_findings,
        schema_validation,
        review_request_id: None,
        // 8-layer results
        session_graph: session_json,
        taint_analysis: taint_json,
        adaptive_risk: adaptive_json,
        sandbox_result: sandbox_json,
        injection_firewall: firewall_json,
        policy_verification: verification_json,
        telemetry_span: telemetry_json,
        behavioral_fingerprint: state
            .behavioral_engine
            .get_fingerprint(&input.agent_id)
            .and_then(|fp| serde_json::to_value(fp).ok()),
        threat_intel: threat_intel_json,
    };

    // Persist audit event
    let stored = StoredAuditEvent {
        event_id: result.audit_event.event_id.clone(),
        agent_id: result.audit_event.agent_id.clone(),
        framework: result.audit_event.framework.clone(),
        action_type: result.audit_event.action_type,
        tool_name: result.audit_event.tool_name.clone(),
        decision: result.audit_event.decision,
        timestamp: result.audit_event.timestamp.clone(),
        reasons: result.audit_event.reasons.clone(),
        review_status: result.review_status,
        risk_score: result.risk.score,
    };
    state.audit_store.append(&stored).await?;

    // Create review request if needed
    if result.decision == GovernanceDecision::Review {
        let now = Utc::now().to_rfc3339();
        let mut review_reasons = result.policy_findings.clone();
        review_reasons.extend(result.risk.reasons.clone());

        let review = ReviewRequest {
            id: Uuid::new_v4().to_string(),
            agent_id: result.profile.agent_id.clone(),
            workspace_id: result.profile.workspace_id.clone(),
            tool_name: result.audit_event.tool_name.clone(),
            decision: result.decision,
            status: "pending".to_string(),
            risk_score: result.risk.score,
            reasons: review_reasons,
            created_at: now.clone(),
            updated_at: now,
        };

        state.review_store.create(&review).await?;
        result.review_request_id = Some(review.id);
        result.review_status = ReviewStatus::Pending;
    }

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════
// Response-Side Scanning
// ═══════════════════════════════════════════════════════════════

struct SensitivePatternDef {
    name: &'static str,
    description: &'static str,
    category: &'static str,
    regex: &'static str,
    redact_with: &'static str,
}

const SENSITIVE_PATTERNS: &[SensitivePatternDef] = &[
    SensitivePatternDef {
        name: "ssn",
        description: "US Social Security Number",
        category: "pii",
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
        redact_with: "[REDACTED-SSN]",
    },
    SensitivePatternDef {
        name: "credit_card",
        description: "Credit card number (Visa, MC, Amex, Discover)",
        category: "financial",
        regex: r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b",
        redact_with: "[REDACTED-CC]",
    },
    SensitivePatternDef {
        name: "aws_access_key",
        description: "AWS Access Key ID",
        category: "credential",
        regex: r"\bAKIA[0-9A-Z]{16}\b",
        redact_with: "[REDACTED-AWS-KEY]",
    },
    SensitivePatternDef {
        name: "aws_secret_key",
        description: "AWS Secret Access Key",
        category: "credential",
        regex: r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        redact_with: "[REDACTED-AWS-SECRET]",
    },
    SensitivePatternDef {
        name: "github_token",
        description: "GitHub personal access token",
        category: "credential",
        regex: r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
        redact_with: "[REDACTED-GH-TOKEN]",
    },
    SensitivePatternDef {
        name: "openai_api_key",
        description: "OpenAI API key",
        category: "credential",
        regex: r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
        redact_with: "[REDACTED-OPENAI-KEY]",
    },
    SensitivePatternDef {
        name: "generic_api_key",
        description: "Generic API key in assignment",
        category: "credential",
        regex: r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?"#,
        redact_with: "[REDACTED-API-KEY]",
    },
    SensitivePatternDef {
        name: "password_assignment",
        description: "Password in assignment or config",
        category: "credential",
        regex: r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?"#,
        redact_with: "[REDACTED-PASSWORD]",
    },
    SensitivePatternDef {
        name: "private_key_block",
        description: "PEM private key block",
        category: "credential",
        regex: r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----",
        redact_with: "[REDACTED-PRIVATE-KEY]",
    },
    SensitivePatternDef {
        name: "bearer_token",
        description: "Bearer authentication token",
        category: "credential",
        regex: r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
        redact_with: "[REDACTED-BEARER]",
    },
    SensitivePatternDef {
        name: "connection_string",
        description: "Database connection string with credentials",
        category: "credential",
        regex: r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s@]+:[^\s@]+@",
        redact_with: "[REDACTED-CONN-STRING]",
    },
];

/// Build compiled regex patterns (cached via Lazy).
static COMPILED_PATTERNS: Lazy<Vec<(Regex, &'static SensitivePatternDef)>> = Lazy::new(|| {
    SENSITIVE_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.regex).ok().map(|re| (re, p)))
        .collect()
});

/// Return the list of sensitive patterns being checked.
pub fn get_sensitive_patterns() -> Vec<SensitivePattern> {
    SENSITIVE_PATTERNS
        .iter()
        .map(|p| SensitivePattern {
            name: p.name.to_string(),
            description: p.description.to_string(),
            category: p.category.to_string(),
        })
        .collect()
}

/// Scan a tool response for prompt injection, taint leaks, and sensitive data.
pub fn scan_response(input: &ResponseScanRequest) -> ResponseScanResult {
    let payload_str = serde_json::to_string(&input.response_payload).unwrap_or_default();
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: u32 = 0;

    // ── Check 1: Injection firewall on response content ──
    let firewall_result = prompt_firewall::scan_prompt(&payload_str);
    if firewall_result.blocked {
        findings.push(format!("injection firewall: {}", firewall_result.summary));
    }
    if firewall_result.risk_score > risk_score {
        risk_score = firewall_result.risk_score;
    }

    // ── Check 2: Taint tracking (detect secret/credential leaks) ──
    let inherited_taints = input
        .metadata
        .as_ref()
        .and_then(|m| m.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(taint_tracker::get_session_taint)
        .unwrap_or_default();

    let taint_result = taint_tracker::analyze_taint(
        "http", // response is coming back from a tool, treat as network data
        &input.tool_name,
        &payload_str,
        &inherited_taints,
    );
    if taint_result.blocked {
        findings.push(format!("taint tracking: {}", taint_result.summary));
        if risk_score < 80 {
            risk_score = 80;
        }
    }
    if taint_result.exfiltration_detected {
        findings.push("taint: potential data exfiltration in response".to_string());
    }

    // ── Check 3: Sensitive pattern matching with redaction ──
    let mut redacted = payload_str.clone();
    let mut has_sensitive = false;

    for (re, pat) in COMPILED_PATTERNS.iter() {
        if re.is_match(&redacted) {
            has_sensitive = true;
            let count = re.find_iter(&redacted).count();
            findings.push(format!(
                "sensitive pattern: {} ({} occurrence{})",
                pat.name,
                count,
                if count > 1 { "s" } else { "" }
            ));
            // Each pattern category carries different weight
            let pattern_score = match pat.category {
                "credential" => 70,
                "financial" => 75,
                "pii" => 65,
                _ => 50,
            };
            if pattern_score > risk_score {
                risk_score = pattern_score;
            }
            redacted = re.replace_all(&redacted, pat.redact_with).to_string();
        }
    }

    // ── Build decision ──
    let decision = if risk_score >= 80 {
        ResponseDecision::Block
    } else if risk_score >= 40 {
        ResponseDecision::Review
    } else {
        ResponseDecision::Allow
    };

    let redacted_payload = if has_sensitive {
        serde_json::from_str::<serde_json::Value>(&redacted)
            .ok()
            .or(Some(serde_json::Value::String(redacted)))
    } else {
        None
    };

    ResponseScanResult {
        request_id: input.request_id.clone(),
        decision,
        risk_score,
        findings,
        redacted_payload,
    }
}
