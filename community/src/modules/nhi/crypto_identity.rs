//! LAYER 3 — Non-Human Identity (NHI)
//!
//! SPIFFE-style identity for agents, HMAC-SHA256 attestation,
//! capability tokens with expiry, and mutual verification.
//!
//! **v0.1 limitations:** Attestation is simulated server-side (the server
//! signs on behalf of the agent). Real agent-side challenge-response signing
//! is planned for v0.2 when the agent SDKs support it.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ── Types ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentity {
    pub agent_id: String,
    pub spiffe_id: String,
    pub public_key_hex: String,
    pub created_at: String,
    pub attestation_status: String,
    pub trust_score: f64,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
struct StoredIdentity {
    pub identity: AgentIdentity,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityToken {
    pub token_id: String,
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub signature: String,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResult {
    pub agent_id: String,
    pub verified: bool,
    pub spiffe_id: String,
    pub trust_score: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutualAttestationResult {
    pub initiator: AttestationResult,
    pub responder: AttestationResult,
    pub mutual_trust: f64,
    pub session_token: Option<String>,
}

// ── Store ──

static IDENTITIES: Lazy<Mutex<HashMap<String, StoredIdentity>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static TOKENS: Lazy<Mutex<HashMap<String, CapabilityToken>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// ── Key Derivation ──

fn get_master_seed() -> Vec<u8> {
    std::env::var("AGENT_ARMOR_NHI_MASTER_SEED")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|_| {
            tracing::warn!(
                "AGENT_ARMOR_NHI_MASTER_SEED not set — using random ephemeral seed. \
                 Set this env var for persistent identity across restarts."
            );
            // Generate a random seed for this process lifetime
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            seed.to_vec()
        })
}

fn derive_keypair(agent_id: &str) -> (Vec<u8>, String) {
    // Derive deterministic secret from agent_id + master seed
    let master_seed = get_master_seed();
    let mut mac = HmacSha256::new_from_slice(&master_seed).expect("HMAC accepts any key size");
    mac.update(agent_id.as_bytes());
    let secret = mac.finalize().into_bytes().to_vec();

    // Public key = HMAC(secret, "public")
    let mut pub_mac = HmacSha256::new_from_slice(&secret).expect("HMAC accepts any key size");
    pub_mac.update(b"public-key-derivation");
    let public = pub_mac.finalize().into_bytes();
    let pub_hex = hex::encode(public);

    (secret, pub_hex)
}

fn sign(secret: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_signature(secret: &[u8], message: &str, signature: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(message.as_bytes());
    // Decode the hex signature and verify with constant-time comparison
    match hex::decode(signature) {
        Ok(sig_bytes) => mac.verify_slice(&sig_bytes).is_ok(),
        Err(_) => false,
    }
}

// ── SPIFFE ID ──

fn build_spiffe_id(agent_id: &str, workspace_id: Option<&str>) -> String {
    let ws = workspace_id.unwrap_or("default");
    format!("spiffe://agent-armor/{}/agent/{}", ws, agent_id)
}

// ── Identity Management ──

pub fn register_identity(
    agent_id: &str,
    workspace_id: Option<&str>,
    capabilities: Vec<String>,
) -> AgentIdentity {
    let (secret, pub_hex) = derive_keypair(agent_id);
    let spiffe_id = build_spiffe_id(agent_id, workspace_id);

    let identity = AgentIdentity {
        agent_id: agent_id.to_string(),
        spiffe_id,
        public_key_hex: pub_hex,
        created_at: Utc::now().to_rfc3339(),
        attestation_status: "registered".into(),
        trust_score: 0.5,
        capabilities: capabilities.clone(),
    };

    let stored = StoredIdentity {
        identity: identity.clone(),
        secret_key: secret,
    };

    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(agent_id.to_string(), stored);
    identity
}

pub fn get_identity(agent_id: &str) -> Option<AgentIdentity> {
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(agent_id)
        .map(|s| s.identity.clone())
}

pub fn list_identities() -> Vec<AgentIdentity> {
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|s| s.identity.clone())
        .collect()
}

// ── Attestation ──

/// Attest an agent via challenge-response.
///
/// **NOTE:** In v0.1 this performs a *simulated* attestation — the server
/// signs the challenge on behalf of the agent. Real challenge-response
/// (where the agent signs and returns the signature) will land in v0.2.
pub fn attest_agent(agent_id: &str, challenge: &str) -> AttestationResult {
    let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(stored) = store.get(agent_id) {
        // Simulated: server verifies its own signature as a placeholder
        // for real agent-side signing (see roadmap for v0.2 agent SDK attestation)
        let expected_sig = sign(&stored.secret_key, challenge);
        let verified = verify_signature(&stored.secret_key, challenge, &expected_sig);
        AttestationResult {
            agent_id: agent_id.to_string(),
            verified,
            spiffe_id: stored.identity.spiffe_id.clone(),
            trust_score: stored.identity.trust_score,
            reason: "simulated attestation (v0.1) — agent SDK signing in v0.2".into(),
        }
    } else {
        AttestationResult {
            agent_id: agent_id.to_string(),
            verified: false,
            spiffe_id: String::new(),
            trust_score: 0.0,
            reason: "unknown agent — no identity registered".into(),
        }
    }
}

pub fn mutual_attest(initiator_id: &str, responder_id: &str) -> MutualAttestationResult {
    let challenge = Uuid::new_v4().to_string();
    let init_result = attest_agent(initiator_id, &challenge);
    let resp_result = attest_agent(responder_id, &challenge);

    let mutual_trust = if init_result.verified && resp_result.verified {
        (init_result.trust_score + resp_result.trust_score) / 2.0
    } else {
        0.0
    };

    let session_token = if init_result.verified && resp_result.verified {
        let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(init_stored) = store.get(initiator_id) {
            let token_data = format!("{}:{}:{}", initiator_id, responder_id, challenge);
            Some(sign(&init_stored.secret_key, &token_data))
        } else {
            None
        }
    } else {
        None
    };

    MutualAttestationResult {
        initiator: init_result,
        responder: resp_result,
        mutual_trust,
        session_token,
    }
}

// ── Capability Tokens ──

pub fn issue_capability_token(
    agent_id: &str,
    capabilities: Vec<String>,
    ttl_seconds: i64,
) -> Option<CapabilityToken> {
    let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    let stored = store.get(agent_id)?;

    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_seconds);
    let token_id = Uuid::new_v4().to_string();

    let payload = format!(
        "{}:{}:{}:{}",
        token_id,
        agent_id,
        capabilities.join(","),
        expires.to_rfc3339()
    );
    let signature = sign(&stored.secret_key, &payload);

    let token = CapabilityToken {
        token_id: token_id.clone(),
        agent_id: agent_id.to_string(),
        capabilities,
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        signature,
        valid: true,
    };

    drop(store);
    TOKENS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(token_id, token.clone());
    Some(token)
}

pub fn verify_capability_token(token_id: &str, required_capability: &str) -> bool {
    let tokens = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(token) = tokens.get(token_id) {
        if !token.valid {
            return false;
        }
        // Check expiry
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&token.expires_at) {
            if Utc::now() > expires {
                return false;
            }
        }
        // Check capability
        token
            .capabilities
            .contains(&required_capability.to_string())
            || token.capabilities.contains(&"*".to_string())
    } else {
        false
    }
}

pub fn revoke_token(token_id: &str) -> bool {
    let mut tokens = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(token) = tokens.get_mut(token_id) {
        token.valid = false;
        true
    } else {
        false
    }
}

// ── Trust Score Updates ──

/// Update trust score with a severity-aware delta.
///
/// Use `update_trust_from_decision` for the standard pipeline path.
/// This raw function is kept for direct callers.
pub fn update_trust_score(agent_id: &str, delta: f64) -> Option<f64> {
    let mut store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(stored) = store.get_mut(agent_id) {
        stored.identity.trust_score = (stored.identity.trust_score + delta).clamp(0.0, 1.0);
        Some(stored.identity.trust_score)
    } else {
        None
    }
}

/// Severity-aware trust update based on the actual risk score.
///
/// - ALLOW:  +0.02 (was +0.01 — faster recovery)
/// - BLOCK with risk < 50 (policy violation, not malicious): -0.01
/// - BLOCK with risk 50-79 (suspicious): -0.03
/// - BLOCK with risk >= 80 (clearly malicious): -0.05
/// - REVIEW: -0.005 (slight penalty, pending human judgment)
///
/// This replaces the old flat -0.05/-0.01 system that made trust
/// unrecoverable after any burst of blocks.
pub fn update_trust_from_decision(agent_id: &str, decision: &str, risk_score: u32) -> Option<f64> {
    let delta = match decision {
        "allow" => 0.02,
        "review" => -0.005,
        "block" => {
            if risk_score >= 80 {
                -0.05
            } else if risk_score >= 50 {
                -0.03
            } else {
                -0.01
            }
        }
        _ => 0.0,
    };
    update_trust_score(agent_id, delta)
}

/// Get the trust score for use in the adaptive risk scorer
pub fn get_agent_trust(agent_id: &str) -> f64 {
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(agent_id)
        .map(|s| s.identity.trust_score)
        .unwrap_or(0.5)
}
