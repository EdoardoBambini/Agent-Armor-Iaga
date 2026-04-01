# Architecture

## 8-Layer Security Pipeline

Every agent request passes through all 8 layers in sequence:

```
Request → DPI → Taint → NHI → Risk → Sandbox → Policy → Firewall → Telemetry → Decision
```

### Layer 1: Protocol Deep Packet Inspection
- Detects MCP, ACP, and HTTP function call protocols
- Parses and normalizes action envelopes
- Validates tool calls against registered MCP schemas

### Layer 2: Taint Tracking
- Tracks data provenance through agent execution chains
- Labels data with taint markers (credential, PII, internal)
- Detects exfiltration when tainted data flows to external sinks

### Layer 3: Non-Human Identity Registry
- Every agent gets a cryptographic identity (HMAC-SHA256)
- Key pair generation and storage
- Signed attestation for agent actions

### Layer 4: Adaptive Risk Scoring
- 5-weight model: statistical, contextual, behavioral, temporal, reputation
- Weights are adjustable per deployment
- Produces a 0-100 risk score that drives the governance decision

### Layer 5: Sandbox Execution
- Isolates tool execution in a controlled environment
- Captures network calls, DB operations, and filesystem changes
- Requires human approval for high-impact operations

### Layer 6: Policy Engine
- Formal verification of workspace policies
- Checks consistency (no contradictions), completeness (no gaps), satisfiability
- Reports coverage percentage and specific issues

### Layer 7: Injection Firewall
- 3-stage defense: pattern matching → entropy analysis → structural validation
- Catches prompt injection, jailbreaks, and indirect prompt attacks
- Reports per-stage catch rates and false positive tracking

### Layer 8: Observability
- OpenTelemetry-compatible span emission
- Real-time SSE event stream for dashboards
- HMAC-signed webhook delivery to external systems

## Advanced Modules (Tier 2)

These modules extend the core pipeline with production-hardening capabilities.

### Response Scanning
- Scans agent output for sensitive data before delivery
- Pattern-based detection of PII, credentials, API keys, internal paths
- Built-in patterns for common secret formats (AWS keys, JWTs, database URIs, etc.)
- Integrated into the pipeline as a post-decision output filter

### Rate Limiting
- Per-agent sliding window rate limiter
- Configurable requests-per-second, burst allowances, and cooldown periods
- Tracks quota consumption per agent ID
- Returns remaining quota and reset timestamps in status responses
- Enforced as a pre-pipeline check to reject requests before they consume compute

### Agent Fingerprinting
- Builds behavioral profiles from agent tool usage patterns
- Tracks action type distribution, timing cadence, and tool preference sequences
- Detects anomalous behavior that deviates from an agent's established baseline
- Fingerprints are stored in-memory and queryable per agent
- Integrated with the risk scoring layer to elevate scores for anomalous agents

### Threat Intelligence
- Maintains a local indicator-of-compromise (IOC) database
- Supports indicator types: IP addresses, domains, file hashes, URLs, custom patterns
- Check endpoint evaluates agent action payloads against known indicators
- Statistics endpoint reports match counts and indicator coverage
- Indicators can be added, listed, and removed via the REST API

## Deployment Modes

### Gateway Mode (default)

All agent traffic routes through Agent Armor as a central gateway:

```
Agent → Agent Armor Gateway → Tool
```

Best for: multi-agent environments, centralized policy management.

### Sidecar Mode

Agent Armor runs alongside each agent as a local process:

```
Agent ↔ Agent Armor Sidecar → Tool
```

Best for: Kubernetes, containerized agents, tight local enforcement.

## Tech Stack

- **Runtime**: Rust + Tokio async runtime
- **HTTP**: Axum 0.8 with Tower middleware
- **Storage**: SQLite via sqlx (async)
- **Auth**: Argon2 password hashing, Bearer token middleware
- **Crypto**: HMAC-SHA256 for NHI identity attestation
- **Events**: Tokio broadcast channels → SSE + webhooks
- **Config**: JSON + YAML support via serde

## Module Boundaries

```
community/src/
├── server/          → HTTP ingress, routing, auth
├── pipeline/        → Orchestration only (calls each layer)
├── modules/
│   ├── protocol/    → Layer 1: DPI
│   ├── taint/       → Layer 2: Taint tracking
│   ├── nhi/         → Layer 3: Identity
│   ├── risk/        → Layer 4: Scoring
│   ├── sandbox/     → Layer 5: Isolation
│   ├── policy/      → Layer 6: Verification
│   ├── injection_firewall/ → Layer 7: Firewall
│   ├── telemetry/   → Layer 8: Observability
│   ├── audit/       → Cross-cutting: audit trail
│   ├── review/      → Cross-cutting: human review queue
│   ├── secrets/     → Cross-cutting: secret references
│   ├── session_graph/ → Cross-cutting: session DAG
│   ├── rate_limit/  → Tier 2: per-agent rate limiting
│   ├── fingerprint/ → Tier 2: behavioral agent fingerprinting
│   └── threat_intel/ → Tier 2: threat intelligence feed
├── events/          → Event bus, SSE, webhooks
├── storage/         → Persistence traits + SQLite impl
└── auth/            → API key management + middleware
```
