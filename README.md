<h1 align="center">Agent Armor</h1>

<p align="center">
  <strong>Zero-trust governance runtime for AI agent actions</strong>
</p>

<p align="center">
  <a href="#agent-armor-040-community">v0.4.0</a> -
  <a href="#quick-start">Quick Start</a> -
  <a href="#what-ships-in-community-040">Community Features</a> -
  <a href="#docs">Docs</a> -
  <a href="#testing-and-verification">Testing</a>
</p>

<p align="center">
  <a href="https://github.com/EdoardoBambini/Agent-Armor-Iaga/actions"><img src="https://github.com/EdoardoBambini/Agent-Armor-Iaga/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BUSL--1.1-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/version-0.4.0-purple" alt="Version 0.4.0">
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
</p>

<p align="center">
  <img src="assets/hero.gif" alt="Agent Armor" width="600">
</p>

---

## Agent Armor 0.4.0 Community

`0.4.0` is the current community release in this repository.

It ships a real governance runtime with:

- the full 8-layer pipeline
- sequence-aware session hardening for same-session multi-call behavior
- persisted workspace rules and built-in policy templates
- feature-gated WASM plugin loading, runtime evaluation, and CLI inspection
- SQLite by default plus optional PostgreSQL support
- expanded Python and TypeScript SDKs plus lightweight framework adapters
- live HTTP end-to-end tests, CLI tests, and real plugin-path validation

It is stronger than `0.3.0`, but it is still not the end of the full roadmap.
The main remaining gaps are the durable-state restart story and the advanced CLI
commands called out below.

## Why It Exists

AI agents now get shell access, file access, HTTP access, database access, and
secret access. Most stacks can execute tool calls, but they do not govern them
well.

Agent Armor sits in front of those actions and decides:

- `allow`
- `review`
- `block`

with an audit trail, risk scoring, and per-layer evidence.

## What Ships In Community 0.4.0

### Core Runtime

- 8-layer deterministic governance pipeline
- MCP-aware inspection path
- ACP and A2A protocol inspection with built-in envelope validation
- policy evaluation with workspace thresholds
- policy templates and persisted workspace rules
- secret reference planning
- human review queue
- audit trail and audit export
- MCP proxy mode and MCP server mode over stdio

### 0.4.0 Hardening And Extensibility

- adaptive risk scoring now consumes real session depth and recent timestamps
- same-session arcs like `file_read -> http` are tested through integration and
  live HTTP paths
- WASM plugin runtime is wired into the pipeline and exposed via:
  - `GET /v1/plugins`
  - `POST /v1/plugins/reload`
  - `agent-armor plugins list`
  - `agent-armor plugins validate <path.wasm>`
- `community/examples/plugins/review_hint.wat` is compiled and validated in
  tests and CI

### SDKs And Adapters

- Python SDK covers governance, policy, plugin, audit, telemetry, review,
  threat intel, NHI, response, and rate-limit endpoints
- TypeScript SDK covers the same runtime surface with `sessionId` support
- dependency-light adapters are included for:
  - Python: OpenAI, LangChain, CrewAI, AutoGen
  - TypeScript: OpenAI, Vercel AI style middleware helpers

### Operational Security Features

- response scanning for secrets and PII in outputs
- per-agent rate limiting
- behavioral fingerprinting
- threat intelligence feed and checks
- SSE and webhook event delivery with DLQ

### Storage And Runtime Hardening

- SQLite storage backend
- optional PostgreSQL backend behind `--features postgres`
- versioned migrations in `community/migrations/`
- `agent-armor migrate` for schema bootstrap and update
- structured logging: `pretty`, `compact`, `json`
- log filtering via `RUST_LOG` or `AGENT_ARMOR_LOG_LEVEL`
- request and response correlation with `x-request-id`
- governance result correlation with `traceId`

## Current Community Limits

The following community items are still missing or incomplete:

- durable-state persistence is only partially closed as a restart story
  `nhi`, `session_graph`, `taint`, `fingerprint`, and rate-limit state now have
  storage traits and persistence hooks, but startup hydration and restart-proof
  validation are not fully closed yet
- enhanced CLI roadmap items are still open beyond the current commands
  `watch`, `replay`, `benchmark`, and `policy-test` are not shipped yet
- SDK coverage is materially broader now, but some responses are still exposed
  as generic JSON objects instead of fully typed SDK models

### Dashboard Status

The dashboard is a live operator console backed by real runtime endpoints.

It supports:

- live overview metrics sourced from the audit, review, session, and analytics APIs
- audit browsing with client-side filtering and CSV export of visible rows
- a real review queue with approve and reject actions
- selected-agent drill-down backed by analytics, fingerprint, and rate-limit endpoints
- runtime controls and posture panels backed by health, firewall, threat intel, telemetry, and policy verification data

When the runtime is protected, the dashboard requires a valid API key and does
not fall back to fake demo counters.

## Quick Start

### Source

```bash
cd community
cargo build --release

# Create a key before starting the server
./target/release/agent-armor gen-key --label local-dev

# Start the runtime
./target/release/agent-armor serve

# Inspect discovered plugins
./target/release/agent-armor plugins list
```

Open `http://localhost:4010` for the dashboard.

### Docker

```bash
docker compose up -d
docker compose exec agent-armor ./agent-armor gen-key --label local-dev
```

### Bootstrap Modes

Protected `/v1/*` routes require a Bearer token.

Preferred bootstrap path:

```bash
cd community
./target/release/agent-armor gen-key --label local-dev
./target/release/agent-armor serve
```

For local exploration only, you can opt into open mode:

```bash
AGENT_ARMOR_OPEN_MODE=true ./target/release/agent-armor serve
```

## Example Calls

```bash
# Health
curl http://localhost:4010/health

# Inspect a safe action
curl -X POST http://localhost:4010/v1/inspect \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "openclaw-builder-01",
    "workspaceId": "ws-demo",
    "framework": "openclaw",
    "metadata": {
      "sessionId": "session-123"
    },
    "protocol": "mcp",
    "action": {
      "type": "file_read",
      "toolName": "filesystem.read",
      "payload": {
        "path": "README.md",
        "intent": "read documentation"
      }
    }
  }'

# Scan a tool response for leaked credentials
curl -X POST http://localhost:4010/v1/response/scan \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "scan-1",
    "agentId": "openclaw-builder-01",
    "toolName": "terminal.exec",
    "responsePayload": {
      "secret": "AKIA1234567890ABCDEF"
    }
  }'

# List plugin registry state
curl http://localhost:4010/v1/plugins \
  -H "Authorization: Bearer <key>"
```

## MCP Stdio Example

Run the built-in MCP client example to exercise `initialize`, `tools/list`, and
`tools/call` against `agent-armor mcp-server` over stdio:

```bash
cd community
cargo run --example mcp_stdio_client
```

## Plugin Example

A real example plugin source lives in `community/examples/plugins/review_hint.wat`.
The runtime loads `.wasm`, so the test and CI path compiles that WAT source and
validates it against the Agent Armor plugin ABI.

## Docs

All current docs for `0.4.0` are linked here.

| Document | Purpose |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Current runtime architecture and module boundaries |
| [`docs/DEMO.md`](docs/DEMO.md) | Demo and local walkthrough |
| [`docs/CASE_STUDY.md`](docs/CASE_STUDY.md) | Historical v2 benchmark and evaluation write-up |
| [`sdks/python/README.md`](sdks/python/README.md) | Python SDK quick start and adapters |
| [`sdks/typescript/README.md`](sdks/typescript/README.md) | TypeScript SDK quick start and adapters |

## API Highlights

### Public

- `GET /`
- `GET /health`

### Governance

- `POST /v1/inspect`
- `GET /v1/audit`
- `GET /v1/audit/export`
- `GET /v1/audit/stats`
- `GET /v1/reviews`

### Profiles And Policies

- `GET/POST /v1/profiles`
- `GET/PUT/DELETE /v1/profiles/:id`
- `GET/POST /v1/workspaces`
- `GET/PUT/DELETE /v1/workspaces/:id`
- `GET/POST /v1/workspaces/:id/rules`
- `GET /v1/templates`
- `GET /v1/templates/:name`

### Response Security

- `POST /v1/response/scan`
- `GET /v1/response/patterns`

### Runtime Controls

- `GET /v1/rate-limit/status/:agent_id`
- `GET/POST /v1/rate-limit/config`
- `GET /v1/firewall/stats`
- `POST /v1/firewall/scan`
- `GET /v1/telemetry/spans`
- `GET /v1/events/stream`
- `GET /v1/plugins`
- `POST /v1/plugins/reload`

### Identity And Auth

- `GET/POST /v1/auth/keys`
- `DELETE /v1/auth/keys/:id`
- `GET/POST /v1/nhi/identities`
- `POST /v1/nhi/attest`
- `POST /v1/nhi/challenge`
- `POST /v1/nhi/verify`

## Testing And Verification

`0.4.0` is verified at four layers plus SDK and plugin-path smoke checks:

- unit tests
- property tests
- direct integration tests
- live HTTP end-to-end tests
- CLI tests
- example plugin compilation and execution tests
- TypeScript SDK build
- Python SDK compile smoke

Current automated coverage:

- `99` unit tests
- `19` property tests
- `10` integration tests
- `8` end-to-end HTTP tests
- `3` CLI tests
- `2` example plugin tests

Total: `173` Rust tests plus TypeScript and Python SDK build checks.

Run them with:

```bash
cd community

# Full Rust suite
cargo test --features plugins

# Example plugin validation only
cargo test --features plugins --test plugin_example_tests

# HTTP E2E only
cargo test --test e2e_http_tests

# PostgreSQL build verification
cargo check --features postgres

# TypeScript SDK build
cd ../sdks/typescript && npm run build

# Python SDK compile smoke
cd ../python && python -m compileall agent_armor
```

The HTTP and integration tests exercise real authenticated requests, persisted
workspace rules, same-session sequence behavior, real plugin directories, and
`pluginResults` propagation in governance responses.

## Open-Core Boundary

Community keeps:

- runtime governance
- storage backends
- migrations
- logging and observability basics
- CLI, HTTP API, MCP proxy, dashboard, SDKs, adapters, and tests

Community does not currently include:

- multi-tenant isolation
- SSO, SAML, JWT, or RBAC
- SIEM integrations
- ML firewall features
- enterprise admin UX

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[Business Source License 1.1](LICENSE)

## Disclaimer

Agent Armor is a governance layer, not a complete security program. Use it as
part of a broader security posture.
