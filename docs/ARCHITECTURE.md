# Architecture

## Release Context

This document describes the current community architecture for `v0.3.0`.

It reflects the code that is actually present in `community/`, including:

- SQLite and optional PostgreSQL storage
- versioned migrations
- structured logging and correlation IDs
- live HTTP E2E verification

## 8-Layer Governance Pipeline

Every governed action flows through the same ordered pipeline:

```text
Request
  -> Protocol DPI
  -> Taint Tracking
  -> NHI Identity
  -> Adaptive Risk
  -> Sandbox / Impact
  -> Policy Evaluation
  -> Injection Firewall
  -> Telemetry
  -> Decision
```

## Layer Summary

### Layer 1 - Protocol DPI

- detects MCP, ACP, A2A, and HTTP-style envelopes
- normalizes and validates MCP, ACP, and A2A request shapes before policy evaluation

### Layer 2 - Taint Tracking

- labels data as it moves through tool actions
- detects exfiltration and unsafe sink usage
- still keeps runtime session state in memory today

### Layer 3 - NHI Registry

- creates non-human identities for agents
- supports challenge-response attestation
- still uses in-memory runtime state today

### Layer 4 - Adaptive Risk

- combines multiple signals into a 0-100 score
- honors per-workspace `thresholdReview` and `thresholdBlock`

### Layer 5 - Sandbox / Impact Analysis

- estimates impact for risky actions
- supports approval/rejection flows for pending sandboxed actions

### Layer 6 - Policy Engine

- checks profiles, workspaces, tool rules, protocols, and destinations
- supports formal verification of workspace policies

### Layer 7 - Injection Firewall

- uses staged rule-based prompt inspection
- tracks runtime stats in memory today
- no ML classifier in community `0.3.0`

### Layer 8 - Telemetry

- emits spans and metrics
- supports SSE and webhook fan-out
- logs request-level correlation via `x-request-id`
- returns pipeline-level `traceId` in governance responses

## Storage

### Backends

- default: SQLite
- optional: PostgreSQL via `--features postgres`

The runtime selects the backend from `DATABASE_URL`:

- `sqlite:...` -> SQLite
- `postgres://...` or `postgresql://...` -> PostgreSQL

### Migrations

Schema migrations are versioned under:

- `community/migrations/sqlite/`
- `community/migrations/postgres/`

The runtime runs them through `sqlx::migrate!()`.

There is also a small compatibility layer that backfills columns needed by older community databases.

## Runtime Surface

```text
community/src/
|- main.rs
|- core/
|- auth/
|- config/
|- dashboard/
|- events/
|- modules/
|- mcp_proxy/
|- pipeline/
|- server/
`- storage/
   |- traits.rs
   |- migrations.rs
   |- sqlite.rs
   `- postgres.rs
```

## Transport And API

- HTTP server: Axum
- auth: Bearer token with Argon2-hashed API keys
- public routes: `/`, `/health`
- protected routes: `/v1/*`
- real-time transport: SSE and webhooks
- MCP support today: proxy/interceptor mode and MCP server mode over stdio

## Logging And Correlation

`v0.3.0` adds:

- `AGENT_ARMOR_LOG_FORMAT=pretty|compact|json`
- `AGENT_ARMOR_LOG_LEVEL`
- `RUST_LOG` fallback
- `x-request-id` on HTTP responses
- `traceId` on governance results

This makes server logs, API responses, and audit/review flows easier to correlate.

## Verification Strategy

The community runtime is verified with:

- unit tests
- property tests
- direct integration tests
- live HTTP E2E tests that start the server and issue real requests

## Known Architectural Gaps

These are the main remaining community architecture gaps:

- framework adapters
- moving remaining in-memory runtime stores behind storage traits

## Dashboard

The dashboard is now a live operator console served from the Rust runtime.

Current connected surfaces include:

- live overview metrics
- audit exploration
- review queue actions
- selected-agent analytics and fingerprint drill-down
- runtime posture cards for firewall, threat intel, telemetry, rate limiting, sessions, and policy verification
