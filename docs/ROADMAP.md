# Roadmap

## Phase 1 — Core Pipeline (Done)

- [x] MCP protocol parser and schema validation
- [x] Policy evaluation engine
- [x] Deterministic risk scoring
- [x] Secret reference resolution
- [x] Human review queue
- [x] Audit trail
- [x] NHI registry with crypto identity

## Phase 2 — 8-Layer Security Stack (Done)

- [x] Protocol Deep Packet Inspection
- [x] Taint tracking engine
- [x] Adaptive 5-weight risk scoring
- [x] Sandbox execution with impact capture
- [x] Policy formal verification
- [x] 3-stage injection firewall
- [x] OpenTelemetry observability
- [x] Cyberpunk dashboard with live API

## Phase 2.5 — Tier 2 Advanced Features (Done)

- [x] Response scanning — detect PII, credentials, and secrets in agent output
- [x] Rate limiting — per-agent sliding window throttling with configurable quotas
- [x] Agent fingerprinting — behavioral profiling and anomaly detection
- [x] Threat intelligence — IOC feed with indicator management and real-time checking

## Phase 3 — Production Hardening

- [ ] ACP protocol support
- [ ] Persistent storage migration tooling
- [x] Rate limiting and throttling
- [ ] Structured logging with log levels
- [ ] Graceful shutdown and health probes
- [x] Docker image and Helm chart
- [x] CI/CD pipeline (GitHub Actions)

## Phase 4 — Enterprise

- [ ] Multi-tenant workspace isolation
- [ ] SSO/SAML authentication
- [ ] SIEM integration (Splunk, Sentinel, Datadog)
- [ ] ML-powered injection firewall (enterprise tier)
- [ ] Webhook delivery guarantees (retry, dead letter)
- [ ] Terraform provider for policy-as-code
- [ ] Admin dashboard with RBAC

## Phase 5 — Ecosystem

- [x] Python SDK — pip installable client
- [x] TypeScript SDK — npm installable client
- [ ] Framework adapters (LangChain, CrewAI, AutoGen)
- [ ] MCP server mode (act as MCP proxy)
- [ ] Community policy marketplace
- [ ] Grafana dashboard templates
