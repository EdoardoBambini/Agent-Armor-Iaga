<h1 align="center">Agent Armor 1.0</h1>

<p align="center">
  <strong>Zero-trust governance kernel for autonomous AI agents.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="version" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license" />
  <img src="https://img.shields.io/badge/12%20layers-defense%20in%20depth-green" alt="12 layers" />
  <img src="https://img.shields.io/badge/Rust-stable-orange" alt="Rust" />
</p>

<p align="center">
  <a href="#what-1-0-is">What 1.0 is</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#status">Status</a>
</p>

<p align="center">
  <img src="media/hero.gif" alt="Agent Armor 1.0 — kernel-enforced governance for autonomous agents" width="720" />
</p>

---

## What 1.0 is

Three things in one binary, glued by a typed deterministic policy language:

1. **A kernel.** Armor sits below the agent SDK. Process launches go
   through `armor run`, which consults the governance pipeline before
   spawning. The 0.4.0 HTTP sidecar still works for SDK-aware agents;
   the kernel is the chokepoint for everything else.
2. **A signed log.** Every governance verdict produces an Ed25519-signed
   receipt linked to the previous one in a Merkle append-log per run.
   Replay verifies the chain bit-exact and detects policy drift.
3. **A reasoning brain.** Optional ML models (ONNX, opt-in) emit
   evidence — never verdicts. The deterministic policy decides; ML
   produces scores the policy can read. Receipts embed the SHA-256 of
   every model that touched the decision.

All driven by APL: a typed DSL with deterministic tree-walk evaluation,
loadable as a `--policy` overlay on top of the YAML profile system.

---

## Quickstart

### Install + start

```bash
cargo install --path crates/armor-core

# Default sqlite, demo data seeded on first boot
armor serve
```

### CLI flow (no auth)

```bash
# Path to a JSON file (camelCase keys, see note below)
armor inspect ./payload.json

# Launch a child process under the governance pipeline
armor run --agent-id openclaw-builder-01 -- python my_agent.py

# Replay the signed receipt chain
armor replay --list
armor replay <run_id>

# Test an APL policy file
armor policy lint crates/armor-apl/examples/no_pii_egress.apl
armor policy test crates/armor-apl/examples/no_pii_egress.apl \
    --context crates/armor-apl/examples/sample_context.json

# Inspect kernel + reasoning posture
armor kernel status
armor reasoning info

# Load an APL bundle as a live overlay on top of YAML
armor serve --policy crates/armor-core/examples/policies/strict.apl
```

### HTTP API flow

```bash
# Generate an API key once
armor gen-key --label my-app
# → Key: aa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Inspect via HTTP. Auth header is `Authorization: Bearer <key>`.
# Payload uses camelCase: agentId, toolName, actionType.
curl -X POST http://localhost:7777/v1/inspect \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer aa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' \
  -d '{
    "agentId":  "openclaw-builder-01",
    "framework":"langchain",
    "action": {
      "type":     "shell",
      "toolName": "bash",
      "payload":  {"cmd": "ls"}
    }
  }'
```

### Docker

```bash
docker compose up -d
curl http://localhost:4010/health     # → 200
docker compose down
```

The container persists its DB and signer key in a named volume
(`agent-armor-data`). Receipts signed inside the container can only be
verified by the same container; to share a signer key across deployments
mount your own key file or set `ARMOR_SIGNER_KEY_PATH`.

### Postgres

```bash
DATABASE_URL=postgres://user:pwd@host/agent_armor \
  cargo install --path crates/armor-core --features postgres

armor serve   # receipts now go to Postgres automatically
```

---

## Features

Cargo features on `armor-core`:

| Feature      | Default | Adds                                                                  |
|--------------|---------|------------------------------------------------------------------------|
| `sqlite`     | ✅      | SQLite backend for audit + receipts.                                   |
| `postgres`   | ❌      | Postgres backend.                                                      |
| `receipts`   | ✅      | Ed25519-signed Merkle-chained receipts (M2).                           |
| `apl`        | ✅      | Armor Policy Language parser + evaluator + `armor policy ...` (M3).    |
| `reasoning`  | ✅      | Reasoning plane scaffold + `armor reasoning info` (M3.5).              |
| `ml`         | ❌      | `tract-onnx` ML backend; opt-in, +~5 MB binary, +~2 min cold compile.  |
| `kernel`     | ✅      | Enforcement kernel + `armor run` + `armor kernel status` (M4).         |
| `linux-bpf`  | ❌      | Linux eBPF/LSM scaffold. Real loader ships in 1.0.1.                   |
| `ui-embed`   | ❌      | Embeds `ui/dist/` into the binary via `rust-embed`.                    |

`default = ["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]`.

---

## Architecture

12 layers of defense in depth, organized into 7 architectural pillars
described in [`AGENT_ARMOR_1.0.md`](AGENT_ARMOR_1.0.md):

1. **Enforcement Kernel** — `crates/armor-kernel/` (M4 scaffold + 1.0.1 loader).
2. **Signed Receipts** — `crates/armor-receipts/` (M2).
3. **Armor Policy Language** — `crates/armor-apl/` (M3 + M6 live overlay).
4. **Attested Plugins** — supply-chain integrity (1.1).
5. **Governance Mesh** — federated rate budgets (1.1).
6. **Visual Plane** — `ui/` embedded via `ui-embed` feature.
7. **Probabilistic Reasoning** — `crates/armor-reasoning/` (M3.5).

Workspace layout:

```
agent-armor/
├── crates/
│   ├── armor-core/          # pipeline, server, CLI, AppState
│   ├── armor-receipts/      # Ed25519 + Merkle log + replay
│   ├── armor-apl/           # APL parser + evaluator
│   ├── armor-reasoning/     # ML evidence (tract-onnx behind `ml`)
│   └── armor-kernel/        # cross-platform launcher + eBPF scaffold
├── docs/adr/                # 8 ADRs (0001–0008)
├── ui/                      # frontend (embedded via ui-embed feature)
├── media/                   # hero assets
├── AGENT_ARMOR_1.0.md       # design document
├── MIGRATION.md             # 0.4.0 → 1.0 + per-milestone notes
└── CHANGELOG.md             # release notes
```

---

## Documentation

- **Design**: [`AGENT_ARMOR_1.0.md`](AGENT_ARMOR_1.0.md)
- **Migration from 0.4.0**: [`MIGRATION.md`](MIGRATION.md)
- **Release notes**: [`CHANGELOG.md`](CHANGELOG.md)
- **Architectural decisions**:
  - [ADR 0001 — Workspace split](docs/adr/0001-workspace-split.md)
  - [ADR 0002 — Open-source license + scope decisions](docs/adr/0002-open-source-license-and-scope.md)
  - [ADR 0003 — Signed receipts design](docs/adr/0003-signed-receipts-design.md)
  - [ADR 0004 — APL MVP](docs/adr/0004-apl-mvp.md)
  - [ADR 0005 — Reasoning plane MVP](docs/adr/0005-reasoning-plane-mvp.md)
  - [ADR 0006 — Kernel MVP](docs/adr/0006-kernel-mvp.md)
  - [ADR 0007 — M5 hardening + RC posture](docs/adr/0007-m5-hardening-rc.md)
  - [ADR 0008 — APL as live policy engine](docs/adr/0008-apl-as-live-policy-engine.md)
- **Contributing**: [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## Status

**1.0 GA candidate.** All six 1.0 milestones complete, 234/234 default
tests passing, clippy `--all-targets -D warnings` clean.

What's intentionally honest about the posture:

- `armor kernel status` reports `authoritative: no (soft enforcement)`
  until **1.0.1** ships the real eBPF/LSM loader. We don't market
  enforcement we don't yet provide.
- `armor reasoning info` reports `engine: noop` unless models are
  configured; pre-trained models for intent-drift / prompt-injection /
  anomaly-seq ship in **1.0.2**.
- WASM codegen for APL is **1.0.3**. Today the evaluator is
  tree-walking, fully deterministic, and replay-safe — the WASM swap
  is purely a performance / sandbox-isolation upgrade.
- macOS Endpoint Security and Windows ETW kernel backends, governance
  mesh, KMS/HSM signers, GPU ML — all **1.1**.

The 1.0 surface is locked. Patch releases are additive; 1.1 is the
next major.

---

---

## Community vs Enterprise

> **Agent Armor Enterprise: from governance kernel to audit dossier in 14 days.**

The governance kernel is the same in both editions. Enterprise adds
modules that live in a separate commercial repository. The table below
lists only what is **verifiable today** — what you can clone, build,
inspect, or call against a running instance. Roadmap items (eBPF
loader, mesh, WASM codegen, curated ML models) are tracked in
[`CHANGELOG.md`](CHANGELOG.md) under the version where they ship.

### What ships in OSS today (Apache-2.0, this repository)

Verifiable by `git clone && cargo test --workspace && docker compose up -d`:

- **12-layer governance pipeline** — single binary, single endpoint
  (`POST /v1/inspect`), 234/234 tests passing.
- **Signed action receipts** — Ed25519 + Merkle append-log per run,
  verifiable offline with `armor replay <run_id> --verify-only`.
- **Armor Policy Language (APL)** — typed DSL with deterministic
  tree-walk evaluator, instruction budget, short-circuit evaluation.
  Try with `armor policy lint <file.apl>`.
- **APL live overlay** — load a bundle as `armor serve --policy
  <file.apl>`. Stricter-wins merge with the YAML profile system.
- **Reasoning plane scaffold** — `armor reasoning info`. Bring your
  own ONNX models via `--features ml` (`tract` backend, no native
  deps).
- **Cross-platform UserspaceKernel** — `armor run -- <cmd>` spawns
  governed child processes on Linux, macOS, Windows.
- **HTTP API with Bearer auth** — `armor gen-key` then call
  `POST /v1/inspect` with `Authorization: Bearer <key>`.
- **SQLite and Postgres backends** — switch by setting
  `DATABASE_URL=postgres://...` and building with `--features
  postgres`. Receipts go to the matching backend automatically.
- **BYOK-ready signer** — `ARMOR_SIGNER_KEY_PATH` lets you point at
  any 32-byte Ed25519 key file, including one served by your KMS
  (AWS KMS, Azure Key Vault, HashiCorp Vault, on-prem HSM via the
  filesystem-mount pattern).
- **Docker deployment** — `docker compose up -d`, `/health` returns
  200 within ~10 seconds on the first attempt.
- **WASM plugin loading** — `armor plugins list` and `armor plugins
  validate <file.wasm>`.

Run the smoke yourself, every claim above is reproducible from a
clean checkout.

### What Agent Armor Enterprise adds (separate commercial repository)

Verifiable on request with a sandbox instance — these are concrete
modules, not promises. Each lives in a separate commercial repo and
is not feasible to reimplement quickly from the OSS surface alone:

- **EU AI Act + GDPR + DORA compliance evidence engine.** Generates
  Annex IV dossiers, RoPA, DPIA, post-market monitoring reports,
  EU AI Office incident notifications. PDF + JSON-LD output, signed
  with qualified e-signatures (eIDAS). Tied to the OSS receipt
  schema so dossiers cite the chain that produced them.
- **DPO Dashboard.** Web app for human-in-the-loop review queues,
  escalation, SLA timers, audit-trailed approvals signed Ed25519 for
  non-repudiation.
- **Multi-tenant isolation paths.** Schema-per-tenant DB layer,
  per-tenant resource quotas, cross-tenant audit isolation,
  tenant lifecycle management.
- **Enterprise SSO.** SAML 2.0 + OIDC + SCIM provisioning,
  fine-grained RBAC with role inheritance, MFA enforcement,
  IP allowlist per tenant.
- **eIDAS qualified signature pipeline.** ETSI EN 319 132
  (XAdES / PAdES / CAdES), Long-Term Validation profile, connectors
  to specific EU Trust Service Providers. Receipts gain legal
  weight in EU jurisdictions.
- **Native SIEM connectors.** Splunk, Datadog, Elastic, Sentinel,
  Chronicle. Field mappings done; not "send us a webhook".
- **Air-gapped distribution.** Offline update channel with signed
  bundle delivery, custom installer, air-gap registry, bundle
  verification chain.
- **Founder-led support.** SLA 99.95%, 24/7 oncall handled by the
  same team that wrote the kernel. No tier-1 ticket triage.
- **Iaga Cloud managed deployment** — when you do not want to run
  the box yourself.

The compliance pieces require a compliance officer + EU regulatory
lawyer kept current as the regulator publishes new guidelines. That
work is what you are paying for, on top of the code itself.

### Open-core promise

The governance kernel — receipt schema, replay algorithm, APL
evaluator, reasoning framework, BYOK signer support, the eBPF loader
when it ships in 1.0.1, the single-cluster mesh when it ships in 1.1
— stays **Apache-2.0 forever**. Enterprise never gates the security
fundamentals. The promise is documented in
[`AGENT_ARMOR_1.0.md`](AGENT_ARMOR_1.0.md) §9 so future founders cannot
walk it back.

### Why Enterprise exists

For teams in regulated environments (banks, insurers, healthcare,
public sector, critical infrastructure), the question is not *"can
we be compliant"* — OSS answers that. The question is *"can we
**prove** it to the auditor / notified body / DPO / regulator
within two weeks instead of six months"*. Enterprise turns the OSS
mechanisms into the dossiers, dashboards, and signed evidence packs
that the EU AI Act, GDPR, and DORA ask for in their acceptance
language, and gives you a phone number to the people who wrote the
governance kernel when something goes wrong.

See [`ENTERPRISE.md`](ENTERPRISE.md) for the full Enterprise pitch
and the EU AI Act / GDPR / DORA article-by-article mapping. Contact:
`enterprise@iaga.start@gmail.com`.

---

## License

The OSS edition (Agent Armor) is licensed under [Apache-2.0](LICENSE).
See also [`NOTICE`](NOTICE).

Agent Armor Enterprise is sold under a separate commercial license.
The two share the same source tree where they share code; Enterprise
adds modules that live in a separate repository and are not covered
by Apache-2.0.

Repository: <https://github.com/EdoardoBambini/Agent-Armor-Iaga>
Contact: `iaga.start@gmail.com`
