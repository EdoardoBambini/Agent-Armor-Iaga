# Changelog

All notable changes to Agent Armor are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

For path renames and migration steps from 0.4.0, see [MIGRATION.md](MIGRATION.md).
For architectural rationale, see the ADRs under [docs/adr/](docs/adr/).

This changelog tracks the **open-source build** of Agent Armor,
licensed under BUSL-1.1 with Change License: Apache-2.0 baked in.
Agent Armor Enterprise is a separate commercial product built on the
same governance kernel; see [`ENTERPRISE.md`](ENTERPRISE.md) for the
Enterprise pitch and the EU AI Act + GDPR compliance pack mapping.

---

## [1.0.0] — Unreleased ("Fortezza")

Architectural leap from 0.4.0. The 0.4.0 sidecar HTTP gate becomes a
distributed, attested, replayable, probabilistically aware kernel for
autonomous AI agents. Every governance decision is now signed,
chained, and verifiable offline. Policy moves from YAML templates to
a typed deterministic DSL. ML is opt-in and produces evidence the
deterministic policy decides on.

### Fixed (GA pre-flight, after E2E smoke)

- **Dockerfile** rewritten for the workspace layout. Previous version
  pointed at the pre-M1 `community/` paths and shipped a stub binary
  that exited immediately. New Dockerfile builds the real binary
  single-shot and `docker compose up` is healthy on first attempt.
- CLI banner: "8 Layers ARMED" → "12 Layers ARMED" (consistent with
  the 1.0 marketing surface; M3.5 + M4 add 4 layers on top of the
  original 8).
- `armor-core` crate description: "(Community Edition)" →
  "(open-source edition)" for consistency with the new
  Community vs Enterprise docs.

### Added

- **Workspace split** into 5 crates under `crates/`: `armor-core`,
  `armor-receipts`, `armor-apl`, `armor-reasoning`, `armor-kernel`.
  Single workspace `Cargo.toml` at the root.
- **M2 — Signed Action Receipts.** Ed25519-signed records of every
  governance verdict, hash-chained per `run_id` (Merkle append-log).
  SQLite and Postgres backends. New CLI: `armor replay --list`,
  `armor replay <run_id>`, `armor replay <run_id> --verify-only`.
  Signer key auto-generated at `~/.armor/keys/receipt_signer.ed25519`
  on first run, override via `ARMOR_SIGNER_KEY_PATH`.
- **M3 — Armor Policy Language (APL).** Typed DSL with deterministic
  tree-walk evaluator, instruction budget, short-circuit boolean
  evaluation, hash-linked replay safety. New crate `armor-apl`. CLI:
  `armor policy test <file.apl>` and `armor policy lint <file.apl>`.
  WASM codegen for APL is tracked for 1.0.3.
- **M3.5 — Probabilistic Reasoning Plane.** New crate `armor-reasoning`
  with always-available `NoopEngine` plus `TractEngine` (pure-Rust
  ONNX via `tract-onnx`) behind opt-in `ml` feature. Model SHA-256
  digests embedded in every receipt. CLI: `armor reasoning info`.
  Pre-trained models ship in 1.0.2.
- **M4 — Enforcement Kernel scaffold.** New crate `armor-kernel` with
  cross-platform `UserspaceKernel` (soft enforcement, every OS) and
  Linux `BpfKernel` scaffold under `linux-bpf` feature. New CLI:
  `armor run [--agent-id ...] [--cwd ...] -- <cmd>` and
  `armor kernel status`. The real eBPF/LSM loader lands in 1.0.1.
- **M5 — `armor run` traverses the full governance pipeline.** Every
  governed launch produces a signed receipt. Postgres receipt backend
  is wired automatically based on the `DATABASE_URL` scheme.
  Cargo feature composition: `armor-core/sqlite|postgres` transitively
  enables the matching `armor-receipts` feature.
- **M6 — APL as live policy engine.** `armor serve --policy <file.apl>`
  loads an overlay merged stricter-wins with the YAML profile system.
  Receipts embed the SHA-256 of the active APL bundle in
  `policy_hash`. New CLI `armor policy lint`.
- **UI embedded** in the binary via `rust-embed` behind `ui-embed`
  feature.
- **8 ADRs** documenting every architectural decision (`docs/adr/0001`
  through `0008`).
- **`armor` short alias binary** alongside `agent-armor`. Same entry
  point.

### Changed

- **Crate renamed**: package `agent-armor` → `agent-armor-core`. Binary
  name `agent-armor` preserved for backward compatibility.
- **License**: stays on BUSL-1.1 with **Change License: Apache-2.0**
  baked into the licence. Each release converts automatically and
  irrevocably to Apache-2.0 four years after publication. See
  [ADR 0002](docs/adr/0002-open-source-license-and-scope.md) for the
  rationale and [`LICENSE`](LICENSE) for the legal text.
- **Defense-in-depth model**: 8 layers → 12 layers. The original 8 are
  hardened in M2–M5; M3.5 + M4 add supply chain attestation /
  blast radius enforcement / behavioral baseline / counterparty trust
  scaffolding.
- **All paths** `community/` → `crates/armor-core/`. Detailed renames
  in [MIGRATION.md](MIGRATION.md).
- **Cargo `default` features** for `armor-core`:
  `["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]`.

### Deferred to 1.0.x patch releases

- **1.0.1**: real eBPF/LSM loader via `aya-rs` + LLVM 18. LSM hooks on
  `execve`, `openat`, `connect`, `sendto`. Landlock fallback. Cgroup
  jailing. Long-lived detached child handle ownership. After 1.0.1,
  `BpfKernel.is_authoritative()` flips to `true`.
- **1.0.2**: pre-trained ONNX models for intent-drift /
  prompt-injection / anomaly-seq, plus pluggable tokenizers shipped
  alongside model files.
- **1.0.3**: WASM codegen for APL via `wasm-encoder`; full
  Hindley–Milner type checker.

### Deferred to 1.1

- Governance mesh (gRPC gossip, federated rate budgets, CRDT on
  receipt log) — OSS, not Enterprise-gated.
- macOS Endpoint Security + Windows ETW kernel backends.
- KMS / HSM signer backends for receipts (BYOK pattern in OSS,
  managed key + eIDAS qualified signatures in Enterprise).
- GPU acceleration ML + native ONNX Runtime backend (`ort`).
- Drift replay with full pipeline re-execution against historical
  receipts (requires receipt schema change).
- Stateful cross-run anomaly detection.
- HuggingFace tokenizers in `armor-reasoning`.
- `armor policy migrate` (YAML → APL converter).

---

## [0.4.0] — 2026-XX-XX ("Azzurra")

The community runtime that proved the thesis. 8-layer defense in depth
behind a single `/v1/inspect` HTTP gate. Policy as YAML + templates.
SDKs in Python and TypeScript. SQLite + Postgres durable state.

See git history for the full 0.4.0 changelog.
