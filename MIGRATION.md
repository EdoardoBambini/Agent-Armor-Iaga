# Migration Guide

This document tracks breaking changes and path renames across Agent Armor
releases. The high-level 1.0 design lives in [`AGENT_ARMOR_1.0.md`](AGENT_ARMOR_1.0.md);
this file tracks the **concrete moves** you need to make when bumping versions.

---

## 0.4.0 → 1.0.0-alpha.1 (M1: "Fortezza Foundation")

**Scope:** repository layout only. No runtime API change. No policy format
change. All 0.4.0 behavior is preserved; tests pass unchanged.

### What moved

| Before (0.4.0) | After (1.0.0-alpha.1) | Notes |
|---|---|---|
| `community/` | `crates/armor-core/` | Cargo crate, now a workspace member |
| `community/Cargo.toml` package name `agent-armor` | `agent-armor-core` | the **crate** renamed; the **binary** is still `agent-armor` |
| `visual/` | `ui/` | official frontend, will be embedded via `ui-embed` feature |
| `assets/hero.gif` | `media/hero.gif` | media consolidated under one folder |
| `assets/hero.mp4` | `media/hero.mp4` | still gitignored (large) |
| `assets/brain.gif` | `media/brain.gif` | |
| `community/target/` | `target/` (repo root) | workspace-level target |
| `community/Cargo.lock` | `Cargo.lock` (repo root) | workspace-level lock |

### What stayed

- Binary name `agent-armor` unchanged (backward compat).
- Library name `agent_armor` (so `use agent_armor::*` keeps working in tests and SDK consumers).
- Policy YAML format unchanged (APL migration comes in M3).
- SDK layout in `sdks/python` and `sdks/typescript` unchanged.
- `docs/`, `charts/`, `skills-lock.json`, `agent-armor.config.json` unchanged.
- `agent-armor-video/` Remotion project unchanged, still standalone.

### What's new

- `armor` is now an official alias binary (same entry point as `agent-armor`).
  Both are built from `crates/armor-core` and can be invoked
  interchangeably.
- `ui-embed` Cargo feature on `agent-armor-core`. When enabled, embeds
  `ui/dist/` into the binary via `rust-embed`. Requires a prior
  `cd ui && npm run build`. Route wiring (`/ui`) lands in a later milestone.
- Workspace-level `Cargo.toml` at the repo root with shared dependency
  versions — future crates (`armor-receipts`, `armor-apl`,
  `armor-reasoning`, `armor-kernel`, `armor-mesh`) will land here without
  further repo reshuffles.

### Breaking commands

If your scripts used any of these, update accordingly:

```diff
- cd community && cargo build
+ cargo build --workspace
+ # or scoped:
+ cargo build -p agent-armor-core

- cd community && cargo test --all-features
+ cargo test --workspace --all-features

- community/target/release/agent-armor
+ target/release/agent-armor

- cd visual && npm install
+ cd ui && npm install
```

### CI

The workflow at `.github/workflows/ci.yml` was rewritten to run from the
workspace root. Branch trigger `feat/1.0-**` was added so M1+ branches
get CI without a PR.

### Why

See [`docs/adr/0001-workspace-split.md`](docs/adr/0001-workspace-split.md).
Short version: we need a multi-crate workspace so that `armor-receipts`
(M2), `armor-apl` (M3), `armor-reasoning` (M3.5), `armor-kernel` (M4),
and `armor-mesh` (M5) can grow as separate, feature-gated crates without
touching `armor-core`. The M1 split is deliberately conservative: we
create the workspace and move the single crate in, but **do not** slice
`armor-core` itself. That comes later, milestone by milestone.

---

## 1.0.0-alpha.1 M2 — "Signed Action Receipts" (staged, not committed)

**Scope:** additive. No runtime API change for 0.4.0 consumers. No policy
format change. `audit_events` is untouched; a new `receipts` table is
written *in addition* whenever the `receipts` cargo feature is active
(default on). All 0.4.0 behavior preserved; 166/166 pre-existing tests
still pass.

### What's new

- New crate `crates/armor-receipts/` providing:
  - `Receipt` / `ReceiptBody` — canonical, Ed25519-signed record of a
    governance verdict.
  - `ReceiptStore` trait with SQLite and Postgres backends.
  - `ReceiptSigner` — single-key Ed25519 signer loaded from
    `<HOME>/.armor/keys/receipt_signer.ed25519` (generated on first run,
    `chmod 0600` on Unix). Override path via env `ARMOR_SIGNER_KEY_PATH`.
  - Hash-linked append-only chain (one chain per `run_id`) with
    end-to-end `verify_chain` that rejects any tampering.
  - `replay(store, run_id, evaluator)` — drift-detection primitive; the
    full "re-run pipeline in sandbox" replay lands in M5.

- New optional field on `AppState`:
  `pub receipts: Option<Arc<dyn ReceiptLogger>>`. `None` when the
  `receipts` feature is disabled or the host hasn't wired a logger.

- New `armor-core` cargo feature `receipts` (default **on**):
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts"]
  receipts = ["dep:armor-receipts"]
  ```

- New CLI subcommand (feature-gated):
  ```
  armor replay --list
  armor replay <run_id>
  armor replay <run_id> --verify-only
  ```

- `execute_pipeline` now performs a best-effort dual-write: after each
  successful `audit_store.append`, if `state.receipts` is `Some`, a
  signed receipt is appended to the corresponding Merkle chain. Errors
  on the receipt path are logged at `warn!` and never propagate.

### Environment / ops notes

- **Signer key path**: `$HOME/.armor/keys/receipt_signer.ed25519`. Back
  this up — losing the private key means new runs start a new chain and
  old chains can still be *verified* (public key derived from
  `signer_key_id`) but not *extended* with matching signatures.
- **DB backend**: the automatic wiring currently enables receipts only
  on `sqlite:` URLs. Postgres support in `armor-receipts` is compiled
  and tested; the `armor-core` helper that auto-enables it on Postgres
  DSNs is a follow-up (tracked for M5).
- **Disabling receipts**: build with `--no-default-features --features
  "demo,sqlite"` (omitting `receipts`). The binary will run exactly as
  0.4.0 with no signing overhead.

### What stayed

- `audit_events` table and all its APIs unchanged.
- `agent-armor` and `armor` binary names unchanged.
- Policy format unchanged.
- Trait `AuditStore` unchanged.
- SDK surface unchanged.

---

## 1.0.0-alpha.1 M3 — "Armor Policy Language" (staged, not committed)

**Scope:** additive. No change to 0.4.0 YAML policy pipeline. New crate
`armor-apl` provides an independent parser + deterministic evaluator for
`.apl` source files. Integration with the live policy store is deferred
to M5; M3 ships the language, the types and a dry-run CLI.

### What's new

- New crate `crates/armor-apl/` providing:
  - `logos`-based lexer (keywords, operators, string escapes, `//` comments),
  - recursive-descent parser producing a `Program` AST,
  - structural validator (unique policy names, builtin arity, non-empty paths),
  - tree-walk evaluator with instruction budget (`EvalBudget`, default 10_000 steps),
  - public `compile(src)` and `evaluate_program(program, ctx, budget)` entry points.

- Supported APL surface (MVP — see [`docs/adr/0004-apl-mvp.md`](docs/adr/0004-apl-mvp.md)):
  ```apl
  policy "name" {
    when <expr>
    then allow|review|block [, reason="..."] [, evidence=<expr>]
  }
  ```
  Expressions support literals (string/int/bool), dotted path access
  (`action.url.host`), comparisons (`== != < <= > >=`), boolean
  logic with short-circuit (`and or not`), membership (`in`, `not in`)
  and builtin calls (`contains starts_with ends_with len lower upper
  secret_ref`).

- New `armor-core` cargo feature `apl` (default **on**):
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts", "apl"]
  apl = ["dep:armor-apl"]
  ```

- New CLI subcommand (feature-gated):
  ```
  armor policy test <file.apl>
  armor policy test <file.apl> --context ctx.json
  ```
  Without `--context` only parse + validate. With a JSON context, the
  evaluator runs and prints `FIRE policy=... verdict=...` for the
  first policy that triggers.

- Example policy + sample context shipped at
  `crates/armor-apl/examples/no_pii_egress.apl` (+ `sample_context.json`).

### Contracts

- **Execution order**: policies run in declaration order; the first
  truthy `when` produces the verdict. Authors order by severity.
- **Missing paths** evaluate to `null` and are falsy. Policies must
  not assume the presence of optional fields.
- **Determinism**: no I/O, no wall-clock, no RNG. Same AST + same
  context ⇒ same result, forever. This is what makes APL compatible
  with the receipt-replay model from M2.
- **Budget**: every AST-node visit decrements a counter; exhaustion
  produces `AplError::BudgetExhausted`, never a silent pass.

### What's *not* in M3 (intentionally)

- WASM codegen (→ M3.1). The tree-walk evaluator is already deterministic.
- Full Hindley–Milner type checker (→ M3.1). The M3 validator is structural.
- APL policies wired into `execute_pipeline` as the live policy engine
  (→ M5). For now the YAML loader remains the authoritative policy
  source; APL runs via the CLI dry-run only.
- Loops, closures, let-bindings, user-defined functions, file imports,
  LSP/IDE integration. Added as the language stabilizes.

### What stayed

- YAML policy loader unchanged. No `armor policy migrate` yet — it lands
  in M5 when the live swap happens.
- `audit_events`, `receipts`, `AuditStore`, `ReceiptStore` unchanged.
- SDK surface unchanged.

---

## 1.0.0-alpha.1 M3.5 — "Probabilistic Reasoning Plane" (staged, not committed)

**Scope:** additive. Pipeline behavior unchanged when no reasoning
engine is wired or the `ml` feature is off. New crate `armor-reasoning`
provides the ML evidence surface; `armor-core` wires it through to
`SignedReceiptLogger` so receipts now carry `model_digests` + `ml_scores`
**when and only when** an engine is active and produces evidence.

### What's new

- New crate `crates/armor-reasoning/` providing:
  - `ReasoningEngine` trait with two impls: `NoopEngine` (always
    present) and `TractEngine` (feature `ml`, pure-Rust ONNX via
    `tract-onnx`).
  - `EvalInput` / `MlEvidence` / `ModelDigest` types — matched in
    shape to `armor_receipts::{ModelDigest, MlScoreBundle}` so the
    glue layer is a one-liner.
  - SHA-256 digest computation for every loaded model file.
  - MVP hash-bag-of-byte-ngrams tokenizer (`[1, 64]` float32) — see
    [ADR 0005](docs/adr/0005-reasoning-plane-mvp.md) for the
    deliberate scope decision.
  - Env-driven model spec: `ARMOR_REASONING_MODELS=name1:path1,name2:path2`.

- New `armor-core` features:
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts", "apl", "reasoning"]
  reasoning = ["dep:armor-reasoning"]
  ml = ["reasoning", "armor-reasoning/ml"]
  ```
  - `reasoning` is **default on** but only enables the `NoopEngine`.
    No native deps, no binary bloat, no behavior change at runtime.
  - `ml` is **default off**. Adds `tract-onnx` to the build (~5 MB
    binary growth, ~2 min cold compile) and activates the
    `TractEngine` so `ARMOR_REASONING_MODELS` actually loads.

- New optional field on `AppState`:
  `pub reasoning: Option<Arc<dyn ReasoningHandle>>` — same
  feature-agnostic pattern as `receipts`.

- New CLI subcommand (feature-gated on `reasoning`, not `ml`):
  ```
  armor reasoning info
  ```
  Prints engine name, loaded model count, and per-model SHA-256
  digest. Suggests next step (`--features ml` rebuild or
  `ARMOR_REASONING_MODELS` setting) when no models are loaded.

- `execute_pipeline` now invokes `reasoning.evaluate_json(...)` once
  before the risk score. Output is passed to `SignedReceiptLogger.record`
  as `Option<&ReasoningOutcome>`. Errors are logged at `warn!` and
  swallowed: a broken ML engine never fails the governance decision.

### Receipt schema impact

The `Receipt` JSON shape is **unchanged**. The fields `model_digests`
and `ml_scores` already existed in M2; they were always serialized
empty/None. Now they get populated when reasoning is active and an
engine produces evidence.

For runs where reasoning is off or produces no evidence, receipts are
**bit-identical** to M2. Replay of legacy chains is unaffected.

### Trait change (internal, not public API)

`pipeline::receipts::ReceiptLogger::record` signature changed:

```diff
-async fn record(&self, event: &StoredAuditEvent);
+async fn record(&self, event: &StoredAuditEvent, evidence: Option<&ReasoningOutcome>);
```

This is internal to `armor-core` (`pipeline::receipts` is `pub` for the
binary's own use, not part of a stable public surface). The two call
sites in `execute_pipeline.rs` were updated; the fast-path block sends
`None`, the main verdict path sends the eval outcome.

### Environment / ops notes

- **Default behavior unchanged**: without `--features ml` and without
  setting `ARMOR_REASONING_MODELS`, the engine is `NoopEngine` and
  receipts look exactly like M2.
- **Disabling reasoning entirely**: `--no-default-features --features
  "demo,sqlite,receipts,apl"`. `AppState.reasoning` will be `None`
  and the pipeline skips the eval call.
- **Real ONNX models**: build with `--features ml`, set
  `ARMOR_REASONING_MODELS=name:/abs/path/model.onnx,...`. The model
  must accept `[1, 64]` float32 input. M3.5.1 will lift the latter
  constraint with pluggable tokenizers.

### What stayed

- `audit_events` / `receipts` schemas unchanged.
- `AuditStore` / `ReceiptStore` traits unchanged.
- APL surface unchanged (M5 will add `ml.*` paths to the eval context).
- SDK API unchanged.
- 166/166 pre-existing core tests still pass.

---

## 1.0.0-alpha.1 M4 — "Enforcement Kernel" (staged, not committed)

**Scope:** additive. New crate `armor-kernel` provides a cross-platform
`EnforcementKernel` trait, a working `UserspaceKernel` for every OS,
and a `BpfKernel` scaffold (Linux, feature `linux-bpf`). Pipeline
behavior is unchanged; the kernel is reachable today only through the
new `armor run` subcommand.

The actual eBPF/LSM loader (the part that makes enforcement
authoritative) is tracked for M4.1. M4 ships the trait shape so M4.1
is purely additive.

### What's new

- New crate `crates/armor-kernel/` providing:
  - `EnforcementKernel` trait — `launch(spec) -> LaunchOutcome`,
    `backend_name()`, `is_authoritative()`.
  - `UserspaceKernel` — cross-platform launcher with policy pre-check,
    scoped environment (allowlist of inherited vars + explicit
    overrides), optional cwd, sync wait + exit code capture.
    Declares `is_authoritative() == false` (soft enforcement).
  - `BpfKernel` — Linux + `linux-bpf` feature. Today returns `Block`
    with reason "linux-bpf scaffold; loader pending M4.1". Same trait
    surface as `UserspaceKernel` so M4.1 swap is config, not refactor.
  - `ProcessSpec`, `KernelDecision`, `LaunchOutcome` — narrow types
    that travel cleanly across the userspace/eBPF datapath boundary.

- New `armor-core` features:
  ```toml
  [features]
  default = ["demo", "sqlite", "receipts", "apl", "reasoning", "kernel"]
  kernel = ["dep:armor-kernel"]
  linux-bpf = ["kernel", "armor-kernel/linux-bpf"]
  ```

- New CLI subcommands (feature-gated on `kernel`):
  ```
  armor kernel status
  armor run [--agent-id AGENT] [--cwd DIR] -- <program> [args...]
  ```
  `armor run` spawns a child under the userspace kernel. The policy
  callback is `allow_all` for M4 — wiring `execute_pipeline` as the
  policy source is M5 (when APL becomes the authoritative engine).

### Honest posture

`armor kernel status` reports `authoritative: no (soft enforcement)`
until the eBPF loader ships in M4.1. We do not market kernel
enforcement we don't yet provide. The binary tells the operator the
truth.

### What stayed

- `audit_events` / `receipts` schemas unchanged.
- `AppState`, `AuditStore`, `ReceiptStore`, `ReasoningHandle` unchanged.
- APL surface unchanged.
- SDK API unchanged.
- 219/219 default-feature tests still pass.

---

## 1.0.0-alpha.1 M5 — "Hardening + 1.0 RC" (staged, not committed)

**Scope:** wiring pass. The scaffolds from M2–M4 are now connected
end-to-end. `armor run` traverses the governance pipeline; every
launch produces a signed receipt; Postgres is a first-class receipt
backend; `--features postgres` works without extra config.

### What's new

- **`armor run` is governed end to end.** `cmd_kernel_run` now builds a
  full `AppState` and uses `execute_pipeline` as the kernel's policy
  callback. Verdict comes from the same pipeline that serves
  `armor inspect`. Fail-closed on pipeline error.

- **Receipt for every governed launch.** Side effect of the wiring
  above: each `armor run` produces an audit event + a signed,
  Merkle-chained receipt. `armor replay --list` shows your launches
  alongside HTTP-served runs. Tamper detection works identically.

- **Postgres receipts wired from the binary.** `try_build_receipt_logger`
  selects backend by URL scheme:
  - `sqlite:` → `SqliteReceiptStore`
  - `postgres://` / `postgresql://` → `PgReceiptStore`
  Build with `--features postgres` and set
  `DATABASE_URL=postgres://...` — receipts go to Postgres
  automatically, no extra flags.

- **Cargo feature composition for storage backends.** `armor-core`'s
  `sqlite` and `postgres` features now transitively enable
  `armor-receipts`'s matching feature via `armor-receipts?/sqlite` and
  `armor-receipts?/postgres`. No more divergence between the host
  binary and the receipts crate on which DB driver is compiled in.

- **Auto-seed on first `armor run`.** If the policy store has zero
  profiles, `cmd_kernel_run` seeds the demo set so the first launch
  produces a meaningful verdict instead of "Agent not found". Idempotent.

### Trait change (`armor-kernel`, internal)

`PolicyCheck` is now async:

```diff
-pub type PolicyCheck = Arc<dyn Fn(&ProcessSpec) -> KernelDecision + Send + Sync>;
+pub type PolicyCheck = Arc<
+    dyn for<'a> Fn(&'a ProcessSpec)
+        -> Pin<Box<dyn Future<Output = KernelDecision> + Send + 'a>>
+        + Send + Sync,
+>;
```

All in-tree callers (`UserspaceKernel::allow_all`, the test suite)
were updated. Not a public-API breaking change because `armor-kernel`
has no external consumers in 1.0-alpha.

### What's *not* in M5 (intentionally deferred)

- ❌ APL as the authoritative policy source in `armor serve`
  (`--policy file.apl` overlay) → **M6**. Requires designing the merge
  between APL evaluation and the current risk scoring; deserves its
  own ADR (0008) and a focused milestone.
- ❌ Drift replay with full pipeline re-execution against historical
  receipts → 1.0 GA or post-GA. Requires serializing the entire
  `InspectRequest` into the receipt body; we don't change the schema
  under RC.
- ❌ eBPF loader → M4.1.
- ❌ Cross-platform kernel (macOS Endpoint Security, Windows ETW) → 1.1.
- ❌ Mesh, KMS/HSM, license switch → 1.1 / 1.0 GA commit.

### What stayed

- `audit_events` / `receipts` schemas unchanged.
- `ReceiptLogger`, `ReasoningHandle`, `EnforcementKernel` trait shapes
  unchanged (only `PolicyCheck` callback type became async).
- APL surface unchanged.
- SDK API unchanged.
- 225/225 default-feature tests still pass.

---

## 1.0.0-alpha.1 GA pre-flight — E2E hardening (staged, not committed)

End-to-end smoke testing of the 1.0 GA candidate (server, CLI, HTTP API,
APL overlay, Docker compose) surfaced four issues that have been fixed
in the working tree:

### Fixes

- **`Dockerfile` rewritten for the workspace layout.** The previous
  Dockerfile pointed at `community/Cargo.toml` and `community/src/`,
  paths that no longer exist after the M1 workspace split. The
  container built but ran a 430 KB stub binary that exited
  immediately without output. The new Dockerfile is a single-shot
  `cargo build --release --bin armor --locked` against the real
  workspace; the resulting binary is ~18 MB and starts cleanly under
  `docker compose up`. The dependency-cache trick used previously
  was fragile across multi-crate workspaces and has been removed.
- **CLI banner** showed "8 Layers ARMED". Updated to "12 Layers ARMED"
  to match the 1.0 marketing surface (M3.5 + M4 added 4 layers on top
  of the original 8).
- **`armor-core` Cargo description** said "(Community Edition)".
  Updated to "(open-source edition)" for consistency with the
  Community vs Enterprise documentation in README + ENTERPRISE.md.

### Documented behaviour clarifications (no code change)

These are not bugs; they are operator-facing facts that the README
quickstart now spells out:

- HTTP API auth header is `Authorization: Bearer <key>`. There is no
  `X-API-Key` header.
- `InspectRequest` JSON uses camelCase keys at every level
  (`agentId`, `toolName`, `actionType`). The serde `#[serde(rename_all
  = "camelCase")]` attribute is the source of truth.
- The receipt signer key path defaults to
  `~/.armor/keys/receipt_signer.ed25519` natively and to
  `/home/armor/.armor/keys/receipt_signer.ed25519` inside the
  Docker container. Receipts signed by one cannot be verified by the
  other unless you mount the key in or set `ARMOR_SIGNER_KEY_PATH`.

### Test posture

- 234/234 default-feature tests still pass.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `docker compose build && docker compose up -d` healthy on the
  first attempt with the new Dockerfile; `/health` returns 200,
  `armor inspect` over HTTP returns the expected verdicts.

---

## 1.0.0-alpha.1 M6 — "APL as Live Policy Engine" (staged, not committed)

**Scope:** additive. The YAML profile + workspace policy system from
0.4.0 stays authoritative. APL is loaded as an *overlay* via
`armor serve --policy file.apl` and merged stricter-wins with the
YAML risk decision: APL can tighten the verdict, never relax it.

### What's new

- **`armor serve --policy <file.apl>`** loads an APL bundle at boot.
  Fail-fast on any compile error: if the operator asked for APL, they
  want APL.

- **Stricter-wins merge** in `execute_pipeline`: after the YAML risk
  score, the pipeline evaluates the APL overlay against a JSON context
  built from the request (`agent`, `action`, `workspace`, `risk`, and
  `ml` when reasoning is on) and merges via
  `merge_decisions(yaml, apl)` where `Block > Review > Allow`.

- **`policy_hash` in receipts is real now.** When an overlay is loaded,
  the SHA-256 of the compiled APL bundle replaces the M2 placeholder
  constant in every receipt body. Replay distinguishes runs with /
  without APL active by inspecting `policy_hash`.

- **`armor policy lint <file.apl>`** semantic alias for
  `armor policy test <file.apl>` without `--context`. Parse + validate
  only.

- **Example bundle** `crates/armor-core/examples/policies/strict.apl`
  shipped: three policies that tighten the YAML baseline (block
  high-risk shell, review all email, block off-allowlist HTTP).

- **`AppState.apl_overlay: Option<Arc<AplOverlay>>`** (cfg-gated on
  `feature = "apl"`, default on).

- **`try_build_receipt_logger(db_url, policy_hash)`** signature
  changed: now accepts an optional `policy_hash` override so the
  caller can pass the APL bundle digest. `None` preserves M2/M5
  behavior with the placeholder constant.

### Receipt shape

JSON shape unchanged. Only the *content* of `policy_hash` changes
when APL is loaded. Receipts produced before M6 (or in runs without
`--policy`) remain bit-identical to M5 — replay legacy intact.

### What's *not* in M6 (deferred)

- ❌ `armor policy migrate` (YAML → APL converter) → 1.1.
- ❌ Hot reload without restart → 1.0.x if requested.
- ❌ Multiple `--policy` files concatenated → 1.0.x if requested.
- ❌ APL replacing YAML entirely → 1.1 once we observe real usage.
- ❌ Drift replay with full pipeline re-execution → 1.0 GA or post-GA
  (requires receipt schema change to embed full `InspectRequest`).

### What stayed

- YAML profile + workspace policy system unchanged. Backward compat
  with 0.4.0 is full: not passing `--policy` produces identical
  behavior to M5.
- `audit_events` / `receipts` schemas unchanged.
- All trait shapes (`AuditStore`, `ReceiptStore`, `ReasoningHandle`,
  `EnforcementKernel`) unchanged.
- SDK API unchanged.

---

## Future (not yet released)
- **M3.1** (optional): WASM codegen for APL via `wasm-encoder`; full type
  checker.
- **M3.5.1**: real pre-trained ONNX models for intent-drift /
  prompt-injection / anomaly-seq, plus pluggable tokenizers shipped
  alongside model files.
- **M4.1**: real eBPF/LSM loader via `aya-rs` + LLVM 18+. LSM hooks on
  `execve`, `openat`, `connect`, `sendto`. Landlock fallback. Cgroup
  jailing. Long-lived detached child handle ownership. After this,
  `BpfKernel.is_authoritative()` flips to `true`.
- **M5**: APL replaces YAML as the authoritative policy format;
  `armor policy migrate` auto-converts. Drift replay re-executes the
  full pipeline in-sandbox against stored receipts; Postgres backend
  for receipts enabled from the binary; hardening pass before 1.0 GA.
- **1.1**: `armor-mesh` (gRPC gossip + federated rate budgets) +
  cross-platform kernel + KMS/HSM signer backends.

These are design intents, not breaking changes yet. This section will be
replaced with concrete diffs once each milestone ships.
