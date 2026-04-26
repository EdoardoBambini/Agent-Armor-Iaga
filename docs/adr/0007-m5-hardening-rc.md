# ADR 0007 — M5 Hardening + 1.0 RC Posture

- **Status**: Accepted
- **Date**: 2026-04-25
- **Deciders**: Edoardo Bambini
- **Milestone**: M5 "Hardening + 1.0 GA"
- **Relates to**: ADR 0002 (license direction), ADR 0003 (receipts), ADR 0006 (kernel)

## Contesto

M1–M4 hanno costruito le superfici architetturali di 1.0: workspace + ui (M1), receipt firmati (M2), APL (M3), reasoning plane (M3.5), enforcement kernel scaffold (M4). M5 è il punto in cui tutto quello che è stato scritto come "trait + scaffold + opt-in" viene **wireato end-to-end** e si fissa la posture per il release candidate.

Questa ADR fissa cosa entra in M5, cosa resta esplicitamente fuori (e perché), e cosa significa "1.0 RC" per Agent Armor.

## Decisioni

### 1. `armor run` attraversa la pipeline di governance

Prima di M5, `armor run` lanciava qualsiasi processo con un policy callback `allow_all`. Il backend kernel era visibile nei receipt ma il verdetto non lo era.

In M5 il `cmd_kernel_run` (`crates/armor-core/src/main.rs`):

1. Costruisce un `AppState` completo (storage, receipts, reasoning, ecc.) — stesso codice path del server HTTP.
2. Sintetizza un `InspectRequest` dal `ProcessSpec` (program → tool_name, args+cwd → payload, action_type=Shell).
3. Crea un `PolicyCheck` async che chiama `execute_pipeline(&request, &state)` e mappa `GovernanceDecision` → `KernelDecision` 1:1.
4. `UserspaceKernel::launch` await il callback prima di spawnare.

**Conseguenza pratica**: ogni `armor run -- <cmd>` produce un audit event + un signed receipt (M2 dual-write automatico). `armor replay --list` mostra le esecuzioni governate. Drift detection funziona già: cambia la policy per quell'agent e replay segnala la divergenza (perché input_hash + policy_hash sono firmati).

**Fail-closed**: se la pipeline ritorna `Err` (es. agent sconosciuto), il policy callback restituisce `KernelDecision::Block`. Mai fail-open per errore di sistema.

### 2. PolicyCheck async (breaking nel trait, additive nel comportamento)

Il trait `EnforcementKernel` di M4 aveva `PolicyCheck` sincrono. Per chiamare la pipeline async serve un Future. M5 cambia la signature:

```rust
pub type PolicyCheck = Arc<
    dyn for<'a> Fn(&'a ProcessSpec)
        -> Pin<Box<dyn Future<Output = KernelDecision> + Send + 'a>>
        + Send + Sync,
>;
```

I callsite esistenti sono stati aggiornati. `UserspaceKernel::allow_all()` continua a esistere e ritornare un Future banale. Test invariati nella loro semantica, riformulati per il Future.

Non è breaking pubblico: `armor-kernel` non ha consumer esterni in 1.0-alpha — il trait è stato introdotto in M4 della stessa staged session.

### 3. Postgres backend per receipts wireato dal binary

`pipeline::receipts::try_build_receipt_logger` ora seleziona il backend al runtime in base al prefisso del `database_url`:

- `sqlite:` → `SqliteReceiptStore` (M2).
- `postgres://` o `postgresql://` → `PgReceiptStore` (presente in `armor-receipts` da M2 ma prima non wireato dal binary).
- Altro → receipts disabilitati con `tracing::info`.

Le features `armor-core/sqlite` e `armor-core/postgres` ora attivano transitivamente le features omonime di `armor-receipts` via `armor-receipts?/sqlite` e `armor-receipts?/postgres` (Cargo feature composition con `?`).

Questo chiude un debito documentato in ADR 0003 ("Postgres backend wireato dal binary → M5").

### 4. Seed automatico al primo `armor run`

`cmd_kernel_run` chiama `seed_demo_data` automaticamente se il `policy_store` è vuoto. Ragione: senza profili agent registrati, ogni pipeline call fail-closed con "Agent not found", che è poco utile per chi prova `armor run` la prima volta. Il seed è idempotente (skip se profiles già presenti).

Questo NON cambia il comportamento di `armor serve`, che ha già il flag `--seed-demo` esplicito (default true).

### 5. Cosa resta fuori da M5 (esplicito)

- ❌ **APL come fonte autoritativa di policy**. Il caricamento `--policy file.apl` in `armor serve` come overlay additivo è M6. Ragione: l'integrazione richiede progettare il merge tra APL evaluation e l'attuale risk scoring, decisione architetturale che merita la propria ADR (0008) e una milestone dedicata.
- ❌ **Drift replay con re-execute della pipeline**. L'infrastruttura `armor_receipts::replay` esiste da M2 con un evaluator pluggable. M5 non aggiunge un default evaluator che riesegue la pipeline storica perché richiede serializzare l'intero `InspectRequest` nei receipt — schema change non desiderato sotto release candidate.
- ❌ **Loader eBPF**. M4.1.
- ❌ **Cross-platform kernel** (macOS Endpoint Security, Windows ETW). 1.1.
- ❌ **Mesh** (gRPC gossip, federated rate budgets). 1.1.
- ❌ **KMS / HSM signer backend**. 1.1.
- ❌ **License switch BUSL → Apache-2.0**. Eseguito al commit unico di release 1.0 GA, deciso fuori da questa ADR (vedi ADR 0002).

### 6. Posture "1.0 RC"

Definiamo "release candidate" così:

- **Architettura completa**: kernel + receipts + APL + reasoning + ML opt-in tutti integrati e wireable.
- **Default features funzionali**: il binary stock con `cargo install` produce `armor serve`, `armor inspect`, `armor run`, `armor replay`, `armor policy test`, `armor reasoning info`, `armor kernel status` — tutti operativi su un DB sqlite freschissimo, zero config.
- **Test workspace** verde su feature default. Clippy `--all-targets -D warnings` pulito.
- **Onesto**: ogni surface che è scaffold dichiara di esserlo nel suo CLI status (vedi `armor kernel status` → "soft enforcement"). Niente marketing che si scontra con la realtà operativa.
- **Documentato**: ogni milestone ha un ADR, un README/MIGRATION update, e una nota in `MEMORY.md` per la prossima sessione.

Ciò che NON è 1.0 RC ma diventa 1.0 GA:
- License switch (eseguito al commit unico).
- Audit di sicurezza esterno (responsabilità dell'utente prima del go-live).
- Documentazione pubblica (`docs/site/`) — fuori scope di queste milestone tecniche.

## Conseguenze

- **Test workspace**: 225/225 invariato (i 6 test M4 userspace passano con la nuova signature async di PolicyCheck dopo refactor minimale).
- **Compile time**: invariato.
- **Binary behavior**: `armor run` ora produce side effect significativi (audit event + receipt firmato) per ogni esecuzione. Documentato in MIGRATION.md.
- **Receipt count cresce**: ogni `armor run` aggiunge un receipt al DB. Nessun cleanup automatico — il DB è append-only by design (replay deve poter ricostruire la storia).
- **Postgres support**: chi setta `DATABASE_URL=postgres://...` ora ha receipts firmati su Postgres senza configurazione aggiuntiva, purché compili con `--features postgres`.

## Esempio operativo end-to-end

```bash
# Default build
$ cargo build --release

# Avvia il server (sqlite locale, seed demo automatico)
$ armor serve &

# In un'altra shell: lancia un comando governato
$ armor run --agent-id openclaw-builder-01 -- python my_agent.py
[armor run] backend=userspace agent=openclaw-builder-01 program=python args=["my_agent.py"]
[armor run] decision: Block
[armor run] reason: policy blocked launch

# Ispeziona la chain dei receipt
$ armor replay --list --limit 5
run_id                                count  verdict first                last
a3c845ab-1d2e-4bbc-...                    1 Block 2026-04-25T...      2026-04-25T...

# Verifica firma Ed25519 della catena
$ armor replay a3c845ab-1d2e-4bbc-...
CHAIN OK  run_id=a3c845ab-...  receipts=1  signer=ed25519-3c8f87af...
  seq=0    verdict=Block  risk=74  reasons=["…"]

# Postgres invece di sqlite
$ DATABASE_URL=postgres://armor:armor@localhost/armor armor serve
# Receipts vanno automaticamente su Postgres senza altro tuning.
```

## Riferimenti

- ADR 0002 — license direction + ml opt-in
- ADR 0003 — receipts schema + dual-write
- ADR 0004 — APL MVP
- ADR 0005 — reasoning plane MVP
- ADR 0006 — kernel MVP
- `AGENT_ARMOR_1.0.md` — design 1.0 completo
