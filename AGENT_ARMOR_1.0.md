# Agent Armor 1.0 — "Fortezza"

> Design document per il salto da 0.4.0 a 1.0.
> Da *sidecar di governance HTTP* a **kernel distribuito, attestato, replayable e probabilisticamente consapevole per agenti autonomi.**
> 0.4.0 chiedeva agli agenti di passare da Agent Armor. 1.0 non lascia loro scelta.

---

## 1. La tesi della 1.0

0.4.0 è un *in-process HTTP gate*: se l'agente non chiama `/v1/inspect`, bypassa tutto. È il limite strutturale della 0.x.

**1.0 rovescia il modello:** il punto di applicazione non è più la SDK dell'agente, ma il **syscall / loopback / MCP transport**. L'agente non può *non* passare per Armor, perché Armor intercetta più in basso.

Questa è la rivoluzione. Tutto il resto (attestazione, replay, mesh, visual, ML) è conseguenza.

Regola d'oro che tiene in piedi l'intero design:

> **La valutazione probabilistica produce EVIDENZE, non VERDETTI.**
> Il verdetto finale resta deterministico. L'ML genera score; la policy APL decide.
> I modelli sono versionati per digest; al replay non si rigira il modello, si rilegge il suo output firmato dal receipt log.

---

## 2. I 7 pilastri

### Pilastro 1 — Enforcement Kernel

Il vero salto: Armor smette di essere opt-in.

- `armor-kernel`: daemon privilegiato che fa da chokepoint reale.
  - **Linux:** eBPF LSM hooks su `execve`, `openat`, `connect`, `sendto` + Landlock fallback.
  - **macOS:** Endpoint Security framework.
  - **Windows:** ETW + WFP (Windows Filtering Platform) per egress, minifilter opzionale per FS.
- L'HTTP sidecar della 0.4.0 diventa *fast path* per SDK-aware; il kernel è *fail-closed* per tutto il resto.
- Nuova modalità `armor run -- <cmd>` che lancia l'agente dentro una cgroup/job object governata.

**Breaking change:** il confine di trust si sposta. Gli SDK Python/TS restano ma perdono privilegio: *consigliano*, non *decidono*.

### Pilastro 2 — Signed Action Receipts + Replay Deterministico

- Ogni decisione (`allow|review|block`) produce un **receipt Ed25519-firmato** con: input hash, policy hash, plugin digests, ML model digests + scores, verdict, timestamp, parent receipt.
- Formato: DAG di receipt → **Merkle log append-only**. Una tabella `receipts` sostituisce `audit_events`.
- `armor replay <run_id>` rigioca l'intera traccia in sandbox e verifica byte-per-byte che le decisioni odierne coincidano con quelle storiche → detection di *policy drift*.
- Export standard: **in-toto attestation** + **SLSA provenance v1** per ogni azione.

### Pilastro 3 — Armor Policy Language (APL)

DSL tipizzato, compilato a bytecode deterministico. Sostituisce YAML + template.

```apl
policy "no_secrets_to_public_http" {
  when action.kind == "http.request"
   and action.url.host not in workspace.allowlist
   and payload contains secret_ref(_)
  then block, reason="PII egress"
}

policy "halt_on_hijack_suspicion" {
  when ml.prompt_injection.score > 0.85
   and action.kind in {"shell", "http"}
  then block, reason="injection suspected", evidence=ml.prompt_injection
}
```

- Type checker + LSP + `armor policy test`.
- Compila a WASM → stesso engine dei plugin → esecuzione deterministica, budget di istruzioni.
- Backward compat: il loader YAML resta ma stampa deprecation warning; i template diventano "preludio APL".

### Pilastro 4 — Attested Plugins + Supply Chain

Ogni `.wasm` plugin richiede:

- firma **Sigstore/cosign** (o chiave workspace),
- **SBOM** CycloneDX,
- digest in `skills-lock.json` (che oggi esiste ma è informativo → diventa autoritativo).

Più:

- registry plugin locale (`~/.armor/plugins/`) con verifica on-load,
- `armor plugin publish` firma e pusha, `armor plugin verify` offline.

### Pilastro 5 — Governance Mesh (multi-agente)

- Ogni nodo Armor espone un gossip endpoint gRPC (mTLS).
- Fatti propagati: policy revisions, receipt heads, plugin digests, revoche, anomalie comportamentali.
- **Rate budget globali**: un worker pool di 50 agenti condivide un budget "100 chiamate HTTP/min a github.com" — oggi è per-process, in 1.0 è federato.
- Modalità **hub** (singolo server) e **p2p** (CRDT su receipt log).

### Pilastro 6 — Visual come first-class citizen

La cartella `visual/` (oggi untracked) diventa il frontend ufficiale di Armor:

- servita direttamente da `armor serve` su `/ui` (embed via `rust-embed`),
- live stream dei receipt via SSE/WebSocket sul log Merkle,
- vista "neural" attuale = dashboard operativa, non demo marketing,
- `agent-armor-video/` (Remotion) resta fuori dal binario → pipeline assets per docs/sito.

### Pilastro 7 — Probabilistic Reasoning Plane

Tre classificatori locali (piccoli, CPU-friendly, no cloud) affiancano la pipeline deterministica:

| Modello | Cosa stima | Runtime |
|---|---|---|
| `intent-drift` | distanza semantica fra goal dichiarato e azione attuale | ONNX, ~30M param |
| `prompt-injection` | probabilità di injection / jailbreak nei tool args | DeBERTa-v3 fine-tuned |
| `anomaly-seq` | anomalia nella sequenza di azioni (autoencoder + seq model) | isolation forest + seq |

Ogni modello emette `{score: 0..1, features: [...], model_digest: sha256}` → finisce nel receipt firmato. APL consuma gli score.

**Calibrazione forzata**: `armor ml calibrate` misura FPR/FNR su un dataset workspace-specifico; se FPR > soglia policy, il modello va in *advisory-only*. Niente blocchi su modelli non calibrati.

**Feature flag `ml`**: la 1.0 core resta leggera e gira senza ML. Chi vuole AI-vs-AI accende il flag. I layer che dipendono dall'ML (vedi sezione 3) degradano a *rule-only* se il flag è spento.

---

## 3. Da 8 a 12 layer — onesto, non marketing

Il brand "8-layer" della 0.x diventa **"12-layer defense-in-depth"** nella 1.0. I nuovi layer non sono riempimento: coprono gap reali.

### Layer rafforzati (1–8)

| # | Layer | Cosa cambia in 1.0 |
|---|---|---|
| 1 | Input validation | + schema fuzzing sui tool args |
| 2 | Intent classification | diventa layer ML (`intent-drift`) |
| 3 | Tool args policy | APL tipizzato |
| 4 | Secret ref planning | + taint tracking cross-call |
| 5 | Egress control | kernel-level (eBPF/WFP/ES), non più solo HTTP |
| 6 | FS control | Landlock / ES / minifilter |
| 7 | Identity / auth | + workload attestation (SPIFFE/SPIRE opzionale) |
| 8 | Audit | → **Receipt Merkle log firmato** |

### Layer nuovi (9–12)

| # | Layer | Cosa fa | Perché manca oggi |
|---|---|---|---|
| **9** | **Supply chain** | verifica firma plugin, SBOM, revoche | i plugin WASM oggi girano senza attestazione |
| **10** | **Blast radius** | calcolo statico del danno potenziale prima di `allow` (file raggiungibili, segreti in scope, rete esposta) | oggi decidi sull'azione, non sul suo raggio |
| **11** | **Behavioral baseline** | anomaly detection per-workspace (`anomaly-seq`) | non c'è concetto di "normale" per questo agente |
| **12** | **Counterparty trust** | reputation di domini, MCP server remoti, modelli LLM chiamati | tutto è trusted by default oggi |

La mesh (pilastro 5) distribuisce 11 e 12: un'anomalia vista da un nodo immunizza gli altri.

---

## 4. Nuova struttura del repo

```
agent-armor/
├── crates/
│   ├── armor-core/         ← ex community/src (pipeline, policy, storage)
│   ├── armor-kernel/       ← NEW: eBPF / ETW / Endpoint Security
│   ├── armor-apl/          ← NEW: policy language + compiler
│   ├── armor-receipts/     ← NEW: Merkle log + signing
│   ├── armor-reasoning/    ← NEW: ONNX runtime + model registry firmato (feature=ml)
│   ├── armor-mesh/         ← NEW: gRPC gossip
│   ├── armor-plugins/      ← refactor con attestation
│   └── armor-cli/
├── ui/                     ← ex visual/ (embedded in binary)
├── sdks/{python,ts,go}/    ← +Go nuovo, tutti declassati a "hints"
├── examples/
├── docs/{book,adr}/        ← mdBook + Architecture Decision Records
├── media/                  ← ex assets/ + output agent-armor-video
│   ├── hero.gif / hero.mp4 / brain.gif
│   └── dashboard.png (screenshot visual)
└── xtask/                  ← build orchestration (release, sign, bench)
```

**Pulizia:** `enterprise/` resta fuori dal repo pubblico (scope confermato community-only). I `*.db` in root vanno in `.gitignore` — sono artefatti di test, erroneamente committati in 0.4.0.

---

## 5. Roadmap per milestone

| M | Nome | Contenuto | Gate di rilascio |
|---|------|-----------|------------------|
| **M1** | *Fortezza Foundation* | Cargo workspace split, `ui/` embedded, `media/` consolidato, `.gitignore` DB | `cargo build` passa, visual servito dal binary |
| **M2** | *Receipts* | Ed25519 + Merkle log + `armor replay` | replay bit-exact di una sessione 0.4.0 importata |
| **M3** | *APL alpha* | Compiler + LSP + test runner, retro-compat YAML | tutte le policy esistenti migrano con `armor policy migrate` |
| **M3.5** | *Reasoning Plane* | `armor-reasoning` crate, 3 modelli ONNX, calibrazione, APL integration | demo: injection bloccata con evidence nel receipt |
| **M4** | *Kernel Linux* | eBPF LSM + `armor run --` su Linux | benchmark < 5% overhead su `curl`/`ls` in loop |
| **M5** | *Attestation + Mesh* | Sigstore, SBOM, gRPC gossip | 3 nodi condividono un rate budget in demo |
| **M6** | *Kernel cross-platform + 1.0 GA* | macOS ES + Windows WFP, docs book, migration guide | RC → 1.0 tag |

Timeline realistica da solo: **4–6 mesi** se il kernel resta Linux-only a 1.0 e macOS/Windows slittano a 1.1.

---

## 6. Breaking changes vs 0.4.0 (vanno in MIGRATION.md)

1. `audit_events` → `receipts` (migrazione automatica, vecchia tabella tenuta readonly una release).
2. `agent-armor.yaml` *funziona ancora* ma deprecato → `.apl` preferito.
3. Gli SDK non sono più autoritativi: in mesh/kernel mode il verdetto SDK può essere scavalcato.
4. Binary name: resta `agent-armor`, ma `armor` diventa l'alias breve ufficiale.
5. Branding: "8-layer" → "12-layer defense-in-depth" ovunque (README, sito, SDK docstring, video Remotion).
6. Licenza: la 1.0 ships su **BUSL-1.1** con **Change License: Apache-2.0** scritta nella licenza stessa. Ogni release converte automaticamente ad Apache-2.0 quattro anni dopo la pubblicazione. Vedi `LICENSE` + ADR 0002.

---

## 7. Decisioni aperte — **Risolte (2026-04-23)**

Le quattro scelte che bloccavano la forma di 1.0 sono chiuse. Dettagli completi in
[`docs/adr/0002-open-source-license-and-scope.md`](docs/adr/0002-open-source-license-and-scope.md).

1. **Kernel scope** → **Linux-only a 1.0**. Cross-platform (macOS Endpoint Security, Windows ETW+WFP) rinviato a 1.1. macOS/Windows restano in preview userspace via SDK 0.4.0 + process jailing soft.
2. **Mesh timing** → **tagliata a 1.1**. 1.0 ships single-node. `armor-mesh` arriva come crate indipendente in 1.1 (schema receipt già compatibile con federazione).
3. **Licenza core** → **BUSL-1.1 con Change License: Apache-2.0 baked-in**. La licenza converte automaticamente ad Apache-2.0 quattro anni dopo la pubblicazione di ogni release. Nessuno switch manuale serve, e nessun futuro maintainer può rinegoziare la transizione: è scritta nella licenza stessa. `armor-enterprise` resta sotto licenza commerciale separata.
4. **ML plane** → **feature-flag `ml` opzionale**, default off. `armor-reasoning` (M3.5) è crate separato; senza `ml` i riferimenti APL `ml.*` risolvono a evidenza mancante.

Roadmap finale: M1 ✅ · M2 ✅ · M3 ✅ · M3.5 ✅ · M4 ✅ · M5 ✅ · M6 ✅ · 1.0 GA pending license switch + commit autorizzato.

---

## 8. Stato finale dei pilastri (1.0 GA)

| Pilastro | Crate | Stato | Note |
|---|---|---|---|
| 1 — Enforcement Kernel | `armor-kernel` | ✅ scaffold + UserspaceKernel | Real eBPF/LSM loader → 1.0.1; cross-platform (macOS/Windows) → 1.1 |
| 2 — Signed Receipts | `armor-receipts` | ✅ completo | Ed25519 + Merkle log, SQLite + Postgres backends |
| 3 — Armor Policy Language | `armor-apl` | ✅ completo | Tree-walk evaluator + APL live overlay (M6); WASM codegen → 1.0.3 |
| 4 — Attested Plugins | (in `armor-core/plugins/`) | infra 0.4.0 | SBOM + Sigstore wiring → 1.1 |
| 5 — Governance Mesh | (futuro `armor-mesh`) | rinviato | 1.1 (gRPC gossip + federated rate budgets) |
| 6 — Visual Plane | `ui/` + `armor-core` `ui-embed` feature | scaffold | Frontend reale work-in-progress separato |
| 7 — Probabilistic Reasoning | `armor-reasoning` | ✅ scaffold + tract backend | Modelli reali pre-trained → 1.0.2; GPU + ort backend → 1.1 |

**12 layer** = 8 originali (hardened in M2–M5) + 9 supply chain attestation (1.1) + 10 blast radius (1.0.1 con eBPF) + 11 behavioral baseline (presente da 0.4.0, esposto via APL `ml.*` paths) + 12 counterparty trust (scaffold via signer key_id nei receipt; full mesh wiring → 1.1).

---

## 9. Boundary Community vs Enterprise

Agent Armor 1.0 esiste in due edizioni che condividono **lo stesso governance kernel**. La differenza è categoriale, non gating:

### Cosa è e resta nel kernel open-source (Agent Armor OSS, BUSL-1.1 con Change License Apache-2.0 baked-in)

- Il governance kernel completo: eBPF/LSM loader (1.0.1), `UserspaceKernel` cross-platform, `armor run`, audit pipeline 12-layer.
- Receipt schema completo: Ed25519 + Merkle log + replay deterministico.
- APL completo: parser, validator, tree-walk evaluator, WASM codegen (1.0.3).
- Reasoning framework: `NoopEngine` + `TractEngine` + BYO ONNX models, BYOK signer (HSM/KMS via AWS KMS / Azure KV / HashiCorp Vault / on-prem Thales/Utimaco).
- Governance mesh single-cluster baseline (1.1): gRPC gossip + audit log condivisi all'interno di un cluster. Multi-region active-active + federated rate budget + mTLS KMS-backed restano in Enterprise (mesh tier-2).
- Plugin WASM attestati con Sigstore + SBOM.
- UI embedded via `ui-embed`.
- SQLite + Postgres backends.
- Tutti i sub-cmd CLI documentati.

**Promessa non rinegoziabile**: nulla di sopra entrerà mai in feature gating Enterprise. Nessun rebrand "Community Edition lite" mai. Le primitive di sicurezza fondamentali sono OSS for life.

### Cosa è **Agent Armor Enterprise** (commercial license)

Categorizzato per dominio:

- **Compliance evidence pack EU AI Act + GDPR + DORA**: Annex IV dossier generator, DPO dashboard, RoPA + DPIA tooling, post-market monitoring automation, EU AI Office incident report workflow, DORA major-incident classification + ICT third-party risk mapping, ISO/IEC 42001 QMS console. Conformity assessment integration con notified body (TÜV / Dekra / Bureau Veritas) sulla roadmap.
- **Cockpit operativo**: web dashboard real-time, alerting, runbook automation, SIEM native connectors (Splunk / Datadog / Elastic / Sentinel / Chronicle), Slack/Teams hooks.
- **Identity & multi-tenancy**: SSO SAML/OIDC, RBAC fine-grained, MFA enforcement, IP allowlist, multi-tenant isolato, eIDAS identità qualificate.
- **Cryptographic ops managed**: managed key lifecycle sopra il BYOK OSS, eIDAS qualified e-signatures, field-level encryption, KMS contractual support.
- **Curated ML model library**: modelli pre-trained (intent-drift, prompt-injection, anomaly-seq) versionati e firmati, GPU acceleration, threat intel feed AI-specifico real-time. Benchmark pubblici quando i modelli stabilizzano.
- **Mesh tier-2**: multi-region active-active, federated rate budget, mTLS KMS-backed (sopra il mesh single-cluster OSS).
- **Heavy-engineering moat code-level**: curated eBPF/LSM program library (DORA Art. 28-44), confidential-computing receipts (SGX/SEV-SNP/Nitro Enclave per EU AI Act high-risk + healthcare), forensic replay con time-travel (EU AI Act Art. 73 incident reporting). Vedi `ENTERPRISE.md` Layer 2.
- **Skills marketplace**: private registry plugin attestati con supply chain SLA.
- **Deployment options**: managed (Iaga Cloud, EU-region first), air-gapped on-prem con offline updates, marketplace AWS/Azure/GCP, FedRAMP-ready in roadmap.
- **Founder-led support**: SLA 99.95%, oncall 24/7 dai maintainer stessi (no tier-1 ticket triage), linea diretta col founder per Growth+, response 1h critical, security advisory pre-disclosure, LTS 5 anni, migration assistance.

### Logica del divario

OSS dà i **meccanismi**. Enterprise dà le **evidenze + cockpit + scala + support contrattuale** che servono a un'organizzazione regolamentata per dimostrare compliance al regulator/auditor/notified body, non solo per averla. Il divario è **time-to-audit**: con OSS un team smart ci arriva in 6 mesi di lavoro custom, con Enterprise in **14 giorni** out-of-the-box.

Slogan unificante: *From governance kernel to audit dossier in 14 days.*

Vedi [`ENTERPRISE.md`](ENTERPRISE.md) per il pitch completo + EU AI Act / GDPR / DORA article-by-article mapping. Iaga Cloud è il deployment managed (uno dei modi di consumare Enterprise), non un prodotto separato in questo repo.

---

## 10. Sintesi

Agent Armor 1.0 è tre cose in una:

- **un kernel** (intercetta più in basso dell'SDK),
- **un log firmato** (ogni decisione è replayable e non ripudiabile),
- **un cervello** (ML probabilistico che produce evidenza, non verdetti).

Il tutto dietro un unico DSL (APL), distribuito in una mesh, osservabile da una UI embedded.

Non è una 0.5 con più layer. È un'altra categoria di prodotto.
