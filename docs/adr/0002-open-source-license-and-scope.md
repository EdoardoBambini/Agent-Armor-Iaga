# ADR 0002 — Chiusura decisioni aperte 1.0 (licenza, ML, kernel, mesh)

- **Status**: Accepted
- **Date**: 2026-04-23
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.0-alpha → 1.0 GA
- **Replaces/amends**: `AGENT_ARMOR_1.0.md` §7 (decisioni aperte)

## Contesto

`AGENT_ARMOR_1.0.md` §7 lasciava aperte quattro scelte che cambiano la forma di 1.0:

1. **Kernel scope** — Linux-only o cross-platform full?
2. **Mesh timing** — dentro 1.0 (M5) o posticipata a 1.1?
3. **Licenza core** — BUSL-1.1 o Apache-2.0?
4. **ML plane** — obbligatorio o feature-flag opzionale?

Questa ADR chiude le quattro. Filosofia guida: **"open source assurdo e inevitabile"** → adozione default, zero frizione legale, ship veloce di un nucleo eccellente, monetizzazione su strato enterprise/managed separato.

## Decisione 1 — Licenza core: **target Apache-2.0** al GA

### Posizione finale

Il core (`armor-core`, `armor-receipts`, `armor-apl`, `armor-reasoning`, `armor-kernel`) va su **Apache-2.0** al momento del release 1.0 GA.

### Perché

BUSL-1.1 sul runtime è incompatibile con la tesi di "infrastruttura default":

- **Cloud provider** (AWS/GCP/Azure) non integrano BUSL su piattaforme managed — perdita automatica di un canale distributivo enorme.
- **Backlash documentato**: MongoDB → SSPL, Elastic → SSPL, Redis → RSAL, HashiCorp → BUSL. In ogni caso: forchette (OpenSearch, Valkey, OpenTofu) o caduta di trust. Armor non ha leva di mercato per sostenere un simile attrito.
- **CNCF / OpenSSF alignment**: Kubernetes, Envoy, Prometheus, OpenTelemetry, Terraform-OSS sono tutti Apache-2.0. Per giocare in quella lega serve lo stesso licensing.
- **Contribuzioni OSS**: CLA + licenza non-OSI = zero PR esterne serie, zero integrazioni downstream.
- **Patent grant di Apache-2.0** è esplicito (art. 3), cosa che manca in MIT/BSD e tutela meglio i contributor.

### Stato esecutivo

- Il file `LICENSE` e `Cargo.toml` mantengono **BUSL-1.1** nello stato working-tree corrente (1.0-alpha.1, preview) per ragioni fuori dal controllo della 1.0-alpha.
- Lo **switch a Apache-2.0 è parte del commit unico di rilascio 1.0 GA** e non va anticipato in milestone intermedie.
- Da questo momento, nuovi file sorgente sono scritti ipotizzando Apache-2.0 come destinazione (nessun header BUSL nei sorgenti nuovi; i file mantengono il pattern esistente del repo).

### Monetizzazione

- `armor-enterprise` (repo privato, non in questo workspace): multi-tenant managed, compliance packs, SLA 24/7, SSO/SAML, audit export packaged, support commerciale. Licenza: proprietaria o BUSL-1.1 a scelta, indipendente dal core.
- `armor-mesh` (quando arriverà in 1.1): decisione di licenza rinviata ma orientata anch'essa ad Apache-2.0 per coerenza.

## Decisione 2 — ML plane: **feature-flag `ml` opzionale**, default off

### Posizione finale

Il Probabilistic Reasoning Plane (pilastro 7) è un **crate separato** (`armor-reasoning`, M3.5) con feature flag `ml`. Default: disattivato.

### Perché

- ONNX runtime aggiunge ~40–60 MB al binary e dipendenze native (opzionalmente GPU). L'80% dei deployment giorno-1 non userà ML.
- Coerente con la regola d'oro del design: **"ML produce evidenze, policy deterministica decide"**. Senza feature `ml`, i riferimenti `ml.*` in APL risolvono a *unknown* e vengono gestiti come evidenza mancante (policy APL deve prevedere il ramo `missing`).
- Binary core leggero = adozione più rapida, CI più veloci, meno superficie di attacco per chi non vuole ML.
- I receipt contengono sempre `model_digests: []` e `ml_scores: None` se feature off, preservando replay bit-exact.

### Conseguenze

- `armor-reasoning` si costruisce con `cargo build -p armor-reasoning --features ml` (nessun default).
- `armor-core` non dipende da `armor-reasoning`; lo carica dinamicamente solo se il config abilita il plane e la feature è compilata.

## Decisione 3 — Kernel scope: **Linux-only a 1.0**, fallback userspace su macOS/Windows

### Posizione finale

`armor-kernel` (M4) ships solo **Linux eBPF LSM + Landlock** in 1.0. macOS (Endpoint Security) e Windows (ETW + WFP) restano in preview userspace via HTTP sidecar 0.4.0 + process jailing limitato, con UX CLI identica (`armor run -- <cmd>`) ma enforcement soft.

### Perché

- eBPF LSM + Landlock sono production-ready su kernel ≥ 5.13, ampiamente deployati.
- **macOS Endpoint Security** richiede kernel extension firmata Apple Developer Program ($99/anno + review Apple di giorni), più entitlement `com.apple.developer.endpoint-security.client` (whitelist Apple).
- **Windows ETW + WFP** richiede driver firmati con Extended Validation certificate ($300–500/anno), più eventuale attestazione WHQL per distribuzione consumer.
- Stack tripla = 8+ mesi reali, non 4. Meglio 1.0 eccellente su Linux che 1.0 mezza-rotta su tre OS.
- README e docs saranno espliciti: "Linux = production, macOS/Windows = preview userspace". Cross-platform kernel vero → **1.1** (milestone M6 spostata).

### Conseguenze

- L'SDK 0.4.0 HTTP sidecar resta il meccanismo di fallback userspace — non deprecato, solo declassato.
- `armor-kernel` è un crate con `#[cfg(target_os = "linux")]` gate; fuori da Linux il crate non si compila (o espone stub `unimplemented!`).
- Documentazione kernel chiaramente separa "enforcement vero" da "preview userspace".

## Decisione 4 — Mesh: **tagliata a 1.1**

### Posizione finale

Il pilastro 5 (Governance Mesh) **esce da 1.0**. Il crate `armor-mesh` (gRPC gossip, mTLS, CRDT su receipt log, rate budget federati) arriva in **1.1** come crate indipendente, opt-in via feature flag.

### Perché

- Mesh da sola costa 2–3 mesi (protocollo gossip, mTLS, federazione stato, test di consistenza CRDT). Ritarda il ship di 1.0 per una feature che è killer solo per utenti multi-agent-at-scale.
- Single-node Armor 1.0 con kernel Linux + receipts + APL + plugin attestati + UI embedded + ML opzionale **è già un prodotto di una categoria che non esiste**.
- Lo schema `Receipt.parent_hash` è già pensato per federazione futura: nessun breaking change quando mesh arriverà.

### Conseguenze

- Roadmap 1.0 passa da 6 milestone a 5:
  - M1 ✅ Fortezza Foundation
  - M2 `armor-receipts` (ora)
  - M3 `armor-apl`
  - M3.5 `armor-reasoning` (opt-in `ml`)
  - M4 `armor-kernel` (Linux)
  - M5 hardening + 1.0 GA
- M5 originale (mesh) e M6 originale (cross-platform kernel) migrati a **1.1**.

## Conseguenze trasversali

- `AGENT_ARMOR_1.0.md` §7 va aggiornato: stato "Risolte — vedi ADR 0002".
- Ogni futura milestone assume queste quattro decisioni come baseline.
- Il messaging pubblico di Armor ("12-layer defense-in-depth", "replay bit-exact", "kernel-enforced governance") regge su queste scelte. Documentarle ora evita di ridiscuterle ad ogni review.

## Riferimenti

- `AGENT_ARMOR_1.0.md` — design 1.0 completo
- `docs/adr/0001-workspace-split.md` — split workspace M1
- `docs/adr/0003-signed-receipts-design.md` — design M2 (receipts)
