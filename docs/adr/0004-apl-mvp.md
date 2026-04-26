# ADR 0004 — Armor Policy Language (APL) MVP (M3)

- **Status**: Accepted
- **Date**: 2026-04-23
- **Deciders**: Edoardo Bambini
- **Milestone**: M3 "Armor Policy Language"
- **Relates to**: `AGENT_ARMOR_1.0.md` §2 Pilastro 3 (APL)

## Contesto

Il pilastro 3 prevede la sostituzione del pipeline YAML + template della 0.4.0 con un DSL tipizzato, compilato a bytecode deterministico (target WASM nel disegno originale). APL deve:

- essere leggibile da operator non-Rust,
- permettere al type checker di prendere errori a compile-time,
- avere esecuzione **deterministica** per il replay dei receipt M2,
- convivere con il loader YAML esistente durante la transizione.

Questa ADR fissa le scelte di M3, scope MVP incluso, e documenta i trade-off che rinviamo.

## Decisioni

### 1. Target di esecuzione: **tree-walk evaluator**, non WASM (in M3)

**Scelta.** M3 ships un interprete Rust puro che cammina direttamente sull'AST. Nessun codegen WASM in M3.

**Motivazione.**

- Un tree-walk evaluator che non tocca il clock, il disco, la rete o l'RNG *è già* deterministico. Dato lo stesso AST e lo stesso `Context`, produce lo stesso `Value`. Questa è esattamente la proprietà che serve al replay dei receipt M2.
- WASM codegen richiede una toolchain seria (`wasm-encoder` + un'IR intermedia, register allocation, linear memory layout per closures). Ship `armor-apl` con un tree-walk che funziona subito sposta la complessità a quando serve davvero: M3.1, o quando `armor-kernel` (M4) richiederà sandboxing hard-isolated tra processi.
- I test di M3 coprono la semantica della lingua, non la rappresentazione eseguibile. Quando arriverà il compiler WASM userà gli stessi test per regressione.
- **Budget di istruzioni**: implementato come `EvalBudget` con decremento su ogni nodo AST. Default 10_000 step, override per-call. Sufficiente per bloccare loop patologici senza pagare il costo di sandbox-kernel per ogni eval.

**Trade-off accettato.** L'evaluator gira nello stesso processo di `armor-core`. In ambiente enterprise con policy fornite da terzi questo non è il modello di minaccia — l'APL MVP assume policy fornite dal workspace owner, non da attori potenzialmente ostili. Quando (in 1.1) apriremo la marketplace di policy firmate, si sostituirà l'evaluator con un modulo WASM isolato.

### 2. Scope del linguaggio (M3 MVP)

Supportato:
- `policy "name" { when <expr> then <action> }`
- `<action>` = `allow | review | block [, reason="..."] [, evidence=<expr>]`
- Literali: string (con escape `\n \t \r \" \\`), int, bool
- Path access: `action.url.host` (percorso dotted arbitrariamente profondo)
- Operatori binari: `== != < <= > >= and or`
- Operatori unari: `not`
- Membership: `x in y`, `x not in y` (liste o stringhe)
- Call: `contains(s, sub) | starts_with(s, pre) | ends_with(s, suf) | len(x) | lower(s) | upper(s) | secret_ref(_)`
- Commenti: `// line comment`
- Precedence (low→high): `or` → `and` → prefix `not` → `==/!=/</<=/>/>=` → `in/not in` → primary
- **Short-circuit evaluation** per `and` e `or`

Fuori scope M3 (rinviati a M3.1 o oltre):

- ❌ Loops, let-binding, closures.
- ❌ Map/dict literali (solo path access legge object).
- ❌ Full type checker (il validator attuale è strutturale: nomi unici, arità builtin).
- ❌ Custom function definition lato utente (solo builtin).
- ❌ WASM codegen.
- ❌ LSP / syntax highlighting (hanno senso quando il linguaggio è stabile).
- ❌ Import tra file APL.

### 3. Struttura del crate

```
crates/armor-apl/
├── Cargo.toml
└── src/
    ├── lib.rs       — public surface (parse, compile, validate, evaluate_program)
    ├── errors.rs    — AplError
    ├── lexer.rs     — logos-based Token + tokenize(src)
    ├── ast.rs       — Program, Policy, Action, Expr, Lit, BinOp, UnOp, Verdict
    ├── parser.rs    — recursive-descent parser
    ├── validator.rs — structural validator (non-empty names, arity, ...)
    └── eval.rs      — Context, EvalBudget, Value, evaluate_program, eval_expr
```

Dipendenze esterne: `logos 0.14` (lexer), più i condivisi del workspace (`serde`, `serde_json`, `thiserror`). Zero dep WASM o parser-combinator heavyweight.

### 4. Integrazione con `armor-core`

- Nuova feature `apl` in `armor-core`, default **on**: attiva `armor-apl` come dep optional.
- Nuovo subcomando CLI `armor policy test <file.apl> [--context ctx.json]`:
  - Parse + validate sempre.
  - Se `--context` è fornito, carica il JSON, esegue `evaluate_program`, stampa FIRE/MISS.
  - Exit code: 0 success, 1 policy error (parse / typecheck / runtime), 2 I/O error.
- Il loader YAML legacy resta. APL **non** sostituisce il policy store in M3: è un secondary evaluator accessibile via CLI. L'integrazione pipeline ("APL come fonte di verità per le decisioni") arriva in M5 dopo che la libreria policy avrà raggiunto stabilità.
- L'AST si serializza a JSON via `serde`, quindi può essere persistito nel DB policy_store in fasi future senza reparsare il sorgente ogni volta.

### 5. Semantica deterministica (contratto stabile)

- Ordine di esecuzione: `policies` in *declaration order*. La **prima** policy il cui `when` evaluta truthy produce il verdetto e interrompe il ciclo. Gli autori ordinano per severità: `block` prima di `review` prima di `allow`.
- Truthiness: `Bool(false)`, `Null`, `Int(0)`, `Float(0)`, `""`, `[]` → falsy. Tutto il resto → truthy. Documentato e coperto da test.
- Equality: int↔float cross-comparison allowed (`1 == 1.0`). Altri cross-type: strict inequality.
- Missing paths: `action.nonexistent` → `Value::Null`. Policy che si appoggiano a campi assenti devono trattarli come `null` esplicitamente.
- Budget exhaustion produce `AplError::BudgetExhausted`; non fire silenzioso.

Questo contratto **non cambierà** in versioni successive di APL (M3.1 WASM compiler ridurrà solo le performance, non la semantica).

## Conseguenze

- 28 test nuovi per `armor-apl` (13 parser + 15 evaluator). Zero regressioni sui test pre-esistenti.
- Crate indipendente (zero dep ciclica su `armor-core`), riusabile da tool esterni (policy linter standalone, IDE plugin futuri).
- La decisione di rinviare WASM è esplicita: nessuno legga "APL gira in WASM" dal README finché M3.1 non lo implementa. La CLI help del comando `armor policy test` segnala "dry-run" per riflettere lo scope MVP.

## Esempio completo

```apl
// crates/armor-apl/examples/no_pii_egress.apl
policy "no_secrets_to_public_http" {
  when action.kind == "http.request"
   and action.url.host not in workspace.allowlist
   and secret_ref(action.payload)
  then block, reason="PII egress", evidence=action.url.host
}

policy "halt_on_hijack_suspicion" {
  when action.kind == "shell"
   and action.risk_score > 80
  then block, reason="injection suspected"
}

policy "default_allow" {
  when true
  then allow
}
```

Dry-run:

```
$ armor policy test no_pii_egress.apl --context sample.json
OK  parsed 3 policies from no_pii_egress.apl
  - no_secrets_to_public_http → Block
  - halt_on_hijack_suspicion → Block
  - default_allow → Allow
FIRE  policy=default_allow  verdict=Allow  reason=None
```

## Riferimenti

- `docs/adr/0002-open-source-license-and-scope.md` — scelte trasversali 1.0
- `docs/adr/0003-signed-receipts-design.md` — design M2
- `AGENT_ARMOR_1.0.md` §2 Pilastro 3 — disegno APL completo
