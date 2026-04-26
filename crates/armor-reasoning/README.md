# armor-reasoning

Probabilistic Reasoning Plane for Agent Armor 1.0 (M3.5).

ML produces **evidence**, never verdicts. The deterministic policy layer
decides; this crate just feeds it scores.

## Backends

| Backend       | Feature flag | Native deps | Use case                |
|---------------|--------------|-------------|-------------------------|
| `NoopEngine`  | always on    | none        | tests, ML disabled prod |
| `TractEngine` | `ml`         | none        | production with ONNX    |

`tract-onnx` is pure Rust. No system libraries to install, no linker
dance, builds clean on Linux / macOS / Windows. GPU support and the
`ort` (ONNX Runtime native) backend are tracked for 1.1.

## Configuring models

The host (`armor-core`) reads model paths from the environment:

```
ARMOR_REASONING_MODELS=intent_drift:/path/to/a.onnx,prompt_injection:/path/to/b.onnx
```

Format: `name:path` pairs, comma-separated. Malformed entries are
silently dropped (with a `warn!` log). Empty / unset → engine falls
back to `NoopEngine` and the pipeline runs without ML evidence.

## Verifying a deployment

```
$ cargo build --release --features ml
$ armor reasoning info
engine: tract
models: 2
  - intent_drift             sha256=8f4a3c...
  - prompt_injection         sha256=2b9e1d...
```

The SHA-256 of every loaded model is embedded in every signed receipt
the host produces (see `armor-receipts`). That's what makes cross-version
replay deterministic: change a model, the digest changes, replay flags
the drift cleanly.

## Tokenizer (MVP)

The MVP tokenizer is a hash bag of byte n-grams projected to a fixed
`[1, 64]` float32 vector. It is deterministic and zero-dep. It is **not**
a real linguistic tokenizer and you cannot pair it with off-the-shelf
HuggingFace models. M3.5.1 will introduce a plug-in mechanism for
custom tokenizers shipped alongside the model file.

For day-1 deployment, train a small classifier (logistic regression,
linear SVM) on top of the same 64-dim hash features and export to ONNX.
Score quality won't beat a real LM, but the wiring is real and the
signed-receipt chain works end to end.

## Failure policy

Every implementation must respect two invariants:

1. `evaluate` never panics, never propagates errors. A broken model
   contributes empty evidence; the host pipeline keeps running.
2. `model_digests` is stable for the lifetime of the engine.

These are enforced by trait contract and reinforced by the integration
tests in `armor-core`.

## License

BUSL-1.1 with Change License: Apache-2.0 baked into the licence
itself (auto-converts four years after each release is published).
See [ADR 0002](../../docs/adr/0002-open-source-license-and-scope.md).
