# Contributing to Agent Armor

Thanks for your interest in contributing to Agent Armor! This project is building the zero-trust security runtime for autonomous AI agents.

## Getting Started

```bash
git clone https://github.com/EdoardoBambini/Agent-Armor-Iaga.git
cd Agent-Armor-Iaga/community
cargo build
cargo run
```

Open `http://localhost:4010` to see the dashboard.

## Development

```bash
cargo run                     # Start server (port 4010)
cargo test                    # Run test suite
cargo clippy                  # Lint
cargo fmt                     # Format code
```

## Project Structure

- `community/src/modules/` — 8 security layer implementations
- `community/src/pipeline/` — Core governance pipeline orchestration
- `community/src/server/` — Axum HTTP server (48 endpoints)
- `community/src/dashboard/` — Embedded HTML dashboard
- `community/src/auth/` — API key auth with Argon2
- `community/src/events/` — SSE + webhooks
- `enterprise/` — Enterprise-only features
- `sdks/` — Python and TypeScript client SDKs

## How to Contribute

### Reporting Issues

- Use GitHub Issues
- Include: what you expected, what happened, steps to reproduce
- For security issues, email iaga.start@gmail.com instead

### Pull Requests

1. Fork the repo
2. Create a branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Add tests if applicable
5. Run `cargo test && cargo clippy`
6. Open a PR with a clear description

### What We're Looking For

- **New detection rules** — Pattern matching for risky agent behaviors
- **Protocol parsers** — New agent framework adapters and protocol hardening
- **Policy templates** — Pre-built policy sets for common use cases
- **SDK improvements** — Python and TypeScript client SDK features
- **Documentation** — Tutorials, examples, translations
- **Bug fixes** — Always welcome

## Code Style

- Follow `rustfmt` defaults
- Use `thiserror` for error types
- Prefer `Arc<Mutex<>>` for shared state
- Keep modules focused and single-purpose
- Use `tracing` for logging, not `println!`

## License

By contributing, you agree that your contributions will be licensed under the same [Business Source License 1.1](LICENSE) as the project.
