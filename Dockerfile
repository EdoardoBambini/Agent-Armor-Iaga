# Stage 1: Build
# Agent Armor 1.0 — workspace build. The runtime binary is `armor`
# (alias `agent-armor`) from `crates/armor-core`.
FROM rust:1.94-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the entire workspace and build in one shot. The dummy-stub
# dependency-cache trick that earlier versions of this Dockerfile used
# is fragile across multi-crate workspaces (the second build can fail
# to rebuild the binary). A single-shot build is slower but reliable.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build only the production binary we ship. `--locked` enforces that
# Cargo.lock matches what was committed.
RUN cargo build --release --bin armor --locked

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' armor

WORKDIR /app

COPY --from=builder /app/target/release/armor ./armor
COPY crates/armor-core/agent-armor.example.yaml ./agent-armor.yaml
COPY crates/armor-apl/examples /app/examples/apl
COPY crates/armor-core/examples/policies /app/examples/policies

RUN mkdir -p /app/data /home/armor/.armor/keys && \
    chown -R armor:armor /app/data /home/armor/.armor

USER armor

ENV PORT=4010
ENV DATABASE_URL=sqlite:///app/data/agent_armor.db?mode=rwc

EXPOSE 4010

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:4010/health || exit 1

ENTRYPOINT ["./armor"]
CMD ["serve"]
