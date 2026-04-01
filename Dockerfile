# Stage 1: Build
FROM rust:1.83-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for dependency caching
COPY community/Cargo.toml community/Cargo.lock ./

# Create dummy source files to build and cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo build --release && \
    rm -rf src

# Copy real source code
COPY community/src/ src/

# Build the actual binary
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' armor

WORKDIR /app

COPY --from=builder /app/target/release/agent-armor ./agent-armor
COPY community/agent-armor.example.yaml ./agent-armor.yaml

RUN mkdir -p /app/data && chown armor:armor /app/data

USER armor

ENV PORT=4010
ENV DATABASE_URL=sqlite:///app/data/agent_armor.db?mode=rwc
ENV AGENT_ARMOR_OPEN_MODE=false

EXPOSE 4010

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:4010/health || exit 1

ENTRYPOINT ["./agent-armor"]
CMD ["serve"]
