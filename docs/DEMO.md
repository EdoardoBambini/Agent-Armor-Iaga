# Demo Walkthrough

## Goal

Show how Agent Armor governs agent actions through all 8 security layers.

## Local Run

```bash
cd community
cargo run
```

Open `http://localhost:4010` for the dashboard.

## What the Demo Shows

### Scenario 1 — Safe File Read

An agent performs a safe MCP file read. Low risk score, matches policy, passes all 8 layers → **ALLOW**.

### Scenario 2 — Shell Exec with Secret

The agent asks to run `git push` with a GitHub secret reference. Tool is allowed but capped at `review` in workspace policy → **REVIEW** (requires human approval).

### Scenario 3 — Destructive Command

The agent tries `rm -rf /var/lib/postgresql`. High-risk shell pattern detected at Layer 4, sandbox flags destructive impact at Layer 5 → **BLOCK** (risk score 95).

### Scenario 4 — Unauthorized Secret

A researcher agent requests a secret it does not own. Vault denies the secret reference, escalated for review → **REVIEW**.

## HTTP Mode

```bash
# List demo scenarios
curl http://localhost:4010/v1/demo/scenarios \
  -H "Authorization: Bearer <key>"

# Run all scenarios
curl -X POST http://localhost:4010/v1/demo/run-adapter \
  -H "Authorization: Bearer <key>"

# Inspect a custom payload
curl -X POST http://localhost:4010/v1/inspect \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "my-agent",
    "workspaceId": "ws-demo",
    "framework": "langchain",
    "protocol": "mcp",
    "action": {
      "type": "shell",
      "toolName": "terminal.exec",
      "payload": {"command": "ls -la"}
    }
  }'
```

## Dashboard Features

The embedded dashboard provides real-time visualization of all 8 security layers:

- Layer status indicators with live/demo mode detection
- Session graph with FSA state tracking
- Adaptive risk weight sliders
- Sandbox pending queue with approve/reject
- Firewall 3-stage catch rate metrics
- Policy formal verification results
- OpenTelemetry span viewer
- Audit trail with filtering
- SSE real-time event feed
