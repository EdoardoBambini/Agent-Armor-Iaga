# Security

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please email **info@iaga.tech** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (optional)

We will acknowledge receipt within **48 hours** and provide an initial assessment within **5 business days**.

## In Scope

- Authentication or authorization bypass
- Injection patterns not caught by the firewall
- Data leakage through API responses or logs
- Cryptographic weaknesses in NHI identity or API key hashing
- MCP proxy bypasses allowing ungoverned tool execution

## Out of Scope

- Denial of service against the server itself
- Social engineering
- Vulnerabilities in upstream dependencies (report to respective maintainers)
- Issues requiring physical access to the host

## Disclosure

We follow responsible disclosure. Once a fix is available we will:

1. Release a patched version
2. Publish a GitHub security advisory
3. Credit the reporter (unless they prefer anonymity)
