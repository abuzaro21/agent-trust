# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security problems.**

Please report vulnerabilities privately to **Ibrahemzaro9@gmail.com**, including reproduction steps and affected components. You will receive an acknowledgment within 72 hours. Coordinated disclosure with credit is fine; we ask for up to 90 days before public disclosure.

## Trust Boundaries (summary)

Untrusted: agent runtimes (including their LLMs), the network, DID resolution inputs, presented credentials, LLM-generated tool calls, remote attestations, connector inputs.

Security-critical: the signer/KMS boundary, the signed policy supply chain (`policies/` → compiled Wasm → SHA-256 hash recorded per decision), the trusted-issuer registry, and the audit/checkpoint signer.

## Design Rules That Must Never Be Relaxed

1. **The LLM never decides its own permissions.** Every action passes the deterministic enforcement point.
2. **Fail closed.** Missing/invalid policy bundle, verifier errors, unreachable replay store on writes, audit-log failure on high-impact actions → deny. No permissive fallback.
3. **Private key material never leaves the `Signer` boundary** — never in Postgres, never in environment variables in production.
4. **Policies are code:** reviewed, tested, hashed; every decision cites the exact `policyBundleHash` that produced it.
5. **Attenuation is structural:** `Authority(child) ⊆ Authority(parent)` is enforced by the verifier, not by issuer goodwill.
6. **Audit is tamper-evident:** hash-chained receipts with signed checkpoints; deletion or edits break verification.

See [docs/threat-model.md](docs/threat-model.md) for the full threat catalogue and failure-behavior matrix.
