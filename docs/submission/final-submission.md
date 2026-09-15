# Final Submission — The Agent That Earns Trust

## Status

**BLOCKED ONLY BY: `SUBMISSION BLOCKER: PUBLIC_DASHBOARD_URL`**
(plus the Loom recording, which must be captured by the author against the
public deployment). No public URL is invented. Everything else in this
package is complete, verified, and frozen at commit `c286ebd`.

When a hosting login (e.g. Fly.io) is available, the remaining act is the
three committed commands in [docs/deployment.md](../deployment.md) —
already rehearsed end-to-end in live identity mode (smoke:live 45/45).

## Form data (copy/paste)

```text
Project name:        The Agent That Earns Trust

One-line description: A verifiable trust layer for AI agents combining
                      cryptographic identity, signed credentials, scoped
                      delegation, revocation, replay protection,
                      contextual policy, and tamper-evident action history.

Repo URL:            https://github.com/abuzaro21/agent-trust

Live Demo URL:       PENDING HOSTING ACCOUNT — see SUBMISSION BLOCKER above.
                     Runs from one command:
                       git clone https://github.com/abuzaro21/agent-trust
                       cd agent-trust
                       docker compose -f docker-compose.demo.yml up --build
                       → http://localhost:3000
                     (identical configuration verified public-identity mode;
                      public did:web identities below are live RIGHT NOW)

Walkthrough URL:     PENDING RECORDING (script ready: loom-script.md)

Architecture summary: Identity → Claims → Verification → Authority →
                      Policy → Provenance. Every request from an agent
                      passes proof-of-possession, DID resolution, VC
                      verification, issuer trust, status/revocation,
                      delegation attenuation, atomic replay claim, a
                      VerifiedFacts-only OPA Wasm policy, and hash-chained
                      action receipts — before a simulated executor can run.
                      The LLM never decides its own permissions.
                      Diagram: docs/submission/architecture.md

Failure-thinking summary: 60/60 deterministic adversarial scenarios
                      (52 attacks + 8 failure demos) across identity,
                      credentials, authority, status, replay, policy,
                      audit, attestation, did:web transport, and
                      infrastructure — each judged on the denial reason AND
                      side-effect invariants (the executor really did not
                      run; a spoof is never attributed to the victim).
                      Every dependency fails CLOSED. CI gate: pnpm test:attacks.

Standards used:       W3C DID Core, did:web (HTTPS-only, SSRF-pinned
                      resolution), W3C VC Data Model 2.0-style credentials
                      (compact JWS, ES256/P-256), JOSE, RFC 8785 canonical
                      JSON, W3C Bitstring Status List, OPA Rego compiled to
                      embedded Wasm (hash-pinned artifact).

Two-year thesis:      docs/submission/two-year-thesis.md (≤300 words)
```

## Core thesis

> Trust is not a score. It is verifiable, scoped, revocable authority.

The canonical demo result — same legitimate agent, same identity, same
valid credential:

```text
refund 120 SAR  → ALLOW + SUCCEEDED   (within delegated scope)
refund 5000 SAR → DENY  AUTHORITY_LIMIT_EXCEEDED   (action left the scope)
```

and the sentence that carries it:

> **The agent can be trusted — but not for this action.**

## Live public identities (resolving now, over public HTTPS)

```text
did:web:abuzaro21.github.io:agents:org
https://abuzaro21.github.io/agents/org/did.json

did:web:abuzaro21.github.io:agents:support
https://abuzaro21.github.io/agents/support/did.json

did:web:abuzaro21.github.io:agents:refund
https://abuzaro21.github.io/agents/refund/did.json
```

Each identity has its own P-256 key; private keys live only as deployment
secrets (never committed, never in the image, never in the browser).

## Verified metrics (final commit c286ebd)

```text
core tests            425 passing
frontend tests        27 passing
redis integration     5/5
adversarial suite     60/60
OPA native tests      13/13
live-mode smoke       45/45
CI                    18/18 green
TypeScript            0 errors
clean clone (HEAD)    install/typecheck/test/build/docker all green
secret scan (git)     0 exposed secrets
```

## Files in this package

- `final-submission.md` (this summary)
- `loom-script.md` (90-second narration, timed)
- `two-year-thesis.md`
- `architecture.md` (one-screen snapshot)
- `ai-tools-and-decisions.md`
- `out-of-scope.md`
- `judge-checklist.md` (requirements + rubric mapping)

## Honest limitations (define P0 scope — not failures)

Single app replica · process-local demo audit/profile state (resets on
restart; Redis externalizes only replay) · synthetic `DemoRefundExecutor` ·
local signers rather than Cloud KMS · did:web inherits DNS+HTTPS operator
trust · no OAuth/A2A/MCP integration. Details: [docs/deployment.md](../deployment.md).
