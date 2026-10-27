# Final Submission — The Agent That Earns Trust

## Status

**BLOCKED ONLY BY: `SUBMISSION BLOCKER: PUBLIC_DASHBOARD_URL`**
(plus the walkthrough recording, which must be captured against the public
deployment). No public URL is invented.

**Release baseline.** The original submission freeze (`c286ebd`) predates an
independent audit. Post-audit repairs live on branch
`fix/agent-trust-doo-p0-20261028` (code baseline `043257b`; documentation
commits follow it). The final submitted SHA is whatever commit is tagged
`builders-league-submission-v1` — record it with `git rev-parse --short HEAD`
and pass it as `DEMO_BUILD_SHA`.

When a hosting login (e.g. Fly.io) is available, the remaining act is the
procedure in [docs/deployment.md](../deployment.md). The earlier live-identity
rehearsal (`smoke:live` 45/45, Step 16) is **not** evidence for the current
build: re-run it against the public URL.

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
                      Every dependency fails CLOSED (a policy-engine crash
                      denies without a receipt). An independent post-freeze
                      audit found and fixed audit-chain poisoning, a dropped
                      authority window and a revocation race; remaining
                      limits are listed below. CI gate: pnpm test:attacks.

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

## Verified metrics (post-audit release branch)

Executed on a clean worktree of the release branch (code baseline `043257b`),
Windows 11, Node 24, pinned OPA 1.20.2, Redis 7 for integration. Counts below
are from those runs; historical counts from the original freeze are not reused.

```text
TypeScript typecheck       0 errors
unit/property tests        480 passed (needs OPA on PATH; 415 pass + 10 skip without it)
frontend/API tests         45 passed
redis integration          5/5 (Redis 7)
OPA native tests           13/13
adversarial suite          60/60 (52 attacks + 8 failure demos)
production web build       passes
CI                         green on the original freeze; re-run on the release branch is pending
live-mode smoke            NOT re-run (needs private keys + public URL) — earlier 45/45 is historical
docker image / compose     see docs/deployment.md "Verification record"
```

Independent review: a read-only audit by a second model family (Codex
GPT-6.1 Sol) reviewed the implementation, an Opus 5.5 pass challenged its
findings, and the same reviewer re-reviewed the five repair commits (no
production defects found; one test weakness fixed).

## Files in this package

- `final-submission.md` (this summary)
- `loom-script.md` (90-second narration, 167 tokens ≈ 67 s of speech)
- `two-year-thesis.md`
- `architecture.md` (one-screen snapshot)
- `ai-tools-and-decisions.md`
- `out-of-scope.md`
- `judge-checklist.md` (requirements + rubric mapping)

## Honest limitations (define P0 scope — not failures)

Single app replica · process-local demo audit/profile/status state (resets on
restart; Redis externalizes only replay) · synthetic `DemoRefundExecutor` (a
simulation — no money moves) · frozen demo clock (2026-09-15T12:00:00Z) ·
local signers rather than Cloud KMS · did:web inherits DNS+HTTPS operator
trust · no OAuth/A2A/MCP integration · the gateway accepts a single delegation
link (multi-hop is tested in `packages/delegation`, not through the gateway) ·
`limits.perDay` is not enforced · no human-in-the-loop approval (`REQUIRE_APPROVAL`
is never produced) · a policy-engine crash denies without writing a receipt ·
status-list freshness/rollback and DID key-purpose checks are not enforced ·
the public API signs demo requests server-side (not caller authentication).
Details: [docs/deployment.md](../deployment.md), [docs/threat-model.md](../threat-model.md#known-limitations-verified-during-release-audit).
