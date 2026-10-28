# Final Submission — The Agent That Earns Trust

## Status

**Status (2026-10-28).** The security fixes were merged by PR #1 (merge commit `e4ba7eb`, CI green) and the judge-facing UI by PR #2 (merge commit `0a3e623`, CI green). The public Render service https://agent-trust.onrender.com was suspended for security containment, then redeployed from `0a3e623` and verified the same day (`smoke:live` 45/45; real-click UI check 15/15; `identityMode web`, `replayStore redis`; auto-deploy off). The 90-second video is optional but recommended and is not recorded yet. Re-verify the public URL immediately before submitting (free-plan sleep, state resets on restart).

**Release baseline.** The original submission freeze (`c286ebd`) predates an independent audit. The post-audit repairs
were merged by PR #1 into `main` as merge commit `e4ba7eb` (tree-identical to the tested branch head `92ff923`; CI green on
`e4ba7eb`). The judge-facing single-stage UI is PR #2 (branch `feat/agent-trust-judge-ui-20261028`); check the PR for
its merge state. The final submitted SHA is whatever commit is tagged `builders-league-submission-v1`; the running build reports it
at `/api/health` (`RENDER_GIT_COMMIT`).

**Submission requirements** (verified by the project owner from the challenge page; not independently re-fetched): public
repository with a clean-clone working build; **a live demo URL is required**; a 90-second video is **optional but
recommended**; AI-tools, decisions and out-of-scope notes; a two-year thesis of at most 300 words.

## Form data (copy/paste)

```text
Project name:        The Agent That Earns Trust

One-line description: A verifiable trust layer for AI agents combining
                      cryptographic identity, signed credentials, scoped
                      delegation, revocation, replay protection,
                      contextual policy, and tamper-evident action history.

Repo URL:            https://github.com/abuzaro21/agent-trust

Live Demo URL:       https://agent-trust.onrender.com (REQUIRED — live, running 0a3e623, verified
                     2026-10-28; re-verify just before submitting).
                     Runs from one command:
                       git clone https://github.com/abuzaro21/agent-trust
                       cd agent-trust
                       docker compose -f docker-compose.demo.yml up --build
                       → http://localhost:3000
                     (the quickstart runs fixture identities; the live overlay
                      adds real did:web identities, see docs/deployment.md.
                      The public did:web identities below resolve RIGHT NOW)

Walkthrough URL:     OPTIONAL but recommended — not recorded yet (script ready: loom-script.md)

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
                      infrastructure — each judged on a typed expected outcome and
                      machine-checked invariants, 48 of 60 also on a specific reason code
                      (the executor really did not run; a spoof is never
                      attributed to the victim); POLICY-002 and STATUS-004
                      do not assert one.
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

## Verified metrics (each line names the code it was run on)

Windows 11, Node 24, pinned OPA 1.20.2, Redis 7 for integration. Historical counts from the original freeze are not reused.

```text
Security release (92ff923, merged to main as e4ba7eb — tree-identical):
  typecheck 0 errors · 483 tests in the default run (435 package + 48 apps/web) · Redis integration 5/5
  OPA native 13/13 · adversarial suite 60/60 (52 attacks + 8 failure demos) · production build · Docker build
  CI: green on the PR head and on the merge commit e4ba7eb
  (details: docs/deployment.md "Verification record")

Judge-UI branch feat/agent-trust-judge-ui-20261028 (code verified at 71b3ef6; later commits are documentation only):
  typecheck 0 errors · 520 tests in the default run (435 package + 85 apps/web; 510 pass + 10 skip without OPA)
  Redis integration 5/5 · OPA native 13/13 · adversarial suite 60/60 · production build
  browser automation 78/78 checks (`pnpm ui:check` against a local instance: layout at 4 widths, light/dark theme,
  decision stage in the first screen, comparison derived from the responses, failure cases, evidence disclosures,
  mobile scroll-into-view with focus kept, keyboard, states)
  CI: green on PR #2 (job "Typecheck + tests + Rego/Wasm + Redis integration"; see the PR checks for the exact head)
  Note: under heavy CPU contention the default parallel run has twice timed out one pre-existing 150-run property test
  (packages/status, 5 s default) that passes alone in ~2 s; it is unrelated to this branch (no package changed).

Public service (https://agent-trust.onrender.com):
  Was suspended for security containment on 2026-10-28 (it ran the pre-audit build 4c25b4b), then resumed and
  redeployed from 0a3e623 (Render deploy dep-dbgvq5egekts738vh0ug) the same day; the previous build was reachable for
  approximately 87 s during the cutover (first observed answering health polling at +24 s after the resume; the new deploy was live at +111 s; the exact cutover time was not recorded).
  Verified on the deployed build: /api/health build.sha 0a3e623, identityMode web; /api/demo/status replayStore redis;
  smoke:live 45/45; real-click UI check 15/15 (120 SAR allowed, 5,000 SAR denied, comparison, spoof, revoked, replay,
  audit chain valid, 60/60 report); a scan of 400 build-log and 150 runtime-log lines found zero secret-pattern matches and zero real errors in those samples. Auto-deploy remains off.
```

Independent review: a read-only audit by a second model family (Codex GPT-6.1 Sol) reviewed the implementation, an Opus 5.5 pass
challenged its findings, and Codex re-reviewed the repair commits and, separately, the UI redesign (9 verified defects fixed, then a
re-review whose remaining findings were also fixed). The single-stage redesign then got its own independent read-only review after the last UI change: 3 verified defects (authorization misreported for an audit veto, comparison could call different outcomes identical, two browser checks that could pass vacuously) were fixed with regression tests.

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
