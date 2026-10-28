# Judge Checklist

Every challenge requirement mapped to a concrete, inspectable artifact.
Nothing vague; every row is clickable or runnable.

**Challenge requirements** (read directly from the signed-in challenge page https://build.doo.ooo/challenges/agent-earns-trust on 2026-10-28; see [submission-readiness.md](submission-readiness.md)): trust profiles with history, scoped authority and attestations · signed verifiable credentials · grant / revoke / scope trust · a trust-gated agent interaction · a concrete malicious or spoofed-agent failure case · identity → claims → verification → policy · a two-year thesis ≤ 300 words. Submission: public repository (a clean clone must run); **a live demo URL is required**; a 90-second video is **optional but recommended** (listed among the deliverables, marked optional in the checklist and form); AI tools, decisions and out-of-scope notes. Disqualifiers: a reputation score without mechanisms; no demo of a trust-gated decision.

## Challenge requirements

| Requirement | Artifact | Where |
|---|---|---|
| **Trust profile** (contextual evidence, no score) | `TrustProfileService` + the decision stage's grant strip (+ "Credential and identity details") and the Evidence section (DID, signed authority, attestations, history) | `packages/trust-profile/src/service.ts` · dashboard `/#demo`, `/#evidence` |
| **Action history** | Hash-chained Action Receipts + signed checkpoints; profile aggregates from the VERIFIED chain only | `packages/audit/src/` · dashboard audit panel · `GET /api/audit/acme-demo` |
| **Authority scope** (grant limited, attenuated) | `AgentDelegationCredential` with actions/resources/audience/amount/window/depth (`perDay` is schema-valid but not enforced); `Authority(child) ⊆ Authority(parent)` walker (tested directly; the gateway accepts a single delegation link) | `packages/delegation/src/` · grant strip in the decision stage |
| **Vouches / attestations** | `AgentAttestationCredential` through the full VC pipeline; issuer+type-scoped trust; evidence-only (a rejected self-vouch is visible on the dashboard) | `packages/trust-profile` · `packages/vc` |
| **Verifiable credentials** | W3C VC 2.0-style compact JWS, ES256/P-256, 11-stage verification incl. status binding | `packages/vc/src/` |
| **Grant / scope issuance** | Org issuer signs delegations; trusted-issuer registry gates whose claims count. The public page explains and exercises grant → scope → revoke (verification runs on every request; quarantine is one of the extra failure cases) but exposes **no** issue/revoke controls (shared state must stay valid for other visitors) | `packages/vc` `CredentialIssuer` + `InMemoryIssuerTrustStore` · dashboard `/#lifecycle` |
| **Revoke** | W3C Bitstring Status List (permanent revocation, reversible suspension) + emergency quarantine — current status kills authority | `packages/status/src/` · dashboard `/#failures` ("Revoked credential") and `/#lifecycle` (the "Revoke" step runs on an isolated credential) |
| **Accept / refuse a task** (trust-gated interaction; spoof failure case) | Trust Gateway: one authorized path; deterministic OPA Wasm ALLOW/DENY with machine reason codes; LLM never decides permissions. Real order: identity → replay claim → credentials & status → delegation chain → policy → decision receipt → execution (simulated) → outcome receipt | `packages/gateway/src/gateway.ts` · `policies/agent-trust/decision.rego` · dashboard `/#demo`, `/#failures` |
| **Live demo (HTTPS URL) — REQUIRED** | **https://agent-trust.onrender.com — live, running `f004ae8` (deploy `dep-dbh4jf8n74is73bjpeb0`), verified 2026-10-28** (`/api/health` build `f004ae8`, `identityMode web`, `replayStore redis`, `smoke:live` 45/45; author-run). Free plan: first request after idle can take about a minute; re-verify just before submitting. One-command local equivalent: `docker compose -f docker-compose.demo.yml up --build` → http://localhost:3000 | README Quickstart |
| **Public repository** | github.com/abuzaro21/agent-trust (MIT, CI on every push) | GitHub |
| **90-second walkthrough — OPTIONAL, recommended** | Narration is 167 tokens ≈ 67 s of speech (`loom-script.md`); not recorded yet (needs the public URL — not recorded against localhost pretending to be public); the challenge page states no take or editing rule for the video | `docs/submission/loom-script.md` |
| **Architecture snapshot** | One-screen diagram, this package | `docs/submission/architecture.md` |
| **Failure thinking / negative tests** | 60/60 scenario suite (52 attacks + 8 failure demos); each judged on a typed expected outcome and machine-checked invariants (a missing checker, verdict or invariant fails), 49 also on a specific reason code and 11 with a written reason for none; hardened by product-mutation testing — see `docs/security-assurance.md`; served at `/attacks`; CI gate `pnpm test:attacks` | `packages/attacks/` |
| **Two-year thesis** | 293 words (296 with the title); the ≤300-word limit is stated on the challenge page (checked 2026-10-28) | `docs/submission/two-year-thesis.md` |
| **AI tools notes** | Honest disclosure incl. seven caught AI mistakes | `docs/submission/ai-tools-and-decisions.md` |
| **Standards story** (bonus signal) | did:web identities (public: `did:web:abuzaro21.github.io:agents:{org,support,refund}`) · VC 2.0-style compact JWS · JOSE ES256 · RFC 8785 · Bitstring Status List · Rego/OPA Wasm. These are **profiles implemented from the specs; no independent conformance certification is claimed** | docs/credential-model.md · docs/architecture.md |

## Rubric dimensions → demonstrating artifacts

(No self-scores; each row names where a judge can verify the claim directly.)

| Dimension | Best evidence |
|---|---|
| **Conceptual clarity (25)** | README first screen (120-vs-5000 table + the single sentence) · canonical demo run in the live UI · `docs/trust-model.md` |
| **Technical depth (25)** | 662 tests in the default run (577 package + 85 apps/web; OPA on PATH needed for the native-parity cases) + 5 Redis integration tests · SSRF-pinned did:web transport · PoP→replay→VC→status→attenuation→Wasm→receipts pipeline · ADRs |
| **Demo quality (20)** | One decision stage: AcmeOrg grants SupportAgent ≤ 500 SAR (read from the backend), two request buttons, a server-authoritative verdict with Authorization and Execution (simulated) as separate facts, and a side-by-side comparison built from the two real responses; spoof / revoked / replay failure cards (three more behind a disclosure); pipeline, receipts, audit history, attestations and the 60/60 report behind disclosures; light default + dark theme; 17 screenshots from real clicks (desktop, tablet, mobile, both themes); responsive at 1920/1440/768/390 px with 78 automated browser checks; optional video script (once recorded on the public URL) |
| **Failure thinking (15)** | 60/60 scenario suite (typed outcome + machine-checked invariants each; mutation-tested) · fail-closed at every enforcement boundary (incl. startup config: Redis/did:web misconfig refuses boot; a policy-engine crash denies without a receipt) · documented bugs-caught table |
| **Future thesis (15)** | `two-year-thesis.md` (portable evidence, provenance-as-contract, agent refusal, standards over scores) + what-the-fabric-doesn't-do honesty |

## Evidence status (what was actually re-run)

| Item | Status |
|---|---|
| Security release (`92ff923` → `main` `e4ba7eb`): typecheck, 483 tests, 5 Redis, 13 OPA, 60/60 attacks, build, Docker build | PASS; CI green on the PR head and on the merge commit |
| Judge-UI branch (code at `71b3ef6`): typecheck, 520 tests (435 package + 85 apps/web), 5 Redis, 13 OPA, 60/60 attacks, build, 78/78 browser checks | PASS locally; CI green on PR #2 (historical; superseded by the next row) |
| Attack-suite assurance release (audited head `2f554ee` → `main` `f004ae8`): typecheck, 662 tests (577 package + 85 apps/web), 5 Redis, 13 OPA, Wasm digest, 60/60 scenarios, production build, 78/78 browser checks | Author-run PASS; GitHub CI green on the merge commit ([run 40750984910](https://github.com/abuzaro21/agent-trust/actions/runs/40750984910)); independent Codex re-ran typecheck, the 662 tests, 60/60, OPA, the Wasm digest and its named negative controls and returned APPROVE FOR PR. Redis, the production build and the browser check were not run in Codex's sandbox (CI ran Redis and the build). Mutation tally (32 mutants): author-reported only |
| Original malformed-input exploit | Reproduced on the pre-fix code; fixed and covered by regression tests |
| `smoke:live` 45/45 | PASS on 2026-10-28 against the deployed `f004ae8` (author-run); earlier that day also PASS on `0a3e623` and on the pre-audit build `4c25b4b` (both superseded) |
| Public `/attacks` page and claim wording (real browser) | PASS 15/15 on `f004ae8` (author-run): corrected headline, typed outcome badges, 60 rows PASS, stored-report verdicts, 49 / 11 reason-code split, no stale wording |
| Public HTTPS URL (REQUIRED) | **MET** on 2026-10-28 — `f004ae8` deployed and verified; re-verify immediately before submitting |
| 90-second walkthrough | OPTIONAL but recommended — not recorded; not a submission blocker |
| Challenge requirements and judging weights | READ DIRECTLY 2026-10-28 from https://build.doo.ooo/challenges/agent-earns-trust (signed-in view, including the submit-form fields); see submission-readiness.md. The deadline's timezone is not stated (UNVERIFIED) |
| Video take/edit rules | None stated on the challenge page |
| Screenshots | Regenerated from the current UI with real clicks (`pnpm shots:live`); they must be regenerated again if the UI changes |

## Submission status

```text
SUBMISSION STATUS (not submitted):
LIVE DEMO: https://agent-trust.onrender.com — f004ae8 deployed (Render deploy dep-dbh4jf8n74is73bjpeb0) and verified on 2026-10-28.

Remaining before submission (full list: submission-readiness.md):
  1. Re-verify the public URL immediately before submitting: /api/health build.sha, /api/demo/status
     (identityMode=web, replayStore=redis), DEMO_PUBLIC_URL=https://agent-trust.onrender.com corepack pnpm smoke:live -> 45/45.
     The free plan sleeps after ~15 min idle (about a minute to wake) and demo state resets on restart.
  2. Optional: record the 90-second walkthrough from the public URL (see loom-script.md and the pre-production plan).
  3. Fill the DOO form by hand (repo URL, live demo URL, optional video URL, notes) before the deadline.
     No release tag is required by the challenge page; the auto-deploy stays off.
```

Key values live only in `.local/` (gitignored); they are generated by
`pnpm demo:did:init` and are the SAME keys the public DID documents bind.
