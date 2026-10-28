# Judge Checklist

Every challenge requirement mapped to a concrete, inspectable artifact.
Nothing vague; every row is clickable or runnable.

**Challenge requirements as verified by the project owner** (taken from the challenge page; not independently re-fetched): trust profiles with history, scoped authority and attestations · signed verifiable credentials · grant / revoke / scope trust · a trust-gated agent interaction · a concrete malicious or spoofed-agent failure case · identity → claims → verification → policy · a two-year thesis ≤ 300 words. Submission: public repository with a clean-clone working build; **a live demo URL is required**; a 90-second video is **optional but recommended**; AI tools, decisions and out-of-scope notes. Disqualifiers: a reputation score without mechanisms; no demo of a trust-gated decision.

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
| **Live demo (HTTPS URL) — REQUIRED** | **https://agent-trust.onrender.com is suspended for security containment (it ran the pre-audit build 4c25b4b); the fix is merged to `main` (`e4ba7eb`, CI green) — redeploy + re-verify before submitting** (see below) (one-command local equivalent: `docker compose -f docker-compose.demo.yml up --build` → http://localhost:3000) | README Quickstart |
| **Public repository** | github.com/abuzaro21/agent-trust (MIT, CI on every push) | GitHub |
| **90-second walkthrough — OPTIONAL, recommended** | Narration is 167 tokens ≈ 67 s of speech (`loom-script.md`); not recorded yet (needs the public URL — not recorded against localhost pretending to be public); any take/edit rules for the video are UNVERIFIED | `docs/submission/loom-script.md` |
| **Architecture snapshot** | One-screen diagram, this package | `docs/submission/architecture.md` |
| **Failure thinking / negative tests** | 60/60 adversarial suite (52 attacks + 8 failure demos) judged on reason code AND side-effect invariants; served at `/attacks`; CI gate `pnpm test:attacks` | `packages/attacks/` |
| **Two-year thesis** | 293 words (296 with the title; ≤300 limit — the limit itself is from the project's own notes, UNVERIFIED against the live brief) | `docs/submission/two-year-thesis.md` |
| **AI tools notes** | Honest disclosure incl. seven caught AI mistakes | `docs/submission/ai-tools-and-decisions.md` |
| **Standards story** (bonus signal) | did:web identities (public: `did:web:abuzaro21.github.io:agents:{org,support,refund}`) · VC 2.0-style compact JWS · JOSE ES256 · RFC 8785 · Bitstring Status List · Rego/OPA Wasm. These are **profiles implemented from the specs; no independent conformance certification is claimed** | docs/credential-model.md · docs/architecture.md |

## Rubric dimensions → demonstrating artifacts

(No self-scores; each row names where a judge can verify the claim directly.)

| Dimension | Best evidence |
|---|---|
| **Conceptual clarity (25)** | README first screen (120-vs-5000 table + the single sentence) · canonical demo run in the live UI · `docs/trust-model.md` |
| **Technical depth (25)** | 519 tests in the default run (435 package + 84 apps/web; OPA on PATH needed for all 519) + 5 Redis integration tests · SSRF-pinned did:web transport · PoP→replay→VC→status→attenuation→Wasm→receipts pipeline · ADRs |
| **Demo quality (20)** | One decision stage: AcmeOrg grants SupportAgent ≤ 500 SAR (read from the backend), two request buttons, a server-authoritative verdict with Authorization and Execution (simulated) as separate facts, and a side-by-side comparison built from the two real responses; spoof / revoked / replay failure cards (three more behind a disclosure); pipeline, receipts, audit history, attestations and the 60/60 report behind disclosures; light default + dark theme; 17 screenshots from real clicks (desktop, tablet, mobile, both themes); responsive at 1920/1440/768/390 px with 78 automated browser checks; optional video script (once recorded on the public URL) |
| **Failure thinking (15)** | 60/60 attack suite with invariant checks · fail-closed at every enforcement boundary (incl. startup config: Redis/did:web misconfig refuses boot; a policy-engine crash denies without a receipt) · documented bugs-caught table |
| **Future thesis (15)** | `two-year-thesis.md` (portable evidence, provenance-as-contract, agent refusal, standards over scores) + what-the-fabric-doesn't-do honesty |

## Evidence status (what was actually re-run)

| Item | Status |
|---|---|
| Security release (`92ff923` → `main` `e4ba7eb`): typecheck, 483 tests, 5 Redis, 13 OPA, 60/60 attacks, build, Docker build | PASS; CI green on the PR head and on the merge commit |
| Judge-UI branch (code at `c7af0dd`): typecheck, 519 tests (435 package + 84 apps/web), 5 Redis, 13 OPA, 60/60 attacks, build, 78/78 browser checks | PASS locally; CI not yet run (branch not pushed, not merged) |
| Original malformed-input exploit | Reproduced on the pre-fix code; fixed and covered by regression tests |
| `smoke:live` 45/45 | PASS on 2026-10-28 against the OLD public build (4c25b4b); NOT RUN on a deployment of the merged code |
| Public HTTPS URL (REQUIRED) | **BLOCKER** — the service is suspended; redeploy the merged code and re-verify |
| 90-second walkthrough | OPTIONAL but recommended — not recorded; not a submission blocker |
| Challenge requirements and judging weights | Provided by the project owner (verified by them on the challenge page); not independently re-fetched by the agents |
| Video take/edit rules, exact form fields | UNVERIFIED |
| Screenshots | Regenerated from the current UI with real clicks (`pnpm shots:live`); they must be regenerated again if the UI changes |

## Submission status

```text
SUBMISSION BLOCKER (only one):
REDEPLOY THE MERGED CODE — https://agent-trust.onrender.com is suspended (it ran the pre-audit build 4c25b4b); main = e4ba7eb

Procedure (Render free plan, existing service `agent-trust`; see docs/deployment.md):
  1. (done) Fix merged to main as e4ba7eb; the service's auto-deploy is OFF and the service is suspended.
  2. Tag the release commit; deploy that exact SHA (render deploys create <service> --commit <SHA> --wait).
  3. Verify: /api/health build.sha == release SHA; /api/demo/status identityMode=web, replayStore=redis;
     DEMO_PUBLIC_URL=https://agent-trust.onrender.com corepack pnpm smoke:live → require 45/45.
Then record the walkthrough per loom-script.md (allow ~1 min cold start on the free plan), pin screenshots to
the deployed commit, and create tag builders-league-submission-v1 on the final SHA.
```

Key values live only in `.local/` (gitignored); they are generated by
`pnpm demo:did:init` and are the SAME keys the public DID documents bind.
