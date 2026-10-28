# Judge Checklist

Every challenge requirement mapped to a concrete, inspectable artifact.
Nothing vague; every row is clickable or runnable.

## Challenge requirements

| Requirement | Artifact | Where |
|---|---|---|
| **Trust profile** (contextual evidence, no score) | `TrustProfileService` + dashboard Trust Profile panel (live did:web DID, authority, attestations, history) | `packages/trust-profile/src/service.ts` · dashboard `/` left column |
| **Action history** | Hash-chained Action Receipts + signed checkpoints; profile aggregates from the VERIFIED chain only | `packages/audit/src/` · dashboard audit panel · `GET /api/audit/acme-demo` |
| **Authority scope** (grant limited, attenuated) | `AgentDelegationCredential` with actions/resources/audience/amount/window/depth (`perDay` is schema-valid but not enforced); `Authority(child) ⊆ Authority(parent)` walker (tested directly; the gateway accepts a single delegation link) | `packages/delegation/src/` · profile "Authority" box |
| **Vouches / attestations** | `AgentAttestationCredential` through the full VC pipeline; issuer+type-scoped trust; evidence-only (a rejected self-vouch is visible on the dashboard) | `packages/trust-profile` · `packages/vc` |
| **Verifiable credentials** | W3C VC 2.0-style compact JWS, ES256/P-256, 11-stage verification incl. status binding | `packages/vc/src/` |
| **Grant / scope issuance** | Org issuer signs delegations; trusted-issuer registry gates whose claims count | `packages/vc` `CredentialIssuer` + `InMemoryIssuerTrustStore` |
| **Revoke** | W3C Bitstring Status List (permanent revocation, reversible suspension) + emergency quarantine — current status kills authority | `packages/status/src/` · "Revoked Credential" preset |
| **Accept / refuse a task** | Trust Gateway: one authorized path; deterministic OPA Wasm ALLOW/DENY with machine reason codes; LLM never decides permissions | `packages/gateway/src/gateway.ts` · `policies/agent-trust/decision.rego` |
| **Live demo (HTTPS URL)** | **https://agent-trust.onrender.com exists but runs the pre-audit build 4c25b4b — redeploy + re-verify before submitting** (see below) (one-command local equivalent: `docker compose -f docker-compose.demo.yml up --build` → http://localhost:3000) | README Quickstart |
| **Public repository** | github.com/abuzaro21/agent-trust (MIT, CI on every push) | GitHub |
| **90-second walkthrough** | Narration is 167 tokens ≈ 67 s of speech (`loom-script.md`); recording pending (needs the public URL — not recorded against localhost pretending to be public); the brief's take/edit rules are UNVERIFIED | `docs/submission/loom-script.md` |
| **Architecture snapshot** | One-screen diagram, this package | `docs/submission/architecture.md` |
| **Failure thinking / negative tests** | 60/60 adversarial suite (52 attacks + 8 failure demos) judged on reason code AND side-effect invariants; served at `/attacks`; CI gate `pnpm test:attacks` | `packages/attacks/` |
| **Two-year thesis** | 293 words (296 with the title; ≤300 limit — the limit itself is from the project's own notes, UNVERIFIED against the live brief) | `docs/submission/two-year-thesis.md` |
| **AI tools notes** | Honest disclosure incl. seven caught AI mistakes | `docs/submission/ai-tools-and-decisions.md` |
| **Standards story** | did:web live identities on public HTTPS: `did:web:abuzaro21.github.io:agents:{org,support,refund}` (public documents + repo `abuzaro21/abuzaro21.github.io`) · VC 2.0-style JWS · JOSE ES256 · RFC 8785 · Bitstring Status List · Rego/OPA Wasm | docs/credential-model.md · docs/architecture.md |

## Rubric dimensions → demonstrating artifacts

(No self-scores; each row names where a judge can verify the claim directly.)

| Dimension | Best evidence |
|---|---|
| **Conceptual clarity (25)** | README first screen (120-vs-5000 table + the single sentence) · canonical demo run in the live UI · `docs/trust-model.md` |
| **Technical depth (25)** | 483 tests in the default run (435 package + 48 apps/web; OPA on PATH needed for all 483) + 5 Redis integration tests · SSRF-pinned did:web transport · PoP→replay→VC→status→attenuation→Wasm→receipts pipeline · ADRs |
| **Demo quality (20)** | Live dashboard: presets, pipeline view, receipts, profile, DID badges; 5 screenshots at 1440×900; Loom script (once recorded on public URL) |
| **Failure thinking (15)** | 60/60 attack suite with invariant checks · fail-closed at every enforcement boundary (incl. startup config: Redis/did:web misconfig refuses boot; a policy-engine crash denies without a receipt) · documented bugs-caught table |
| **Future thesis (15)** | `two-year-thesis.md` (portable evidence, provenance-as-contract, agent refusal, standards over scores) + what-the-fabric-doesn't-do honesty |

## Evidence status (what was actually re-run)

| Item | Status |
|---|---|
| Typecheck, 483 tests (incl. the 48 apps/web tests), 5 Redis, 13 OPA, 60/60 attacks, build | PASS on the release branch (see `final-submission.md`) |
| Original malformed-input exploit | Reproduced on the pre-fix code; fixed and covered by regression tests |
| `smoke:live` 45/45 | PASS against the current public service (pre-audit build 4c25b4b); NOT RUN on a deployment of the release commit |
| Public HTTPS URL on the release commit, 90-second walkthrough | BLOCKER — URL exists on the old build; walkthrough not recorded |
| Live challenge brief (fields, take rules, thesis limit) | UNVERIFIED — brief not accessible |

## Submission status

```text
SUBMISSION BLOCKER (only one):
REDEPLOY THE RELEASE COMMIT — https://agent-trust.onrender.com currently runs the pre-audit build 4c25b4b

Procedure (Render free plan, existing service `agent-trust`; see docs/deployment.md):
  1. Merge the release branch (with approval), disable the service's auto-deploy first.
  2. Tag the release commit; deploy that exact SHA (render deploys create <service> --commit <SHA> --wait).
  3. Verify: /api/health build.sha == release SHA; /api/demo/status identityMode=web, replayStore=redis;
     DEMO_PUBLIC_URL=https://agent-trust.onrender.com corepack pnpm smoke:live → require 45/45.
Then record the walkthrough per loom-script.md (allow ~1 min cold start on the free plan), pin screenshots to
the deployed commit, and create tag builders-league-submission-v1 on the final SHA.
```

Key values live only in `.local/` (gitignored); they are generated by
`pnpm demo:did:init` and are the SAME keys the public DID documents bind.
