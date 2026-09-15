# Threat Model

## Untrusted Boundaries

```text
Agent runtime (including the LLM)
Internet / counterparty systems
DID resolution inputs
Presented credentials
LLM-generated tool calls
Remote attestations
Enterprise connector inputs
```

## Security-Critical Components

The KMS/signer, the signed policy supply chain, the trusted-issuer registry, and the audit/checkpoint signer. Compromise of any of these is a fabric-level incident, not a per-agent one.

## Threat Catalogue

| Threat | Attack | Detection / Defense | Result |
|---|---|---|---|
| **Identity spoofing** | EvilAgent copies a trusted agent's DID and profile | Challenge/proof-of-possession must sign with the key in the DID document | `DENY: IDENTITY_PROOF_INVALID` |
| **Credential forgery** | Tamper `maxAmount: 500` → `50000` | JWS signature verification | `DENY: VC_SIGNATURE_INVALID` |
| **Fake issuer** | Attacker creates a DID and self-issues a cryptatically valid "trusted" credential | Trusted Issuer Registry + credential-type authorization | `DENY: UNTRUSTED_ISSUER` |
| **Replay** | Re-send a captured valid request | `jti` + nonce + timestamp + task digest + atomic replay cache + audience binding | `DENY: REPLAY_DETECTED` |
| **Stolen access token** | Bearer-token theft | DPoP-style sender binding + short lifetimes — the token alone is insufficient (RFC 9449 semantics) | Attack fails without the key |
| **Compromised agent** | Attacker holds the *real* private key | Least privilege, short expiry, audience binding, anomaly signals, quarantine, VC revocation, key rotation | Blast radius limited — no crypto magic claims detection |
| **Delegation escalation** | Child agent requests authority wider than its parent's | Recursive attenuation verification | `DENY: NON_ATTENUATED_DELEGATION` |
| **Revoked parent** | Child credential still temporally valid after parent revocation | Full chain status verification | `DENY: PARENT_DELEGATION_REVOKED` |
| **Revocation race** | Use a VC immediately after revocation, before refresh | Short cache TTL, event invalidation, fail-closed on high risk | Bounded by cache freshness |
| **Policy tampering** | Modify Rego to allow everything | Git-reviewed policies + signed/versioned bundle + hash in every decision record | Detected/prevented forensically |
| **Audit deletion** | Delete a deny receipt or transaction from the DB | Chained event hashes + signed checkpoints | Chain verification fails |
| **Malicious vouch / Sybil** | Dozens of fake agents vouch for each other | Issuer trust + domain policy; endorsements without issuer authority don't count | Untrusted vouches have no effect |
| **Prompt injection** | Tool content asks to bypass restrictions | The LLM is outside the security boundary; the PEP re-verifies the actual structured action | No bypass |
| **Wrong audience** | A valid credential/request replayed against another service | `aud` / resource binding | `DENY: AUDIENCE_MISMATCH` |
| **DID resolution abuse** | Malicious DID triggers unsafe fetches or a hanging resolver | Supported-method allowlist, timeouts, caching, network egress policy | Resolution failure (fail closed) |
| **Supply chain** | Modified library, policy, or image | Pinned dependencies + SBOM + signed images + CI security gates | Deployment blocked |

## The Hardest Case: Compromised Agent

If an attacker steals the agent's genuine private key while its credential is still unrevoked, signature verification *correctly* reports the request as signed by the right key. **We do not claim cryptography detects this.** What we do is make the compromise expensive and stoppable:

```text
scope           = refund:create only
amount          ≤ 500 SAR
rate            ≤ 20 operations/day
audience        = PaymentAgent only
credential TTL  = 24h
runtime proof   = very short-lived
high-risk       = human-in-the-loop
kill switch     = emergency quarantine
```

Honest failure engineering beats an unrealistic detection claim — in front of judges and in production.

## Adversarial Attack Matrix (executable, deterministic)

Every scenario below is a registered case in `packages/attacks` and runs end-to-end via `pnpm demo:attacks` (CI: `pnpm test:attacks`). A scenario PASSES only when **both** the expected denial reason **and** the side-effect invariants hold: executor call counts, victim receipt attribution, policy/attenuation stage gates, replay-store state, cache contents, and victim trust-profile immutability. "Attack blocked" is never inferred from a reason code alone.

Positive control (every category): a legitimate 120 SAR refund through the identical pipeline → `ALLOW` + `SUCCEEDED`, so the matrix proves the fabric denies *attackers*, not agents.

**Recommended 90-second failure-demo sequence** (video shortlist):

| # | Scenario | Why it is the story |
|---|---|---|
| 1 | AUTHORITY-001 | Contextual authority: same valid identity — 120 SAR ALLOW, 5000 SAR DENY |
| 2 | IDENTITY-001 | Spoofed DID: valid-looking request, wrong key, zero side effects |
| 3 | STATUS-001 | Revocation: same legitimate agent, credential gone, policy never sees it |
| 4 | REPLAY-001 | Replay: identical signed bytes, second attempt denied, one logical refund |

Full matrix (regenerate: `pnpm demo:attacks`, see `artifacts/attacks/attack-report.md`):

| Attack | Trust layer | Control | Expected reason | Side effect? | Test ID | Demo? |
|---|---|---|---|---|---|---|
| Spoofed agent: EvilAgent claims SupportAgent DID, signs with its own key | IDENTITY | PoP + kid ownership + body digest | IDENTITY_PROOF_INVALID | NO | IDENTITY-001 | DEMO 2 |
| Wrong kid: valid proof references a verification method owned by another DID | IDENTITY | PoP + kid ownership + body digest | IDENTITY_PROOF_INVALID | NO | IDENTITY-002 |  |
| Signed-body tamper: 120 SAR signed, 5000 SAR on the wire | IDENTITY | PoP + kid ownership + body digest | IDENTITY_PROOF_INVALID | NO | IDENTITY-003 |  |
| Wrong audience: a correctly-signed proof aimed at a different service | IDENTITY | PoP + kid ownership + body digest | AUDIENCE_MISMATCH | NO | IDENTITY-004 |  |
| Tampered VC: payload edited after signing | CREDENTIAL | VC verification pipeline (11 stages) | VC_SIGNATURE_INVALID | NO | CREDENTIAL-001 |  |
| Wrong issuer key: VC signed by a key the issuer DID does not own | CREDENTIAL | VC verification pipeline (11 stages) | VC_ISSUER_KEY_MISMATCH | NO | CREDENTIAL-002 |  |
| Valid signature, untrusted issuer (crypto-valid ≠ trusted) | CREDENTIAL | VC verification pipeline (11 stages) | UNTRUSTED_ISSUER | NO | CREDENTIAL-003 |  |
| Expired credential | CREDENTIAL | VC verification pipeline (11 stages) | VC_EXPIRED | NO | CREDENTIAL-004 |  |
| Not-yet-valid credential | CREDENTIAL | VC verification pipeline (11 stages) | VC_NOT_YET_VALID | NO | CREDENTIAL-005 |  |
| Subject mismatch: credential issued for another agent | CREDENTIAL | VC verification pipeline (11 stages) | WRONG_SUBJECT | NO | CREDENTIAL-006 |  |
| Amount escalation: 5000 SAR against a 500 SAR delegation | AUTHORITY | OPA Wasm delegated-scope policy | AUTHORITY_LIMIT_EXCEEDED | NO | AUTHORITY-001 | DEMO 1 |
| Action escalation: request refund:create with an order:read-only delegation | AUTHORITY | OPA Wasm delegated-scope policy | ACTION_NOT_IN_SCOPE | NO | AUTHORITY-002 |  |
| Resource escalation: request outside the delegated resource pattern | AUTHORITY | OPA Wasm delegated-scope policy | RESOURCE_NOT_IN_SCOPE | NO | AUTHORITY-003 |  |
| Audience escalation: delegation bound to RefundAgent, used against another service | AUTHORITY | OPA Wasm delegated-scope policy | AUDIENCE_MISMATCH | NO | AUTHORITY-004 |  |
| Child delegation broadens parent authority (attenuation walker) | AUTHORITY | OPA Wasm delegated-scope policy | DELEGATION_ACTION_ESCALATION | NO | AUTHORITY-005 |  |
| Delegation depth escalation beyond remaining budget (attenuation walker) | AUTHORITY | OPA Wasm delegated-scope policy | DELEGATION_DEPTH_EXCEEDED | NO | AUTHORITY-006 |  |
| Revoked credential — same legitimate agent and key | STATUS | Bitstring status lists / quarantine | CREDENTIAL_REVOKED | NO | STATUS-001 | DEMO 3 |
| Suspended credential (reversible mechanism) | STATUS | Bitstring status lists / quarantine | CREDENTIAL_SUSPENDED | NO | STATUS-002 |  |
| Quarantined agent — everything else valid (per-identity kill switch) | STATUS | Bitstring status lists / quarantine | AGENT_QUARANTINED | NO | STATUS-003 |  |
| Tampered status list (corrupted bitstring in the status store) | STATUS | Bitstring status lists / quarantine | CREDENTIAL_STATUS_UNAVAILABLE | NO | STATUS-004 |  |
| Foreign issuer status list (controller ≠ credential issuer) | STATUS | Bitstring status lists / quarantine | CREDENTIAL_STATUS_UNAVAILABLE | NO | STATUS-005 |  |
| Declared status mechanism, checker unavailable | STATUS | Bitstring status lists / quarantine | CREDENTIAL_STATUS_UNAVAILABLE | NO | STATUS-006 |  |
| Exact replay: identical signed bytes submitted twice | REPLAY | atomic CLAIM-ONCE store | REPLAY_DETECTED | NO | REPLAY-001 | DEMO 4 |
| Concurrent replay race: 100 identical valid requests at once | REPLAY | atomic CLAIM-ONCE store | fail-closed / invariant | NO | REPLAY-002 |  |
| Replay store unavailable — protected write fails closed | REPLAY | atomic CLAIM-ONCE store | REPLAY_PROTECTION_UNAVAILABLE | defined | REPLAY-003 |  |
| Replay-poisoning: attacker burns a future jti; legitimate proof must still work | REPLAY | atomic CLAIM-ONCE store | fail-closed / invariant | NO | REPLAY-004 |  |
| Corrupted policy Wasm — refused at load, fail closed | POLICY | pinned Wasm artifact + manifest + schema | fail-closed / invariant | NO | POLICY-001 |  |
| Manifest hash mismatch — artifact integrity gate | POLICY | pinned Wasm artifact + manifest + schema | POLICY_BUNDLE_INVALID | NO | POLICY-002 |  |
| Policy engine outage mid-pipeline — fail closed, executor untouched | INFRASTRUCTURE | fail-closed composition | POLICY_EVALUATION_ERROR | defined | POLICY-003 |  |
| Reputation-score injection: trustScore in the policy input is schema-rejected | POLICY | pinned Wasm artifact + manifest + schema | fail-closed / invariant | NO | POLICY-004 |  |
| Receipt mutation: amount edited in a stored receipt | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-001 |  |
| Decision mutation: ALLOW flipped to DENY in a stored receipt | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-002 |  |
| Receipt deletion (middle of the chain) | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-003 |  |
| Receipt reorder | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-004 |  |
| Forged receipt inserted into the chain | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-005 |  |
| Cross-stream substitution: receipts from another stream spliced in | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-006 |  |
| Full-chain rewrite: old receipt modified, all later hashes recomputed | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-007 |  |
| Truncation: tail receipts deleted after the checkpoint anchored them | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-008 |  |
| Forged checkpoint signed by the wrong key | AUDIT | hash chain + signed checkpoint | fail-closed / invariant | NO | AUDIT-009 |  |
| Fake vouch from an untrusted issuer (signature may be valid) | ATTESTATION | full pipeline + issuer/type trust | fail-closed / invariant | NO | ATTEST-001 |  |
| 100 Sybil vouches — count is not trust | ATTESTATION | full pipeline + issuer/type trust | fail-closed / invariant | NO | ATTEST-002 |  |
| Trusted attestations but NO delegation credential — gateway must still deny | ATTESTATION | full pipeline + issuer/type trust | REQUEST_MALFORMED | NO | ATTEST-003 |  |
| Revoked attestation disappears from trusted evidence | ATTESTATION | full pipeline + issuer/type trust | fail-closed / invariant | NO | ATTEST-004 |  |
| Attestation for the wrong subject cannot attach to the victim | ATTESTATION | full pipeline + issuer/type trust | fail-closed / invariant | NO | ATTEST-005 |  |
| document.id mismatch (server serves a different identity) | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-001 |  |
| Private IP target (DNS → RFC1918) — denied before connect | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-002 |  |
| Loopback target (DNS → 127.0.0.1) | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-003 |  |
| Cloud metadata / link-local target (DNS → 169.254.169.254) | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-004 |  |
| DNS rebinding: validated hostname, connection address turns private | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-005 |  |
| Redirect to an internal target | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-006 |  |
| Oversized document response | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-007 |  |
| Private key material in the served document (JWK with d) | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-008 |  |
| Foreign kid: verification method owned by another DID | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-009 |  |
| Cache poisoning: invalid document served first, valid second | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | NO | DIDWEB-010 |  |
| Emergency key rotation with max-age=0 (post-compromise publish) | DID_WEB | strict parser + SSRF transport + cache | fail-closed / invariant | defined | DIDWEB-011 |  |
| Audit store unavailable after policy ALLOW — no side effect without a durable decision | INFRASTRUCTURE | fail-closed composition | AUDIT_LOG_UNAVAILABLE | defined | INFRA-001 |  |
| Executor fails after a legitimate ALLOW — honest FAILED outcome receipt | INFRASTRUCTURE | fail-closed composition | fail-closed / invariant | defined | INFRA-002 |  |
| Execution succeeds but outcome receipt cannot be persisted — EXECUTION_UNCERTAIN, never blind retry | INFRASTRUCTURE | fail-closed composition | AUDIT_OUTCOME_UNRECORDED | defined | INFRA-003 |  |
| OPA engine crash inside evaluate — fail closed with a denial receipt | INFRASTRUCTURE | fail-closed composition | POLICY_EVALUATION_ERROR | defined | INFRA-004 |  |
| Redis (replay store) outage on a protected write — fail closed before policy | INFRASTRUCTURE | fail-closed composition | REPLAY_PROTECTION_UNAVAILABLE | defined | INFRA-005 |  |

### No-score invariant

Every scenario whose surface could carry an aggregate (trust profiles, policy input, audit receipts) additionally asserts the structural no-score property: `trustScore`/`rating`/`stars` fields are schema-inexpressible (POLICY-004), and 100 untrusted vouches produce zero trusted evidence and zero authority change (ATTEST-002).

### Deeper evidence (in suite, not necessarily in the video)

Audit full-chain rewrite vs. signed checkpoint (AUDIT-007), did:web SSRF/rebinding/redirect/cache-poisoning (DIDWEB-002…010), policy artifact integrity (POLICY-001/002), and the honest distributed-failure window (INFRA-003 `EXECUTION_UNCERTAIN`) are shown in the machine-readable report and terminal output.

## Failure Behavior Matrix

Production-grade does not mean "every dependency always works." It means the failure mode is defined **before** the failure:

| Failure | Behavior |
|---|---|
| Policy Wasm missing / invalid / init failure | **Fail closed** — no permissive fallback |
| Signature verifier errors | **Fail closed** |
| DID resolution unavailable, no valid cache | **Fail closed** |
| Revocation endpoint down, high-risk action | **Fail closed** |
| Revocation endpoint down, low-risk, cache within freshness policy | Policy decides |
| Redis replay store unavailable | Write actions: **fail closed** (`REPLAY_PROTECTION_UNAVAILABLE`) |
| Audit logging unavailable | Write/high-impact: **fail closed** or durable local queue per mode |
| Reputation history unavailable | Not a crypto DENY — policy decides whether reputation is required |
| Explanation renderer fails | The security decision stands; machine reason codes returned |

**Fixed rule for the replay dependency:** any write request that needs the replay store and cannot reach it returns `REPLAY_PROTECTION_UNAVAILABLE`. Redis being down never becomes implicit permission. Read-only operations may follow a different policy only if explicitly designed for it.

## Provenance Integrity Tests

```text
unchanged chain                       → verify OK
edit an old receipt                   → verification fails
delete an intermediate receipt        → verification fails
change a policy hash                  → verification fails
bad checkpoint signature              → verification fails
```

Chain verification is exposed via `GET /v1/audit/verify` for auditors.
