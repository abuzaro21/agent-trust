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

## Attack Suite (executable tests, not prose)

Every row above becomes a scripted attack in `tests/attacks/` with a defined expected denial:

```text
tests/attacks/
├── spoofed-identity      → IDENTITY_PROOF_INVALID
├── forged-credential     → VC_SIGNATURE_INVALID
├── untrusted-issuer      → UNTRUSTED_ISSUER
├── replayed-request      → REPLAY_DETECTED
├── delegation-escalation → NON_ATTENUATED_DELEGATION
├── revoked-parent        → PARENT_DELEGATION_REVOKED
├── audience-confusion    → AUDIENCE_MISMATCH
└── post-revocation       → CREDENTIAL_REVOKED
```

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
