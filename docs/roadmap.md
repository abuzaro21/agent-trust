# Roadmap

**Window: 13 September → 15 November 2026** (internal code freeze a few days before the deadline).

The classic failure mode for this project would be attempting a DID platform + a full OAuth server + SPIRE + blockchain + reputation ML + A2A + MCP all production-complete at once. The correct MVP is **smaller, with real security properties**.

## Mandatory Scope (P0 — not negotiable)

| Capability | In MVP |
|---|---:|
| Cryptographic agent identity (DID + PoP) | ✅ |
| DID resolution | ✅ |
| Real VC signing/verification (JWS/ES256) | ✅ |
| Membership / Delegation / Attestation VCs | ✅ |
| Scope, resource, amount, expiry limits | ✅ |
| Delegation attenuation (incl. property tests) | ✅ |
| Credential revocation (Bitstring Status List) | ✅ |
| Proof-of-possession on every request | ✅ |
| Replay protection (atomic, fail-closed) | ✅ |
| Trusted issuer registry | ✅ |
| Rego → embedded OPA Wasm | ✅ |
| Deterministic ALLOW/DENY explanations | ✅ |
| Tamper-evident action history | ✅ |
| Two real demo agents | ✅ |
| Attack suite | ✅ |
| Public live demo + clean clone/start | ✅ |
| Architecture docs + 90-second video | ✅ |

## Explicitly Deferred

```text
did:webvh as a P0 dependency      Full SPIRE deployment
Full RFC 8693 authorization server  Mandatory Cloud KMS before core works
Selective disclosure / BBS        Blockchain
ML reputation model               Multi-region HA
A2A + MCP simultaneously          Complex wallet UI
```

## Build Order (mandatory — no UI before cross-agent E2E)

```text
 1. contracts + JSON schemas
 2. crypto signer/verifier
 3. DID resolver abstraction + did:web / did:key
 4. VC issue/verify
 5. delegation + attenuation
 6. revocation
 7. Redis replay protection
 8. policy input contract + Rego → Wasm
 9. audit / ActionReceipts
10. cross-agent E2E
11. attack/failure suite
12. dashboard + demo polish
```

Gate before step 12: a single command (`pnpm demo:e2e`) prints that Agent A was accepted or rejected **for the right reasons**. A pretty UI must never hide an incomplete core.

## Week-by-Week

| Period | Work | Definition of Done |
|---|---|---|
| **13–19 Sep** | Architecture + ADRs + schemas + threat model + monorepo | Someone new can understand the trust model from README + diagrams |
| **20–30 Sep** | DID identity + signer/KMS interface + VC issue/verify | Agent A has a real DID & VC; Agent B can verify them |
| **1–10 Oct** | Delegation/attenuation + revocation + replay/PoP | All scope/expiry/revocation negative tests pass |
| **11–20 Oct** | OPA + explanations + issuer trust + trust profile | Deterministic ALLOW/DENY with reason codes |
| **21–30 Oct** | Action receipts + cross-agent interaction + UI | Live end-to-end interaction |
| **31 Oct–6 Nov** | Attack suite + failure modes + HITL | spoof/forge/replay/revoke/compromise tests pass |
| **7–11 Nov** | Public deploy + clean clone + CI/CD + docs | A stranger can clone & run; live URL stable |
| **12–14 Nov** | 90s video + architecture snapshot + polish | Submission package frozen |
| **15 Nov** | Submit only | No new features |

Estimated focused effort: **130–170 hours** for one person holding the scope above. The biggest schedule risks are cryptographic-contract bugs, delegation edge cases, and revocation/replay races — not missing features.

## Cut Lines

```text
P0 — Frozen Scope
  did:web + did:key fixtures
  real JWS/VC signing & verification
  scoped delegation + attenuation
  trusted issuers + real revocation
  atomic Redis replay protection + fail-closed writes
  Rego → embedded OPA Wasm + reasonCodes
  tamper-evident provenance + 2 agents + attack suite + live demo

P1 — only after the full P0 E2E passes
  did:webvh resolver adapter + Cloud KMS/HSM signer
  HITL + RFC 8693 subset + one A2A adapter

P2 — after the competition
  SPIRE deployment + MCP/A2A full interoperability
  multi-tenant control plane + advanced selective disclosure
```

## CI Gates

Every pull request runs: format, lint, typecheck, unit tests, VC validation tests, delegation property tests, `opa fmt/check/test`, policy.wasm compilation + hash manifest, integration tests, attack tests, secret scanning, dependency/SAST scanning, container build. `main` additionally: signed image build → staging deploy → smoke tests → cross-agent E2E.

**Policies are code.** Any change under `policies/**/*.rego` requires tests and review; the policy bundle hash and version are recorded with every decision.
