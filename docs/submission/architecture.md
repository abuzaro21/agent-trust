# Architecture Snapshot (submission)

One screen. Every arrow is implemented, tested, and visible in the live
dashboard — the browser only renders what the backend already decided.

```text
 SupportAgent
      │  signed task — proof-of-possession bound to the task bytes
      ▼
 ╔══════════════════════ TRUST GATEWAY (verification boundary) ═══════════════════════╗
 ║                                                                                    ║
 ║  1  Proof of Possession  +  DID Resolution                                         ║
 ║       did:web over public HTTPS: pinned DNS, exact document.id binding,            ║
 ║       P-256-only, bounded cache          ── unresolved / bad kid ──► DENY          ║
 ║  ▼                                                                                 ║
 ║  2  Verifiable Credentials     ES256 compact-JWS VC · trusted-issuer registry ·    ║
 ║       ▼                            Bitstring Status List (revocation/suspension) · ║
 ║  3  Delegated Authority          quarantine kill switch        any failure ─► DENY ║
 ║       ▼                            Authority(child) ⊆ Authority(parent):           ║
 ║                                      actions · resources · audience ·              ║
 ║                                      amount cap · window · depth                   ║
 ║  4  Replay Protection          atomic CLAIM-ONCE (Redis SET NX PX)                ║
 ║       ▼                                                                          ║
 ║  5  VerifiedFacts              ONLY cryptographically established facts may      ║
 ║       ▼                            cross this line                               ║
 ║  6  OPA Wasm Policy            deterministic · same input → same answer ·        ║
 ║                                    hash-pinned artifact                          ║
 ║       ├── ALLOW ──► 7  Decision Receipt ──► 8  Idempotent Executor ──► 9 Outcome ║
 ║       │                                   receipt (audit-before-side-effect,    ║
 ║       │                                     executor runs ONLY after 7)         ║
 ║       └── DENY  ──► 7  Decision Receipt  (effect DENY + reason code; no 8/9)     ║
 ║                                                                                    ║
 ║  Provenance: hash-chained Action Receipts  +  signed checkpoint over the chain    ║
 ╚════════════════════════════════════════════════════════════════════════════════════╝
                                        │
                                        ▼
              DemoRefundExecutor  (simulation — no real payment movement)

 Trust Profile (read model) ← identity · active authority · attestations ·
     verified history from the audit chain.   Evidence — never authority,
     never a score.
```

Three load-bearing properties:

1. **A valid signature is not trust** — it proves *who*, never *whether*.
2. **Authority is scoped and revocable** — 120 SAR passes; the same agent's
   5000 SAR is denied `AUTHORITY_LIMIT_EXCEEDED` in the same minute.
3. **Every dependency fails closed** — resolver, status, replay, policy,
   audit: an unavailable check denies; there is no permissive fallback.

Implementation map: `packages/did · vc · status · delegation · replay ·
policy · gateway · audit · trust-profile · attacks` · `apps/web` (view only).
Deeper: [../architecture.md](../architecture.md) ·
[../architecture-overview.md](../architecture-overview.md) ·
[../threat-model.md](../threat-model.md).
