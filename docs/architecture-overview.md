# Architecture — one screen (judge view)

The whole system is one authorized path plus one honest read model. Every
arrow below is implemented, tested, and visible in the live dashboard —
the browser only renders what the backend already decided.

```text
 Agent A (proposes a task, signed)
   │
   ▼
 Identity / proof-of-possession      ← did:web (real HTTPS documents) + ES256
   ▼
 VC / Claims                          ← W3C Verifiable Credentials (JWS)
   ▼
 Status / Delegation                  ← Bitstring revocation · quarantine ·
   │                                    Authority(child) ⊆ Authority(parent)
   ▼
 Replay                               ← atomic CLAIM-ONCE (Redis SET NX PX)
   ▼
 VerifiedFacts                         ← only cryptographically established
   │                                    facts may cross this line
   ▼
 OPA Wasm Policy                       ← deterministic ALLOW / DENY + reasons
   ▼
 ALLOW / DENY
   ▼
 Audit Receipt                         ← hash-chained, signed checkpoints
   ▼
 Executor (simulation in the demo)
   ▼
 Outcome Receipt / Checkpoint


 Trust Profile  ←  authority + attestations + verified history
                   (evidence — it NEVER grants authority and never scores)
```

Three properties carry the entire argument:

1. **A valid signature is not trust.** It proves *who*, not *whether*.
2. **Authority is scoped and revocable** — 120 SAR may pass while 5000 SAR
   from the same agent, same credential, same minute is denied.
3. **Every dependency fails closed** — resolver, Redis, status, policy,
   audit: an unavailable check denies; nothing falls back to permissive.

Deeper documentation: [architecture.md](architecture.md) ·
[threat-model.md](threat-model.md) · [trust-model.md](trust-model.md) ·
[credential-model.md](credential-model.md) · [deployment.md](deployment.md)
