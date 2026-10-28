# Architecture — one screen (judge view)

The whole system is one authorized path plus one honest read model. Every
arrow below is implemented, tested, and visible in the live dashboard —
the browser only renders what the backend already decided. Where the target design is
broader than what was built, [architecture.md](architecture.md) says so.

```text
 Agent A (proposes a task, signed)
   │
   ▼
 1 Identity / proof-of-possession    ← did:web (HTTPS documents) + ES256
   ▼
 2 Replay claim                       ← atomic CLAIM-ONCE (Redis SET NX PX)
   ▼
 3 Credentials + status               ← W3C VCs (JWS) · issuer trust ·
   │                                    Bitstring revocation · quarantine
   ▼
 4 Delegation chain                   ← Authority(child) ⊆ Authority(parent)
   │                                    (the gateway accepts one link in P0)
   ▼
 VerifiedFacts                         ← only verified facts may cross this line
   ▼
 5 OPA Wasm policy                     ← deterministic ALLOW / DENY + reason;
   │                                    enforces action, resource, audience,
   │                                    amount and time limits
   ▼
 6 Decision receipt                    ← hash-chained, signed checkpoint
   ▼
 7 Executor (simulation in the demo)
   ▼
 8 Outcome receipt


 Trust Profile  ←  authority + attestations + verified history
                   (evidence — it NEVER grants authority and never scores)
```

The dashboard renders exactly these eight steps, in this order, from the
backend's own result — it never reorders or infers them.

Three properties carry the entire argument:

1. **A valid signature is not trust.** It proves *who*, not *whether*.
2. **Authority is scoped and revocable** — 120 SAR may pass while 5000 SAR
   from the same agent, same credential, same minute is denied.
3. **Every dependency fails closed** — resolver, Redis, status, policy,
   audit: an unavailable check denies; nothing falls back to permissive.

Deeper documentation: [architecture.md](architecture.md) ·
[threat-model.md](threat-model.md) · [trust-model.md](trust-model.md) ·
[credential-model.md](credential-model.md) · [deployment.md](deployment.md)
