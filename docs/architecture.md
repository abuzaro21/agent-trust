# Architecture

> **Target architecture ≠ delivery architecture.** The theoretical design stays broad, but the live submission never depends on its riskiest components. Everything volatile sits behind a stable interface as a P1 adapter.

## What is implemented vs. the target design

This document describes the **target architecture** and marks what P0 actually built. Where the two
differ, the table below is authoritative.

| Topic | Target (this document) | Implemented in P0 |
|---|---|---|
| Runtime | Fastify Trust API + separate agents/credential service | One Next.js app (`apps/web`) whose route handlers call the library packages in-process; `apps/trust-gateway`, `credential-service`, `agent-alpha/beta` are empty placeholders |
| Identity | `did:web` + `did:key`, `did:webvh` as P1 | `did:web` (hardened, SSRF-pinned) and `did:key` P-256 fixtures; no `did:webvh` |
| Policy | Rego → Wasm, evidence incl. reputation inputs | Rego → Wasm, `VerifiedFacts`-only input; emits `ALLOW`/`DENY` (never `REQUIRE_APPROVAL`) |
| Delegation | Multi-hop chains with attenuation | Chain walker/attenuator in `packages/delegation` (tested directly); **the gateway accepts a single delegation link** |
| Limits | amount, currency, `perDay`, window, depth | amount, currency, window, depth enforced; **`perDay` is accepted but not enforced** |
| Human approval | HITL via `REQUIRE_APPROVAL` | Not implemented (P1) |
| Persistence | PostgreSQL | None — audit, status, profile state are in-memory and reset on restart; only replay claims are in Redis |
| Provenance | Periodic signed checkpoints | A checkpoint is signed over the current chain when the audit/profile API is read |
| Key custody | KMS/HSM `Signer` | Local ES256 signer; demo keys are deployment secrets |
| Executor | Real enterprise API | `DemoRefundExecutor` — a simulation, no money moves |
| Clock | Wall clock | Frozen demo clock `2026-09-15T12:00:00Z` in the demo app (tests use their own fixed clocks) |

Failure behavior worth stating precisely: if the policy **engine throws**, the request is denied and the
executor never runs, but no decision receipt is written (the receipt schema requires a real policy hash).
Receipts are schema-validated *before* they are appended, so a malformed receipt can never corrupt the chain.

## The Core Decision

We do not build a "reputation score for agents." We build a **Trust & Authorization Fabric** that can prove:

- who the agent is (**identity**),
- who granted its authority and vouches for it (**credentials**),
- what the limits of that authority are (**delegation**),
- whether it is still valid (**revocation**), and
- what historical evidence justifies trust **in this specific context** (**policy over provenance**).

## Technology Choices (frozen)

| Domain | Decision |
|---|---|
| Agent identity | W3C DID Core — **`did:web` in P0**, `did:key` for local fixtures/tests, `did:webvh` as P1 adapter behind `DidResolver` |
| Cryptographic proof | Proof-of-possession per request; DPoP-style sender binding semantics |
| Credentials | W3C VC Data Model 2.0 |
| Credential signing | JOSE/JWS, `ES256` profile |
| Delegation | Custom `AgentDelegationCredential` on top of VC with strict attenuation |
| Runtime auth | Direct signed requests in MVP; RFC 8693 Token Exchange as P1 upgrade |
| Revocation | W3C Bitstring Status List + emergency quarantine |
| Policy | **Rego compiled to OPA Wasm, embedded in the Fastify process** behind `PolicyEngine` |
| Workload identity | SPIFFE/SPIRE integration point only — not an MVP dependency |
| Provenance | Append-only hash chain + signed checkpoints |
| Database | PostgreSQL *(target — not built; P0 state is in-memory)* |
| Replay protection | Redis atomic `SET NX EX` on `jti`; write actions **fail closed** when unavailable |
| Key custody | `Signer` abstraction — P0 protected local/demo signer; Cloud KMS/HSM in P1 |
| Backend | TypeScript + Fastify *(target — P0 runs the packages inside Next.js route handlers)* |
| UI | Next.js |
| Deployment | Web + Trust API (embedded OPA Wasm) + PostgreSQL + Redis in simple containers — no OPA network service |

Both volatile seams are frozen behind interfaces so no vendor or protocol dependency enters the core:

```ts
interface DidResolver {
  supports(did: string): boolean;
  resolve(did: string): Promise<DidResolutionResult>;
}

interface PolicyEngine {
  evaluate(input: PolicyInput): Promise<PolicyDecision>;
}
```

## The Planes

### Identity Plane

Every agent has a DID and a control key that is **never an environment variable in production**. The DID document publishes the verification method; private material lives in a KMS/HSM or workload-identity mechanism (P1) or a protected local signer (P0 demo).

Four identity concepts are kept strictly separate — collapsing them into one "user" is what makes serious systems ambiguous:

| Concept | Example |
|---|---|
| **Subject** | RefundAgent (`did:web:agents.acme.example:refund-01`) |
| **Controller** | Acme (`did:web:acme.example:org`) |
| **Operator** | The Kubernetes workload running the agent (`spiffe://acme.prod/agents/refund-01`) |
| **Beneficiary** | The Acme customer/department on whose behalf it acts |

### Credential Plane

Three credential types (all W3C VC 2.0, JWS-signed):

- **`AgentMembershipCredential`** — who controls the agent, which organization it belongs to
- **`AgentDelegationCredential`** — what it may do (actions, resources, limits, depth)
- **`AgentAttestationCredential`** — verifiable vouches/claims about behavior or certification

A cryptographically valid self-signed credential from an unknown issuer is **not accepted**. The **Trusted Issuer Registry** defines which issuer DIDs are trusted, for which credential types, in which trust domain. Signature verification and the decision to trust an issuer are separate steps — the W3C model itself separates them.

### Verification Plane

Runs before policy; produces **verified facts**, not opinions:

```text
resolve DID
→ prove key possession
→ claim request nonce/JTI (atomic; right after PoP, before credential work)
→ verify VC signature
→ validate schema/type
→ validate issuer trust
→ validate subject/audience
→ validate notBefore/expiry
→ check revocation
→ verify parent delegation chain
→ enforce attenuation
→ build verified evidence
```

If cryptographic verification fails there is no "low trust" outcome — the result is `DENY / IDENTITY_PROOF_INVALID` (or the matching reason code). Verification failures are denials, not scores.

### Policy Plane

The OPA runtime is **not** a sidecar service in P0. CI compiles Rego to `policy.wasm`; the Fastify process loads the Wasm module in-process. Fewer moving parts, no network hop, faster cold start. In exchange, we own the policy lifecycle explicitly:

```text
policies/*.rego
   ↓ fmt / check / test
opa build -t wasm
   ↓
policy.wasm + policyManifest.json
   ↓
SHA-256 policy hash
   ↓
PolicyEngine.evaluate(input)
```

Every decision records `policyVersion` and `policyHash`. If the bundle is missing, invalid, or fails to initialize, **write actions are denied** — there is no permissive fallback. Rego receives only pre-verified facts; it is never a cryptographic parser.

Illustrative **target** policy input (the implemented `VerifiedFacts` shape is `packages/schemas/src/schemas/verified-facts.schema.ts`; it carries no reputation counters):

```json
{
  "actor": { "did": "did:web:...", "controller": "did:web:...", "quarantined": false },
  "request": { "action": "refund:create", "amount": 120, "currency": "SAR", "resource": "tenant:acme" },
  "authority": { "actions": ["refund:create"], "maxAmount": 500, "currency": "SAR" },
  "evidence": {
    "credentialsValid": true,
    "revocationChecked": true,
    "replaySafe": true,
    "successfulSimilarActions30d": 41,
    "unresolvedIncidents": 0
  }
}
```

Decisions are structured objects with deterministic reason codes — never LLM-generated. An LLM may later *rephrase* a decision for a human; the decision object remains the source of truth.

### Provenance Plane

Every decision that reaches policy (and, separately, each execution outcome) produces an **ActionReceipt** in an append-only hash chain. Requests denied earlier — a failed identity proof, a replay, a credential problem — and infrastructure failures such as an unavailable audit store or a crashed policy engine write no decision receipt:

```text
eventHash = SHA-256(previousEventHash || canonical(eventPayload))
```

Checkpoints are signed over the chain (in P0, when the audit/profile API is read). Deleting or editing any old event breaks the entire chain after it. Raw conversations and PII never enter the chain — and never enter any public ledger. External transparency anchoring (digest-only, Sigstore/Rekor pattern) is optional and off by default.

## The Security Boundary That Matters

```text
┌─────────────────────────┐        ┌──────────────────────────────┐
│  Agent runtime (LLM)    │  untrusted  │  Trust Gateway (Fastify)      │
│  proposes tool calls    │ ──────▶ │  verifies, decides, enforces  │
│  NEVER decides its own  │        │  OPA Wasm · receipts · replay │
│  permissions            │        │  gate                          │
└─────────────────────────┘        └──────────────────────────────┘
```

Untrusted: agent runtimes, the internet/counterparties, DID resolution inputs, presented credentials, LLM-generated tool calls, remote attestations, connector inputs. Security-critical: the signer/KMS, the signed policy supply chain, the trusted-issuer registry, the audit signer.

## Delivery Architecture

```text
P0 / Delivery
  did:web (HTTPS-hosted DID documents) + did:key fixtures
  W3C VC + real JWS verification · scoped delegation + attenuation
  real revocation · Redis atomic replay protection
  Rego → OPA Wasm embedded in Fastify
  in-memory (P0) / Postgres (target) + tamper-evident receipts · two demo agents · trust-gated simulated action

P1 / Optional differentiators
  did:webvh resolver adapter · Cloud KMS/HSM signer
  A2A adapter · RFC 8693 subset · HITL approvals
```

Why `did:web` for the live demo: it is the simplest to operate and the most institutionally legible — `did:web:agents.acme.example:support-1` resolves to a DID document served over HTTPS. `did:webvh` remains in the vision as a P1 adapter so the demo never depends on history/witness/resolver complexity.

## Standards Alignment

This fabric is built into a real, currently-open standards gap, not alongside it: W3C DID Core already allows non-human subjects; DIF's July 2026 position treats AI agents as first-class DID subjects with verifiable-evidence authority; the KYA-OS project moved to DIF's Trusted AI Agents WG (April 2026); and MCP's own August 2026 roadmap names "Agent Identity and Enterprise-Ready Security" — explicitly listing DPoP, workload identity, and RFC 8693 token exchange as directions of work.
