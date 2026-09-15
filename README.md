# Agent Trust

**A Trust & Authorization Fabric for AI agents — verifiable identity, scoped delegation, revocable authority, and deterministic policy enforcement.**

> **Trust is not a score. It is verifiable, scoped, revocable authority.**

---

## The Problem

AI agents are increasingly allowed to take real actions — refunds, payments, data access — with nothing but an API key and a prompt. Nobody can answer, before execution, in a way that is cryptographically verifiable:

> *Should this agent be allowed to do this action, for this principal, on this resource, right now — and can we prove why?*

A reputation number cannot answer that question. A high score does not create authority, and a low score does not revoke it. This project replaces the "trust score" with a **trust fabric** that proves each layer independently:

```text
Agent DID
   ↓
Signed proof-of-possession
   ↓
W3C Verifiable Credentials
   ↓
Delegation / Capability chain
   ↓
Credential + Revocation Verification
   ↓
Context + Provenance + Attestations
   ↓
Embedded Rego Policy Engine (OPA Wasm)
   ↓
ALLOW / DENY / REQUIRE_APPROVAL
   ↓
Enterprise Action
   ↓
Tamper-evident Action Receipt
```

## What the Fabric Proves

| Question | Mechanism |
|---|---|
| Who is the agent? | W3C DID (`did:web` in P0, `did:key` for test fixtures), proof-of-possession on every request |
| Who granted its authority? | W3C Verifiable Credentials 2.0 (JWS/ES256) from issuers listed in a **Trusted Issuer Registry** |
| What are the limits? | Scoped actions/resources, amount & time caps, strict **delegation attenuation** (`Authority(child) ⊆ Authority(parent)`) |
| Is it still valid? | W3C Bitstring Status List revocation + emergency quarantine |
| Is *this* action acceptable *now*? | Rego policies compiled to **OPA Wasm, embedded in the service process** — deterministic `ALLOW` / `DENY` / `REQUIRE_APPROVAL` with reason codes |
| What actually happened? | Tamper-evident, hash-chained **Action Receipts** with signed checkpoints |

## The Sentence That Leads This Project

> **Identity tells us who the agent is. Credentials tell us what others claim about it. Delegation tells us what it is allowed to do. Reputation provides evidence about past behavior. Policy decides whether this specific action is acceptable now.**
>
> No layer substitutes for another.

And the invariant that makes the model coherent:

> **Reputation can strengthen or weaken trust, but it can never manufacture missing authority.**
>
> - An agent with 10,000 successful actions and no `refund:create` credential → **DENY**.
> - A brand-new agent with a valid low-risk delegation → can be **ALLOW**.
> - A high-reputation agent whose credential was revoked → **DENY**.

## Security Stance

- **The LLM never decides its own permissions.** An agent runtime may *propose* a tool call, but every request passes through an independent, deterministic enforcement point. Prompt injection cannot alter a Verifiable Credential or a Rego policy.
- **Compromised keys are assumed possible.** No cryptography detects an attacker who holds the *valid* private key — so the design limits the blast radius instead: narrow scopes, amount/day caps, audience binding, short credential & proof lifetimes, human-in-the-loop for high-risk actions, revocation, and an emergency quarantine switch.
- **Fail closed.** Missing/invalid policy bundle, unavailable replay store on a write action, audit-log failure, signature-verifier errors — all deny. There is no permissive fallback anywhere.

## Demo Scenario

Two fictional organizations:

```text
Acme Retail                          PayCo
  CustomerSupportAgent  ──refund──▶  PaymentAgent
```

Acme issues its support agent a delegation credential: `refund:create`, `merchant:acme`, **max 500 SAR**, bounded expiry. PayCo's PaymentAgent has **never seen Acme's agent before** — it knows only trusted issuers and policy. Trust is portable across the organizational boundary.

The failure demo is the point:

```text
1) Valid identity + 120 SAR refund          → ALLOW
2) Same identity + 5,000 SAR refund         → DENY  AUTHORITY_LIMIT_EXCEEDED
3) Spoofed identity / wrong private key     → DENY  IDENTITY_PROOF_INVALID
4) Legit agent, credential revoked          → DENY  CREDENTIAL_REVOKED
5) Replay of captured signed bytes          → DENY  REPLAY_DETECTED
```

> **The agent is trusted — but not for this action.**

## Architecture at a Glance

```mermaid
flowchart LR
    A[Agent A<br/>DID + Key] -->|Signed task + credentials + PoP| ENFORCE[Policy Enforcement Point]
    ENFORCE --> DID[DID Resolver]
    ENFORCE --> VC[VC Verifier]
    VC --> STATUS[Revocation / Status List]
    VC --> TRUST[Trusted Issuer Registry]
    VC --> DELEG[Delegation Chain Verifier]
    ENFORCE --> REPLAY[Replay Store<br/>Redis SET NX EX]
    ENFORCE --> EVID[Trust Evidence Builder]
    EVID -->|Verified facts + request context| OPA[Embedded OPA Wasm<br/>Compiled Rego]
    OPA -->|ALLOW| B[Agent B / Enterprise API]
    OPA -->|REQUIRE_APPROVAL| HITL[Human Approval]
    OPA -->|DENY + reasons| ENFORCE
    B --> LOG[Hash-chained Action Receipts]
    ENFORCE --> LOG
    LOG --> CHECKPOINT[Signed Checkpoints]
    LOG --> PROFILE[Trust Profile<br/>evidence read model]
    ATTEST[Attestation Credentials<br/>issuer+type-scoped] --> PROFILE
```

Full details: [docs/architecture.md](docs/architecture.md) · [threat model](docs/threat-model.md) · [credential model](docs/credential-model.md) · [trust model](docs/trust-model.md)

## Repository Layout

```text
agent-trust/
├── apps/
│   ├── web/                  # Next.js demo & operations UI
│   ├── trust-gateway/        # Fastify + embedded OPA Wasm — the enforcement core
│   ├── credential-service/   # Issuance, revocation, trusted-issuer registry
│   ├── agent-alpha/          # Demo agent A (CustomerSupportAgent)
│   └── agent-beta/           # Demo agent B (PaymentAgent)
├── packages/
│   ├── crypto/               # Signer abstraction (local / KMS)
│   ├── did/                  # Resolver abstraction + did:web, did:key, did:webvh adapters
│   ├── vc/                   # W3C VC issue/verify (JWS, ES256)
│   ├── delegation/           # Attenuation-verified delegation chains
│   ├── trust-profile/        # Evidence-based trust profiles
│   ├── schemas/              # JSON schemas for all contracts
│   ├── policy-engine/        # PolicyEngine abstraction + OPA Wasm adapter
│   ├── sdk/                  # Client SDK for agents
│   └── testkit/              # Fixtures, test DID documents, attack builders
├── policies/                 # Rego — policies are code, versioned & hashed
├── tests/                    # conformance / integration / e2e / attacks / chaos
├── infra/                    # docker / terraform
└── docs/                     # architecture, threat model, ADRs, roadmap
```

## Status & Roadmap

**🚧 Architecture frozen — implementation underway (scaffold stage).**

Delivery architecture (P0) is deliberately narrower than the target architecture; the riskiest components are P1 adapters behind stable interfaces, so the live demo never depends on them.

| Phase | Scope |
|---|---|
| **P0 — frozen** | `did:web` + `did:key` fixtures, real JWS/VC signing & verification, scoped delegation + attenuation, trusted issuers + real revocation, atomic Redis replay protection with fail-closed writes, Rego → embedded OPA Wasm with reason codes, tamper-evident provenance, two demo agents, attack suite, public live demo |
| **P1 — after P0 E2E passes** | `did:webvh` resolver adapter, Cloud KMS/HSM signer, human-in-the-loop approvals, RFC 8693 token-exchange subset, one A2A adapter |
| **P2 — post-competition** | SPIFFE/SPIRE deployment, full MCP/A2A interop, multi-tenant control plane, selective disclosure |

Build order and week-by-week plan: [docs/roadmap.md](docs/roadmap.md).

## Development

Requires Node 22+ (24 recommended). pnpm is provided via corepack:

```bash
corepack enable
pnpm install
pnpm typecheck          # strict TS across the workspace
pnpm test               # vitest unit + property suite (no services needed)
pnpm test:integration   # Redis-backed replay tests (needs TEST_REDIS_URL)
docker compose up -d redis   # one-command dev Redis (port 6380 — 6379 is
                             # inside a Windows excluded-port range on some
                             # machines; CI uses 6379)
TEST_REDIS_URL=redis://127.0.0.1:6380 pnpm test:integration

pnpm demo:e2e           # cross-agent gateway demonstration (all real components)
pnpm demo:profile       # evidence-based Trust Profiles — attestations, history, integrity
pnpm demo:attacks       # adversarial suite: 60 deterministic scenarios, invariants too
pnpm test:attacks       # same suite as a CI gate (exits non-zero on any FAIL)

# Demo dashboard (Next.js)
pnpm dev                # http://localhost:3000 — trust console + /attacks security tests
pnpm test:frontend      # API adapter integration + presentation tests
pnpm build:web          # production build check
pnpm demo:did:init      # one-time live identity setup → did:web docs + gitignored local keys
pnpm demo:did:resolve did:web:example.com:agents:support   # real HTTPS resolution + diagnostics
DEMO_DID_DOMAIN=example.com pnpm demo:e2e:web              # live did:web mode (deployment-gated)

# Policy pipeline (requires the pinned OPA v1.20.2 on PATH, or tools/bin):
pnpm policy:fmt && pnpm policy:check && pnpm policy:test
pnpm build:policy       # → artifacts/policy/policy.wasm + manifest.json (hash-pinned)
```

Implemented packages (Phases 1–6 — identity, credentials, delegation, status, replay, policy, gateway):

| Package | Contents |
|---|---|
| `@agent-trust/schemas` | JSON Schema contracts (draft 2020-12), TS types, closed reason-code enum, ajv validator |
| `@agent-trust/crypto` | Frozen `Signer` interface, ES256 `LocalSigner`, RFC 8785 canonical JSON, DPoP-style proof-of-possession |
| `@agent-trust/did` | `DidResolver` seam (ADR-0001), `did:key` P-256, production `did:web` resolver (ADR-0004): strict parser, HTTPS-only SSRF-pinned transport, exact document-id binding, P-256 key profile, bounded cache with rotation-aware freshness, method registry |
| `@agent-trust/vc` | Compact-JWS W3C VC 2.0 issuance/verification — 11-stage pipeline. Quarantine kill switch on verified identities. |
| `@agent-trust/delegation` | `Authority(child) ⊆ Authority(parent)` attenuator + chain walker with cycle detection, property-tested |
| `@agent-trust/status` | W3C Bitstring Status List (revocation permanent, suspension reversible), signed status-list credentials, agent quarantine — fail-closed |
| `@agent-trust/replay` | Atomic CLAIM-ONCE replay protection (ADR-0003): in-memory + Redis `SET NX PX`, post-crypto claim ordering, proof-derived TTL |
| `@agent-trust/policy` | Embedded OPA Wasm engine (ADR-0002): hash-pinned artifact, `VerifiedFacts`-only input, deterministic denial precedence |
| `@agent-trust/audit` | Hash-chained Action Receipts (domain-separated SHA-256, RFC 8785 bodies), atomic append, signed checkpoints, tamper/truncation/rewrite detection |
| `@agent-trust/gateway` | **The Trust Gateway** — composes every layer into one authorized path: PoP → replay → VC/status → delegation chain → VerifiedFacts → policy → decision receipt → idempotent executor → outcome receipt. Receipts only for authenticated actors; audit-before-side-effect; executor unreachable without gateway authorization. |
| `@agent-trust/trust-profile` | **Trust Profiles (read model)** — contextual, evidence-based answers to "what VERIFIED evidence exists for this agent": resolved identity, active authority with evidence digests, issuer+type-scoped attestations, and aggregated history from the VERIFIED audit chain + signed checkpoint (history fails closed independently). `AgentAttestationCredential` passes the FULL VC pipeline; attestations are EVIDENCE, never authority. The profile schema structurally forbids score fields — no trust/reputation number exists, and the profile never bypasses policy. |
| `@agent-trust/attacks` | **Adversarial suite** (`pnpm demo:attacks`) — 60 deterministic scenarios across identity/credential/authority/status/replay/policy/audit/attestation/did:web/infrastructure; each judges the denial reason AND the side-effect invariants (executor calls, victim attribution, cache state, profile immutability); machine-readable `artifacts/attacks/attack-report.{json,md}` |

| `apps/web` | **Demo dashboard** (Next.js, `pnpm dev`) — trust console (profile, presets, pipeline, decision, audit, evidence) + `/attacks` suite view. A pure read model: every decision comes from the real gateway server-side; no trust logic or scores in the browser. |
## Architecture: the authorized path

```text
SupportAgent (proposes)          the agent/LLM is NOT the authorization boundary
      │  signed task (PoP bound to task content)
      ▼
Trust Gateway  ──────────────  VERIFICATION BOUNDARY
      ├─ 1 request schema (fail closed)
      ├─ 2 identity / PoP / DID / htu / time
      ├─ 3 replay claim (Redis SET NX PX, post-crypto)
      ├─ 4 credentials: selection → verification → status → quarantine
      ├─ 5 delegation chain → effective attenuated authority
      ├─ 6 VerifiedFacts (centralized builder)
      ├─ 7 policy — OPA Wasm          POLICY BOUNDARY
      ├─ 8 decision receipt           PROVENANCE BOUNDARY (audit-before-side-effect)
      ├─ 9 DENY → stop, executor never called
      ▼
Action Executor  ────────────  SIDE-EFFECT BOUNDARY (idempotent by taskId)
      ▼
execution-outcome receipt (separate chained event)
```

The defining demonstration: the same fully-authenticated legitimate agent, same valid credentials — **120 SAR → ALLOW, 5000 SAR → DENY `AUTHORITY_LIMIT_EXCEEDED`**. Run it yourself:

```bash
corepack pnpm demo:e2e                                   # in-memory replay store (labeled)
TEST_REDIS_URL=redis://127.0.0.1:6380 corepack pnpm demo:e2e   # real Redis SET NX PX
```

The project's own rule applies: **no UI before cross-agent E2E works** — a single `pnpm demo:e2e` must print that Agent A was accepted or rejected for the right reasons before any dashboard exists.

## Documentation

- [Architecture](docs/architecture.md) — the planes, verification pipeline, and delivery decisions
- [Threat model](docs/threat-model.md) — attack suite, fail-closed matrix
- [Credential model](docs/credential-model.md) — VC types, delegation attenuation rules
- [Trust model](docs/trust-model.md) — trust profiles, reputation-as-evidence, decision objects
- [Roadmap](docs/roadmap.md) — phases, build order, definition of done
- [ADRs](docs/adr/) — frozen architecture decisions ([ADR-0004: did:web live identity plane](docs/adr/0004-did-web-live-identity.md))
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE) © abuzaro21 and contributors
