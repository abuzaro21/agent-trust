# Trust Model

## The Guiding Sentence

> **Identity tells us who the agent is. Credentials tell us what others claim about it. Delegation tells us what it is allowed to do. Reputation provides evidence about past behavior. Policy decides whether this specific action is acceptable now.**
>
> No layer substitutes for another.

## Why Not a Score

`Agent score = 92/100` collapses five different questions into one number and answers none of them verifiably. It cannot say *for which action*, *under whose authority*, *until when*, or *why* — and it manufactures the dangerous illusion that high reputation implies broad authority.

## Trust Profile

A trust profile is **curated evidence**, not a number:

```yaml
agent:
  did: did:web:agents.acme.example:refund-bot
  controller: did:web:acme.example:org
  status: active

authority:
  refund:create:
    max_amount: 500
    currency: SAR
    valid_until: 2026-10-31T00:00:00Z

attestations:
  recognized_issuers: 3
  security_certification: verified

history:            # evidence, not score
  refund:create:
    successful_30d: 41
    denied_30d: 2
    disputed_30d: 0

security:
  credential_revoked: false
  quarantined: false
  last_key_rotation: 2026-09-01T00:00:00Z

evidence_freshness:
  computed_at: 2026-09-13T00:00:00Z
```

**Policy decides what the evidence means.** The profile itself never renders a verdict.

The API exposes this as `GET /v1/agents/{did}/trust-profile` — a curated view scoped to the requester's context. Full customer-interaction history never goes to a counterparty; only the evidence required for that relationship does.

## The Reputation Rules

> **Reputation can strengthen or weaken trust, but it can never manufacture missing authority.**

| Situation | Outcome |
|---|---|
| 10,000 successful actions, no `refund:create` credential | **DENY** |
| Brand-new agent, valid low-risk delegation | Can be **ALLOW** — policy decides |
| Excellent reputation, credential revoked | **DENY** |
| Valid authority, elevated dispute/incident signals | Policy may require approval or deny |

## Decisions Are Objects, Not Strings

Every evaluation returns a structured, deterministic decision:

```json
{
  "decisionId": "dec_01J...",
  "effect": "ALLOW",
  "reasonCodes": [
    "IDENTITY_VERIFIED",
    "TRUSTED_ISSUER",
    "DELEGATION_VALID",
    "WITHIN_AMOUNT_LIMIT",
    "NO_ACTIVE_REVOCATION"
  ],
  "matchedPolicies": ["refund.low-risk.v7"],
  "evidenceRefs": ["vc:delegation:123", "receipt-summary:refund:30d"],
  "policyBundleHash": "sha256:...",
  "expiresAt": "2026-09-13T12:05:00Z"
}
```

A denial names the exact violated constraint:

```json
{
  "effect": "DENY",
  "reasonCodes": ["AUTHORITY_LIMIT_EXCEEDED"],
  "failedConstraints": [
    { "field": "request.amount", "actual": 5000, "operator": "<=", "expected": 500 }
  ]
}
```

**Rules:**

1. Reason codes and constraints are deterministic. **No LLM generates the security rationale.** An LLM may later rephrase the decision object for humans; the object remains the source of truth.
2. Every decision records the `policyBundleHash` that produced it, so a decision from last week can be explained under *the policy that was in force then*.
3. A failed explanation renderer degrades the explanation, never the security decision.

## Human-in-the-Loop

Approvals live outside the prompt entirely. Example policy:

```text
refund ≤ 500 SAR          → autonomous
500 < refund ≤ 5,000      → human approval required
refund > 5,000            → hard deny
```

The PDP returns `REQUIRE_APPROVAL`; a human authenticates via OIDC and approves a **specific task hash** — never a general delegation; the issued Approval object is short-lived and one-time-use; the request is re-evaluated with the approval as evidence. OIDC here proves the human; it never serves as the agent's identity.

## The Two-Year Thesis

Agent identity will not remain a name, an API key, or a service account. It becomes a **verifiable chain** linking the actor to its controller, its delegator, and the authority it holds right now — workload identity (SPIFFE) inside the infrastructure, DIDs across organizational boundaries, VCs for membership/capability/attestation, short-lived proofs (DPoP/token-exchange semantics) for runtime access, and policy engines deciding each specific action in context.

Reputation will not succeed as one global number. It succeeds as **verifiable evidence, scoped to a domain, a time, and a context**.

The layer that wins does not need to own every agent framework. It needs to be a **protocol-neutral trust fabric** that stands in front of MCP, A2A, and enterprise APIs and answers one question in a cryptographically defensible way, before execution:

> **Should this agent be allowed to do this action, for this principal, on this resource, right now — and can we prove why?**
