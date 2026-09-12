# Credential Model

All credentials are W3C Verifiable Credentials 2.0, signed as JWS with the `ES256` profile.

## Credential Types

| Type | States | Issued by |
|---|---|---|
| **`AgentMembershipCredential`** | Who controls the agent; which organization it belongs to; optional runtime binding (e.g. SPIFFE ID) | Organization controller DID |
| **`AgentDelegationCredential`** | What the agent may do: actions, resources, audience, limits, delegation depth | Controller or an authorized delegator |
| **`AgentAttestationCredential`** | A verifiable claim about behavior, certification, or security posture | A trusted attester in the registry |

## Delegation Credential Shape

```json
{
  "type": ["VerifiableCredential", "AgentDelegationCredential"],
  "issuer": "did:web:acme.example:org",
  "credentialSubject": {
    "id": "did:web:agents.acme.example:refund-bot",
    "authority": {
      "actions": ["refund:create"],
      "resources": ["tenant:acme"],
      "audience": ["did:web:payments.example:agent"],
      "limits": { "amount": 500, "currency": "SAR", "perDay": 20 },
      "delegationDepth": 0
    }
  },
  "validFrom": "2026-10-01T00:00:00Z",
  "validUntil": "2026-10-31T00:00:00Z",
  "credentialStatus": { "type": "BitstringStatusList", ... }
}
```

## Attenuation — The Core Invariant

For any sub-delegation:

```text
Authority(child) ⊆ Authority(parent)
```

concretely:

```text
child.actions    ⊆ parent.actions
child.resources  ⊆ parent.resources
child.amount     ≤ parent.amount
child.expiry     ≤ parent.expiry
child.depth      < parent.remainingDepth
```

An agent can never turn a 500 SAR delegation into a 50,000 SAR one, nor convert `orders:read` into `refund:create`. Delegation cycles and depth overflow are structural violations and are rejected.

This invariant is enforced by the recursive delegation-chain verifier **before** policy runs, and it is property-tested: *whatever delegation tree the test generator produces, the validator must never accept a child with authority beyond its parent's.* (See `packages/delegation` and `tests/conformance`.)

## Durable vs Runtime Authority

| | Durable authority | Runtime authority |
|---|---|---|
| Form | Relatively long-lived VC establishing the origin of the delegation | Short-lived proof/token bound to the agent's key, a specific audience, and a specific action |
| Lifetime | Days–weeks | Minutes |
| Purpose | Prove *where the authority comes from* | Prove *who is acting right now* |
| Analogue | OAuth Token Exchange's subject/actor split | DPoP sender-constrained proof |

## Revocation

- **W3C Bitstring Status List** is the revocation/suspension mechanism of record.
- A local status index/cache (Postgres `Revocation` table) serves freshness with bounded lag; high-risk actions fail closed when the status source is unreachable and the cache is stale.
- **Emergency quarantine** (`Quarantine` table + kill switch) stops an agent regardless of credential state — it is the operator's break-glass control, and every decision records whether it was active.

## Trust Rules

1. A signature proves integrity and issuer control — **not** that the claim should be accepted.
2. The **Trusted Issuer Registry** decides which issuer DIDs are accepted, per credential type, per trust domain. Self-signed credentials from unregistered issuers are rejected as `UNTRUSTED_ISSUER`.
3. Raw VC documents may be stored encrypted; the relational tables hold only indexes and normalized facts. **Private signing keys are never stored in the database.**

## Data Model (relational index)

| Model | Key fields | Purpose |
|---|---|---|
| `Agent` | `did`, `controller_did`, `status`, `current_key_id`, `workload_binding` | Logical agent identity |
| `TrustedIssuer` | `issuer_did`, `trust_domain`, `allowed_credential_types[]`, `status`, validity window | Issuer trust decisions |
| `Credential` | `credential_id`, `type`, `issuer_did`, `subject_did`, `claims`, validity, `status_ref`, `credential_hash` | VC index |
| `Delegation` | `credential_id`, `delegator_did`, `delegate_did`, `parent_id`, `actions[]`, `resources[]`, `limits`, `audience[]`, `max_depth` | Authority graph |
| `Attestation` | `credential_id`, `issuer_did`, `subject_did`, `predicate`, `domain`, `evidence_hash` | Verifiable vouches |
| `Revocation` | `credential_id`, `status_list`, `index`, `status`, `changed_at` | Local status cache |
| `Decision` | `decision_id`, `effect`, `reason_codes`, `failed_constraints`, `policy_hash`, `evidence_hash`, `request_hash` | Explainability/audit |
| `ActionReceipt` | `event_id`, `actor_did`, `action`, `resource`, `request_hash`, `decision_id`, `previous_hash`, `event_hash`, `signature` | Tamper-evident provenance |
| `Quarantine` | `agent_did`, `reason`, `activated_at`, `expires_at`, `operator` | Emergency kill switch |
| `Approval` | `approval_id`, `approver`, `task_hash`, `constraints`, `expires_at`, `used_at` | Human-in-the-loop |
