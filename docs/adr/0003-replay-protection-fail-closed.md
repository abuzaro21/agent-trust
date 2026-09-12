# ADR-0003: Atomic Redis replay protection; writes fail closed

- **Status:** Accepted (frozen)
- **Date:** 2026-09-13

## Context

A captured, validly-signed request must not be executable twice. The naive `GET`-then-`SET` cache pattern is racy: two concurrent replays can both observe "not seen" and both proceed. We also need a defined behavior for when the replay store is down.

## Decision

- Replay protection uses a single **atomic** Redis operation on the proof's `jti`:

  ```text
  SET replay:<aud>:<kid>:<jti> 1 NX EX <ttl>
  ```

  with `ttl = proof_expiry − now + allowed_clock_skew`.

- `OK` → first use; verification continues. `nil` → `DENY / REPLAY_DETECTED`.
- Redis unreachable **on a write/state-changing action** → `DENY / REPLAY_PROTECTION_UNAVAILABLE` (**fail closed**). Redis being down never degrades into implicit permission.
- Read-only operations may follow a different policy only where explicitly designed for it.
- This mirrors DPoP (RFC 9449) semantics — sender-bound proofs with replay detection — rather than an ad-hoc nonce scheme. Audience and key binding are part of the replay key, so a captured proof is also useless against another service.

## Consequences

- The guarantee is atomic at the storage engine, not at the application layer — no race window between check and set.
- Redis becomes a hard dependency for writes; its availability requirement is explicit and its failure mode is a defined denial, not an outage ambiguity.
- Per-day operation limits (`perDay`) can reuse the same atomic counter pattern with a bounded window key.
