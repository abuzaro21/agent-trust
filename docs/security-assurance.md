# Security assurance of the attack suite

This page states what the 60-scenario suite (`packages/attacks`, `pnpm test:attacks`) actually proves, how a scenario can fail,
what was weak before, and what it does **not** prove. It is evidence about the *tests*; the product's controls are described in
[threat-model.md](threat-model.md).

## How a scenario passes

A scenario passes only if **all** of these hold (`packages/attacks/src/oracle.ts`):

1. It declares a typed expected verdict — `DENIED`, `REFUSED`, `DETECTED`, `CONTAINED` or `FAILED_SAFE` — and the observation carries the same typed verdict, derived from real objects (a gateway result, a loader result, a verifier result), never from prose. `BREACHED` is observable but can never be expected.
2. It declares **exactly one** reason-code policy: a specific `reasonCode`, a predicate, or a written `noReasonCode` justification. None of the three, or more than one, fails.
3. The reason-code policy holds on the observation.
4. A registered invariant checker exists and accepts the recorded evidence. Missing checker, missing invariant key, wrong type, or an exception all fail. Checkers use strict helpers (`requireInvariants`, `requireAtLeast`) — a key the scenario forgot to record can never satisfy a check.
5. The human-readable outcome text contains no failure marker. This is defence in depth only; the text is never the oracle.

The 12 scenarios without a reason code are `DIDWEB-001…011` (the resolver reports DID-Core `didResolutionMetadata.error` values, and the transport a typed `DidWebTransportError`, not gateway reason codes) and `INFRA-002` (an `ALLOW` decision whose execution `FAILED`; the oracle is the typed decision/outcome state). The list is pinned by a test.

## What was weak, and what changed

| Area | Before | After |
|---|---|---|
| PASS rule | Reason match **and** a regex over the scenario's own outcome string **and** a checker; a missing checker passed, no reason spec passed | Typed verdict + one reason policy + checker + marker scan; every missing piece fails |
| `STATUS-004`, `POLICY-002` | Checker was unconditional (`() => ({ok:true})`); 58 of 60 asserted invariants | All 60 assert invariants; `STATUS-004` asserts `executorCalls === 0`, `policyCalls === 0`, credential stage `FAIL` |
| Reason codes asserted | 31 of 60 | 48 of 60 (12 documented exceptions) |
| `POLICY-001/002` | Manifests failed the **shape** gate, so the digest gate was never reached | Real manifest with a tampered digest → `hash_mismatch`; self-consistent garbage module → instantiation failure; control: the genuine artifact loads; assertion: no engine is obtainable. No executor counter is invented (nothing executes at load). |
| `AUDIT-*` | Checkpoint id `ckpt_au` is 7 characters (schema minimum 8): the checkpoint half was rejected for a **malformed payload**, never reaching the tamper comparison | Valid fixture; every audit scenario proves the untouched history verifies (chain, signed checkpoint, and the trust-profile consumer) before tampering |
| `POLICY-004` | Fixture also had empty `credential.types`, so it was invalid with or without the score | Control: same facts without the score validate; with it, invalid only for the extra property |
| `REPLAY-002` | Parsed numbers out of its own outcome sentence | Typed counts (1 authorized, 99 denied, 99 replay-denied, 1 refund) |
| `AUTHORITY-005/006`, `ATTEST-*`, `DIDWEB-*` | Counters not wired to the code under test; no positive controls | Walker result recorded with an accepted legitimate chain; trusted vouch accepted beside the rejected ones; good did:web document resolves; a public address *does* reach connect while blocked targets record `connectAttempts === 0` |

## Product-mutation evidence

To measure whether the suite depends on the defences it names, one defence at a time was removed from the product source, the suite re-run, and the file restored (nothing committed). The scripts are not part of the repository: a mutation run edits tracked source in place and is a review exercise, not a CI step.

**Before the hardening**, removing the checkpoint head-hash comparison, the policy digest comparison, or the checkpoint truncation check left the suite at **60/60 PASS** (only the SSRF mutant was caught). **After**, all four are caught by exactly the scenarios that name them (`AUDIT-007`, `POLICY-001/002`, `DIDWEB-002…005`, `AUDIT-008`).

A wider 33-mutant sweep over the gateway, credential verifier, replay, audit chain/checkpoint, delegation, did:web and trust-profile code found 12 initially surviving mutants. Strengthening existing scenarios (the count stays 60) closed the real gaps — checkpoint signature / payload / stream binding (`AUDIT-009`), `previousHash` linkage (`AUDIT-005`), both delegation-depth branches (`AUTHORITY-006`), did:web kid ownership and redirect refusal (`DIDWEB-009`, `DIDWEB-006`), issuer-and-type-scoped attestation trust (`ATTEST-001`). Removing both quarantine stages together is caught by `STATUS-003`.

Two mutants still survive and are **subsumed by other checks**, not gaps: the explicit `kid`/issuer DID comparison in the credential verifier (an unrelated kid cannot be found in the issuer's document, giving the same refusal) and the "parent has no remaining depth" branch (subsumed by the "child depth not strictly less" branch). The two redundant quarantine stages each survive removal individually because the other still denies.

A mutation sweep proves these specific defences are exercised; it is not a proof of completeness.

## What this does not prove

- The suite checks listed scenarios. It does not enumerate every attack, and a pass is not a security certification.
- The executor is a simulation (`DemoRefundExecutor`, no money moves), the clock is frozen at 2026-09-15T12:00:00Z, and the audit log is in-memory and process-local — controls are exercised, durability and real-time behaviour are not.
- The signed checkpoint is produced by the demo signer and is not anchored outside the process.
- `verifyAuditAgainstCheckpoint` compares sequence and head hash; interior-receipt tampering is detected by `verifyAuditChain`, and the trust-profile consumer runs both and fails closed. `AUDIT-001/002` assert that combination, not the anchoring function alone.
- Checkpoint verification accepts any resolvable signer unless the caller pins `expectedSignerDid`; the repo's consumers pin it and `AUDIT-009` exercises the pinned path.
- `AUTHORITY-005/006` call the delegation walker directly because the gateway accepts a single delegation link.
- did:web network scenarios use controlled transport doubles; no real request is made to any internal address.
- `POLICY-001/002` assert a loader boundary (no engine is produced). There is deliberately no executor counter in them.

## Verification record (this branch)

Typecheck clean; 637 unit/property tests pass (50 files, includes 117 new `packages/attacks` tests: oracle negative controls, registry integrity, per-scenario mutation of recorded evidence, regression tests for each weakness above); 60/60 scenarios; Redis integration 5/5 against a disposable container; OPA `fmt`/`check`/`test` clean (13/13); `policy.wasm` SHA-256 equals the committed manifest (`c0248310…eea8`, unchanged). No gateway, crypto, replay, policy, audit, Rego or Wasm file was modified.

## Open items from the independent audit (NOT yet fixed on this branch)

A fresh read-only audit (Codex GPT-6.1 Sol) of commits `e91b367`..`4cd2c9b` found six assurance gaps and no changed security implementation. Each came with an executed negative control. Until these are fixed, the statements above should be read with them:

- **P1** `DIDWEB-007` injects a `TOO_LARGE` error from a test double instead of sending oversized bytes through the real transport. Removing both size-cap checks in `did-web-transport.ts` left the suite green.
- **P1** `DIDWEB-005` tests private-address classification, not DNS-rebinding pinning. Changing the default request to connect by hostname left the suite green.
- **P2** `INFRA-002` can pass with `undefined === undefined` decision links.
- **P2** `AUDIT-001..008` read only `history.integrity.verified`, not that the consumer returns empty history.
- **P2** `requireInvariants` compares JSON text (`toJSON`, `NaN`/`null`, key-order quirks); `allOf()` and an empty expectation pass vacuously; `judge()` propagates a throwing checker.
- **P2** The registry mutation test accepts a checker that ignores most recorded evidence; each asserted key needs an independent violation test.

The planned fixes are: drive the real transport with oversized and chunked responses, plus a socket-level pinning test and a second-resolution rebinding control. Then make the checks structural and strict, declare asserted and informational keys per scenario, and update the "48 of 60 / 12 exceptions" counts if `INFRA-002` gains a reason code.
