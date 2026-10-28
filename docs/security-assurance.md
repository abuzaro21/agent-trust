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

The 11 scenarios without a reason code are `DIDWEB-001…011` (the resolver reports DID-Core `didResolutionMetadata.error` values and the transport a typed `DidWebTransportError`, not gateway reason codes). Their checkers pin that typed cause (for example `invalidDid`, `internalError`, `TOO_LARGE`, `POLICY`), so "some error" is not enough; `DIDWEB-011` is a freshness property with no failure at all. The list is pinned by a test.

## What was weak, and what changed

| Area | Before | After |
|---|---|---|
| PASS rule | Reason match **and** a regex over the scenario's own outcome string **and** a checker; a missing checker passed, no reason spec passed | Typed verdict + one reason policy + checker + marker scan; every missing piece fails |
| `STATUS-004`, `POLICY-002` | Checker was unconditional (`() => ({ok:true})`); 58 of 60 asserted invariants | All 60 assert invariants; `STATUS-004` asserts `executorCalls === 0`, `policyCalls === 0`, credential stage `FAIL` |
| Reason codes asserted | 31 of 60 | 49 of 60 (11 documented exceptions, typed cause pinned instead) |
| `POLICY-001/002` | Manifests failed the **shape** gate, so the digest gate was never reached | Real manifest with a tampered digest → `hash_mismatch`; self-consistent garbage module → instantiation failure; control: the genuine artifact loads; assertion: no engine is obtainable. No executor counter is invented (nothing executes at load). |
| `AUDIT-*` | Checkpoint id `ckpt_au` is 7 characters (schema minimum 8): the checkpoint half was rejected for a **malformed payload**, never reaching the tamper comparison | Valid fixture; every audit scenario proves the untouched history verifies (chain, signed checkpoint, and the trust-profile consumer) before tampering |
| `POLICY-004` | Fixture also had empty `credential.types`, so it was invalid with or without the score | Control: same facts without the score validate; with it, invalid only for the extra property |
| `REPLAY-002` | Parsed numbers out of its own outcome sentence | Typed counts (1 authorized, 99 denied, 99 replay-denied, 1 refund) |
| `AUTHORITY-005/006`, `ATTEST-*`, `DIDWEB-*` | Counters not wired to the code under test; no positive controls | Walker result recorded with an accepted legitimate chain; trusted vouch accepted beside the rejected ones; good did:web document resolves; a public address *does* reach connect while blocked targets record `connectAttempts === 0` |

## Product-mutation evidence

To measure whether the suite depends on the defences it names, one defence at a time was removed from the product source, the suite re-run, and the file restored (nothing committed). The scripts are not part of the repository: a mutation run edits tracked source in place and is a review exercise, not a CI step.

**Before the hardening**, removing the checkpoint head-hash comparison, the policy digest comparison, or the checkpoint truncation check left the suite at **60/60 PASS** (only the SSRF mutant was caught). **After**, all four are caught by exactly the scenarios that name them (`AUDIT-007`, `POLICY-001/002`, `DIDWEB-002…005`, `AUDIT-008`).

A wider sweep of 32 single-defence mutants over the gateway, credential verifier, replay, audit chain/checkpoint, delegation, did:web and trust-profile code found 12 initially surviving mutants. Strengthening existing scenarios (the count stays 60) closed the real gaps: checkpoint signature / payload / stream binding (`AUDIT-009`), `previousHash` linkage (`AUDIT-005`), both delegation-depth branches (`AUTHORITY-006`), did:web kid ownership and redirect refusal (`DIDWEB-009`, `DIDWEB-006`), issuer-and-type-scoped attestation trust (`ATTEST-001`), each of the verifier's two quarantine stages independently (`STATUS-003`), and the verifier's own kid/issuer comparison, exercised with a hand-crafted JWS and a permissive resolver (`CREDENTIAL-002`). The final independent audit also showed that the two quarantine stages are not interchangeable: with no `expectedSubject` only the late stage catches a quarantined subject, and the early stage changes which reason a quarantined actor receives.

**One** mutant still survives individually and is **subsumed**, not a gap: the "parent has no remaining depth" branch in the delegation attenuation walker is covered by the "child depth is not strictly less than the parent's" branch for every schema-valid non-negative depth, so the suite cannot distinguish them by outcome (only the diagnostic constraint text differs). Product source was not changed to make any mutant killable.

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

Typecheck clean; 658 unit/property tests pass (51 files, including 138 `packages/attacks` tests: oracle negative controls, registry integrity, per-key evidence mutation, socket-pinning, regression tests for each weakness above); 60/60 scenarios; Redis integration 5/5 against a disposable container; OPA `fmt`/`check`/`test` clean (13/13); `policy.wasm` SHA-256 equals the committed manifest (`c0248310…eea8`, unchanged). No gateway, crypto, replay, policy, audit, Rego or Wasm file was modified.

## Independent audit and its resolution

A fresh read-only audit (Codex GPT-6.1 Sol) of the first two commits found six assurance gaps and no changed security implementation. Each came with an executed negative control; all six were fixed and each control was re-run as a real product mutant:

| Finding | Fix | Re-run as product mutant |
|---|---|---|
| P1 `DIDWEB-007` injected the `TOO_LARGE` error from a double | Drives the **real** streaming transport: declared `content-length` and streamed bytes both capped, below-limit control served, end-to-end through the resolver | Removing either or both size caps: killed (`DIDWEB-007`, vitest) |
| P1 `DIDWEB-005` tested classification, not pinning | Scenario records one DNS lookup and the validated address reaching the connection primitive; a vitest case inspects the default `https.get` options (`host` = validated IP, SNI = hostname, pinned `lookup`) | Connect-by-hostname, wrong lookup answer, second lookup: killed |
| P2 `INFRA-002` passed on `undefined === undefined` | Both receipts must be found in the chain by id, linked, ordered; now also requires `WITHIN_SCOPE` | covered by per-key tests |
| P2 `AUDIT-001..008` read only `verified` | Also record that the consumer's history is empty; control: untouched history is served | Consumer serving history while `verified=false`: killed (`AUDIT-001…008`) |
| P2 `requireInvariants` compared JSON text; empty combinators passed | Structural strict equality (rejects `toJSON`, `NaN`, `undefined`, class instances); empty expectation and `allOf()` fail; a throwing checker is a FAIL | unit tests |
| P2 per-scenario mutation test too weak | Evidence is a declarative table; **every asserted key** is independently deleted and corrupted and must be rejected; a recorded key that is neither asserted nor listed informational fails | registry test |

A second Codex pass over the fixes failed to complete ("selected model is at capacity", a platform error; not retried unchanged). Before failing it reported one real bug, a sparse array passing `strictEqual` without its holes being compared; that is fixed and tested. The six fixes above were verified by re-running each original negative control as a real product mutant, not by that second report. A fresh independent pass over the final diff is still worth doing.

The first Codex pass also agreed that no trust-consuming path relies on checkpoint comparison alone.


## Final independent audit (read-only, against `e1fab52`)

Verdict: **CHANGES REQUIRED** — two P2 findings, no P0/P1, no change to any protected path (gateway, crypto, replay, policy, audit, VC, delegation, status, DID, trust-profile, schemas, Rego, policy artifacts). Both were reproduced and fixed:

| Finding | Fix |
|---|---|
| P2 `strictEqual` accepted malformed arrays: prototype-supplied elements, a custom `toJSON` (which serialises as different evidence), `Array` subclasses | Evidence must be plain JSON-like data: exact `Array`/`Object` prototype, own enumerable data properties only (no accessors, symbols or non-index extras), every array index an own element. Negative controls run through `judge` and the real `AUDIT-009` checker. |
| P2 quarantine survivors were described as redundant, but removing the late stage lets a quarantined subject verify when `expectedSubject` is omitted | `STATUS-003` now reaches each verifier quarantine stage independently (plus a pre-quarantine control); both single-stage mutants are killed. The documentation no longer calls them redundant. |

Follow-ups from the same audit: the stale statement that `POLICY-002` and `STATUS-004` assert no invariant was removed from `docs/submission/final-submission.md`, and the verifier's kid/issuer comparison, which the audit found redundant only under today's resolvers, is now pinned by `CREDENTIAL-002`. The audit did not certify the author-reported mutation tally, because the mutation scripts are not in the repository; the figures above come from the author's runs and from the audit's independent reproduction of the specific controls it listed. These fixes have not been re-audited by Codex.
