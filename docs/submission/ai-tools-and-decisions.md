# AI Tools & Engineering Decisions

## How AI was used (full disclosure)

An AI coding agent (ZCode, GLM-powered) implemented the workspace packages,
tests, and documentation across 17 incremental steps, each closed by a
milestone gate: typecheck, unit/property suites, the adversarial suite,
OPA native tests, CI green.

**AI output was never trusted as correct.** Every mechanism carries
executable proof: positive controls, negative/shuffled controls, explicit
pre-registered gates (a gate is never retuned after a run to make a failure
look like a pass), and property-based tests. Where AI was wrong — and it
was, repeatedly and consequentially — the test layer caught it:

## Real mistakes AI made that verification caught

| Mistake | How it was caught |
|---|---|
| **Wrong multicodec assumption for did:key P-256** — the initial did:key encoder used the secp256k1 code point; vectors were silently unverifiable | cross-checked against the did:key method spec vectors in the test suite |
| **Quarantine ordering risk** — an early gateway draft checked the quarantine switch on the *claimed* DID before proof-of-possession bound it to a key; a spoofed claim could then have punished the victim's identity instead of the attacker's. Threat-model review rejected the ordering before it shipped | design review against threat-model.md; the shipped order (identity binding first, quarantine after) is pinned by gateway quarantine tests |
| **OPA policy gap — delegated action set never checked** — `refund_action_authorized` only tested the supported-action whitelist, so an agent delegated for `order:read` only could still refund. Found by attack scenario **AUTHORITY-002**, which was written expecting the walker to deny — and it didn't | the 60-scenario suite; policy fixed, artifact rebuilt, native test 13/13 |
| **did:web `max-age=0` freshness bug** — the cache gave explicit `max-age=0` a 1 ms pseudo-fresh lifetime, so a compromised-key revocation signal could be ignored for microseconds-to-milliseconds windows | pre-step security review reproduced it; fixed to immediately-stale/never-cached, three regression tests added |
| **DNS/IPv6 parsing defects in the SSRF transport** — a broken embedded-IPv4 splice classified `::ffff:10.0.0.1` as safe (SSRF bypass), and a host/port policy check applied address classification to hostnames, breaking every real resolution | security test matrix: 100 did:web cases incl. mapped/NAT64/CGNAT forms |
| **Redis client crashed on managed-failover socket close** — an `uncaughtException` from node-redis killed the process; then the reconnect path left the demo wedged after Redis returned | controlled outage rehearsal (stop/start Redis): fail-closed during the window, auto-recovery after |
| **`setup:opa` asset table keyed `amd64` while Node reports `x64`** — the script had literally never worked on Windows | clean-clone verification on a fresh machine state |

Also caught at review time (documented, not shipped): dashboard route code
running the 60-scenario suite on page load (14O violation — served the
baked artifact instead), and an in-memory replay fallback when Redis was
configured but unreachable (16H violation — startup now fails).

## Major engineering decisions

- **did:web for P0 identities, did:key only for test fixtures.** did:web
  rides DNS+HTTPS — boring, deployable, honest about what it inherits
  (ADR-0004). `did:webvh` deliberately deferred (out of scope).
- **Embedded OPA Wasm instead of a network policy service.** The policy
  plane gets no new network dependency and no availability surface; the
  artifact is hash-pinned by manifest and native↔Wasm parity is a test.
- **Redis `SET NX PX` for atomic replay**, claimed only AFTER crypto
  verification (a garbage proof cannot burn a jti), TTL derived from the
  proof's own expiry.
- **W3C Bitstring Status List** for revocation (permanent) + suspension
  (reversible), bound per issuer/controller; plus an emergency quarantine
  kill switch that never outruns identity verification.
- **Hash-chained Action Receipts + signed checkpoints** for provenance —
  audit-before-side-effect; tamper/truncation/rewrite detection is
  property-tested.
- **No blockchain, no transparency log for P0** — a signed checkpoint over
  the receipt chain already serves the claim made; anchoring is future work.
- **No scalar trust score, anywhere, structurally** — the profile schema
  forbids score fields; attestations are evidence, never authority;
  "10,000 successful actions" cannot manufacture a missing credential.
- **Single demo app replica** because audit/profile state is process-local
  in P0; only replay is externalized. Scaling it would fork judge-visible
  truth — so the deployment pins `replicas=1` instead.
- **Fail-closed is the universal error posture** — enforced identically at
  resolver, status, replay, policy, audit, and startup-config layers.
