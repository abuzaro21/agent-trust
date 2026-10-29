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

## Independent post-freeze review (October 2026)

After the 17-step build was frozen, a second audit was run with different
tools: Claude Sonnet 5.5 orchestrated; **OpenAI Codex GPT-6.1 Sol** performed a
read-only code audit (and later a read-only review of the repair commits);
**Claude Opus 5.5** was consulted once to challenge the audit's conclusions.
Findings were re-verified against the source before being acted on, and the
reviewers disagreed in places (documented, not forced into agreement).

| Defect in the AI-written implementation | How it was found | Resolution |
|---|---|---|
| **Audit-chain poisoning** — a request such as `amount:-5` was denied, but the denial receipt carried the invalid amount; the log accepted it and chain verification failed afterwards, so one request could turn the audit view red until restart | Opus follow-up probe, reproduced with one `curl` | Parameters gate in the gateway + receipt schema validation before append; 29 regression tests (22 gateway, 2 audit-log, 5 API) |
| **Authority window dropped** — `validFrom/validUntil` never reached the policy facts, so expired/not-yet-valid authority was allowed | Codex audit, reproduced against the real Wasm | Window passed through from the signed credential; tests for both bounds |
| **Concurrent revocation lost update** — two simultaneous revokes could undo one another | Codex audit, reproduced | Per-list serialization (single-process only) |
| **Result digest silently dropped** from outcome receipts | Codex audit | Result passed to the receipt builder; tamper test |
| **Public suite trigger** — `?run=1` ran the 60-scenario suite per unauthenticated call | Opus review | Route serves the build artifact only |
| **Documentation drift** — test counts, "amount/day caps", human-in-the-loop, target-vs-built architecture, and a 90-second script whose narration was ~102 s, not 87 s | Claim-to-code matrix | Corrected in this package |

Not fixed (listed in the threat model): status-list rollback, `perDay`
enforcement, DID key-purpose checks, multi-hop through the gateway.

## The 90-second video (October 2026)

The submission film ([video.md](video.md)) was made with AI tools, disclosed here and in the video description:

- **Claude (Anthropic), through Claude Code**, produced the film under the author's direction:
  - the edit and motion graphics, in Remotion (React and TypeScript);
  - the narration pipeline;
  - the original synthesized music and sound effects;
  - the quality checks.
- **Chatterbox TTS** (Resemble AI, MIT licence), run locally with its built-in voice, generated **all narration**. There is no voice cloning, and Resemble's imperceptible Perth watermark is kept in the audio.
- **Whisper** small.en (OpenAI) transcribed every narration line to check its accuracy. It is not part of the film.
- **OpenAI Codex (GPT-6.1 Sol), read-only,** independently critiqued the film. It checked the narrated claims against the capture logs, measured the audio, and confirmed that the evidence frames were unchanged across the timing revisions.
- No generative image or video model was used. The application footage is a real screen recording of the public demo, and the explanatory graphics are labelled ILLUSTRATION on screen.

Verification caught AI mistakes here too:
- A caption drafted as "Accepted once. Refused twice." was false and was corrected to "Accepted once. Re-send refused."
- An earlier mix passed every loudness and transcription check, yet the author heard a hiss in it. The causes were traced (a synthetic noise bed, the voice model's breathy aspiration, and limiter clicks) and fixed at their source.

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
