# 90-Second Loom Script

**Target: 85–90 seconds.** Read at a calm demo pace (~145 wpm) the narration
below is **87 seconds**. Words in `CAPS` are on-screen anchors, not spoken.

Recording rules: one continuous take · browser 100% zoom, window 1440×900 ·
no devtools, no editor, no terminal (except one 3-second glance at the
60/60 report page) · cursor moves only to click a preset · dashboard is the
only visual.

---

## 0:00–0:08 — The problem
**Show:** landing page on the Trust Profile panel.

> "AI agents are about to act for people and companies — refunds, payments,
> data access. But knowing who an agent is doesn't tell us what it's allowed
> to do."

## 0:08–0:18 — The trust model
**Show:** cursor traces Profile: DID line (`did:web:abuzaro21.github.io:agents:support`),
authority box (`≤ 500 SAR`), attestation badges, no-score statement.

> "So we don't use a trust score. Trust here is verifiable evidence: a real
> did:web identity, signed credentials, scoped delegated authority, current
> revocation state, and a history anyone can verify."

## 0:18–0:35 — ALLOW
**Show:** click **Valid 120 SAR** → pipeline fills ✓×4 → ALLOW → SUCCEEDED.

> "This Support Agent has delegated authority to refund up to five hundred
> SAR. A one-twenty request passes every gate — identity, credential,
> status, replay — and the deterministic policy says ALLOW. It executes, and
> receipts are written before and after."

## 0:35–0:50 — Contextual DENY
**Show:** click **Over-limit 5000 SAR** → pipeline shows policy DENY,
execution NOT_RUN.

> "Same agent. Same valid identity, same valid credential — only the number
> changed. Five thousand exceeds the delegation, so policy denies:
> AUTHORITY LIMIT EXCEEDED. And this is the whole point — the agent can be
> trusted, **but not for this action.**"

## 0:50–1:00 — Spoof
**Show:** click **Spoofed Agent** → IDENTITY_PROOF_INVALID, policy NOT_RUN.

> "An attacker claiming the same identity fails at the door: a valid
> signature is a proof of the key it was signed with — policy and execution
> never even run."

## 1:00–1:10 — Revocation
**Show:** click **Revoked Credential** → CREDENTIAL_REVOKED.

> "And when authority is revoked — one bit on a status list — the same
> legitimate agent is blocked immediately. Revocation is real, not vibes."

## 1:10–1:20 — Replay
**Show:** click **Replay Attack** → first AUTHORIZED, second REPLAY_DETECTED.

> "A captured signed request is single-use. Replaying it cannot trigger a
> second refund — one authorization, one execution."

## 1:20–1:30 — Architecture / close
**Show:** navigate to /attacks, terminal beat on the 60/60 banner, back to profile.

> "Sixty adversarial scenarios — spoofing, tampering, revocation bypass,
> replay, provider outages — every one denied, every invariant checked.
> Identity, claims, authority, freshness, policy, provenance. Trust is not a
> score. It's verifiable, scoped, revocable authority."

---

## Recording checklist (do all before recording)

- [ ] hosting deployed (`/api/health` ok; `/api/demo/status`:
      `identityMode=web`, `replayStore=redis`, build SHA = final commit)
- [ ] run each preset once to warm did:web caches; then **restart the web
      container once** so the audit panel starts at zero receipts (deterministic demo world)
- [ ] browser: private window, zoom 100%, bookmarks/toolbar hidden,
      address bar will be cropped/out of frame (never present localhost as public)
- [ ] no editor, no terminal visible except planned 3-second security-suite glance
- [ ] `DEMO_PUBLIC_URL=… pnpm smoke:live` = 45/45 immediately before recording
- [ ] one take; retake if a click misfires

## Rehearsed timing (live-mode local rehearsal)

Measured with this script's exact narration against the running rehearsal:
each segment's UI transition completes well inside its window; the full pass
lands at ~87 s ± 2 s. Trim words — not scenarios — if the public deployment
runs slower (cold did:web fetches only affect the first ~5 s).
