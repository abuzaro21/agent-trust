# 90-Second Walkthrough Script

**Target: 85–90 seconds.** The narration below is **192 tokens**
(`wc -w` of the quoted lines, em-dashes counted). At a calm 145 words/minute
that is ~79 s of speech, which leaves ~11 s of silence for the UI transitions. (An earlier
draft of this script had 247 words — ~102 s at that pace — and was cut.)
Words in `CAPS` are on-screen anchors, not spoken.

Recording rules:

- Browser 100% zoom, window 1440×900 (or a 16:9 capture scaled to 1920×1080
  without changing the page layout); no devtools, no editor, no terminal.
- The only visuals are the running dashboard (`/` and `/attacks`). The 60/60
  beat is the `/attacks` page, not a terminal.
- Cursor moves only to click a preset or to follow the narrated element.
- **Take rule — UNVERIFIED.** Whether the competition requires one unedited
  continuous take (versus an edited cut) could not be checked because the
  live brief was not accessible. Record each segment from the real running
  application; if the brief demands a single take, record the whole script
  in one pass. Never substitute synthetic visuals for the real UI.

## Claims that must stay accurate (do not narrate beyond these)

- The refund executor is a **simulation** — say "simulated refund", never imply real money moved.
- The *Replay* preset sends the identical signed request twice from the server; it demonstrates the
  protection, it is not a live external attacker.
- The *Revoked Credential* preset revokes an **isolated** credential, not the primary one.
- Receipt timestamps come from the frozen demo clock (2026-09-15T12:00:00Z).
- "Sixty scenarios" is read from the `/attacks` page (a build-time report), not computed on screen.
- The gateway accepts a single delegation link in P0; do not narrate multi-hop delegation.

---

## 0:00–0:08 — The problem
**Show:** landing page on the Trust Profile panel.

> "AI agents will soon act for companies. But knowing who an agent is
> doesn't tell us what it may do."

## 0:08–0:18 — The trust model
**Show:** cursor traces Profile: DID line (`did:web:abuzaro21.github.io:agents:support`),
authority box (`≤ 500 SAR`), attestation badges, no-score statement.

> "So there's no trust score. Trust is evidence: a real did:web identity,
> signed credentials, scoped authority, current revocation status, and
> verifiable history."

## 0:18–0:35 — ALLOW
**Show:** click **Valid 120 SAR** → the pipeline stages (identity → … → execution) turn green → ALLOW → SUCCEEDED.

> "This Support Agent may refund up to five hundred SAR. A hundred-and-twenty
> request passes every gate — identity, credential, status, replay — and
> policy says ALLOW. The simulated refund runs, with receipts before and
> after."

## 0:35–0:50 — Contextual DENY
**Show:** click **Over-limit 5000 SAR** → pipeline shows policy DENY,
execution NOT_RUN.

> "Same agent, same valid credential — only the number changed. Five thousand
> exceeds the delegation: DENY, authority limit exceeded. The agent can be
> trusted, but not for this action."

## 0:50–1:00 — Spoof
**Show:** click **Spoofed Agent** → IDENTITY_PROOF_INVALID, policy NOT_RUN.

> "A spoofer claiming that identity fails at the door: a signature only proves
> the key it was made with. Policy never even runs."

## 1:00–1:10 — Revocation
**Show:** click **Revoked Credential** → CREDENTIAL_REVOKED.

> "Revoke the credential — one bit on a status list — and the same legitimate
> agent is blocked immediately."

## 1:10–1:20 — Replay
**Show:** click **Replay Attack** → first AUTHORIZED, second REPLAY_DETECTED.

> "A captured signed request is single-use. Replaying it cannot trigger a
> second refund. One authorization, one execution."

## 1:20–1:30 — Evidence / close
**Show:** navigate to `/attacks`, hold on the 60/60 banner, then back to the profile.

> "Sixty adversarial scenarios, each checked for the denial and for side
> effects that must not happen. Trust is not a score — it's verifiable,
> scoped, revocable authority."

---

## Recording checklist (do all before recording)

- [ ] hosting deployed (`/api/health` ok; `/api/demo/status`:
      `identityMode=web`, `replayStore=redis`, build SHA = release commit)
- [ ] run each preset once to warm did:web caches; then **restart the web
      container once** so the audit panel starts at zero receipts (deterministic demo world)
- [ ] browser: private window, zoom 100%, bookmarks/toolbar hidden,
      address bar out of frame (never present localhost as public)
- [ ] no editor and no terminal visible
- [ ] `DEMO_PUBLIC_URL=… pnpm smoke:live` = 45/45 immediately before recording
- [ ] retake any segment where a click misfires
- [ ] re-time against the real recording; trim words — not scenarios — if
      the public deployment is slower (cold did:web fetches only affect the first ~5 s)

## Timing status

The 192-token count is measured. The claim that each UI transition fits its
window has **not** been re-measured against the post-audit build or a public
deployment — treat the per-segment windows as targets until the recording is made.
