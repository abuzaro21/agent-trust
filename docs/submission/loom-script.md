# 90-Second Walkthrough Script

The challenge lists the 90-second video as **optional but recommended**; the live demo URL is the required part. This script targets the redesigned dashboard (buttons "120 SAR" / "5,000 SAR" in the demo panel; failure cases as cards).

**Target: 85–90 seconds.** The narration below is **167 tokens**
(`wc -w` of the quoted lines, em-dashes counted; 162 words). At a calm 145
words/minute that is ~67 s of speech, which leaves ~23 s for UI transitions. (An earlier
draft had 247 words — ~102 s at that pace — and a second draft 192 tokens whose
individual windows were too tight; both were cut after review.)
Words in `CAPS` are on-screen anchors, not spoken.

Recording rules:

- Browser 100% zoom, window 1440×900 (or a 16:9 capture scaled to 1920×1080
  without changing the page layout); no devtools, no editor, no terminal.
- The only visuals are the running dashboard (`/` and `/attacks`). The 60/60
  beat is the `/attacks` page, not a terminal.
- Headless capture has no mouse cursor. Use highlight boxes placed from DOM bounding boxes (disclosed as overlays) instead of a drawn cursor; presets are clicked through the real DOM.
- **Show the public HTTPS URL** (address bar or a lower-third) so viewers can see it is the deployed demo; keep a standing caption "executor simulated · demo clock 2026-09-15".
- No background music or click sound effects by default (music licence is unverified; scripted clicks sound fake).
- **Take rule — UNVERIFIED.** Whether the competition requires one unedited
  continuous take (versus an edited cut) is not stated in the requirements the
  project owner verified. Record each segment from the real running
  application; if the brief demands a single take, record the whole script
  in one pass. Never substitute synthetic visuals for the real UI.

## Claims that must stay accurate (do not narrate beyond these)

- The refund executor is a **simulation** — say "simulated refund", never imply real money moved.
- The *Replay* preset sends the identical signed request twice from the server; it demonstrates the
  protection, it is not a live external attacker.
- The *Revoked Credential* preset issues and revokes a separate **isolated** credential; the primary one
  stays valid. Narrate "a credential", not "the credential" from the 120 SAR beat.
- Gate order in the real pipeline is identity → replay → credential (incl. revocation status) → delegated
  authority → policy; narrate it in that order.
- "Sixty scenarios" = 52 attacks + 8 failure demos; do not call all sixty "attacks" or "adversarial".
- Say "signed, hash-chained history", not "verifiable history" — checkpoints have no independent anchor.
- The demo has no issue/revoke controls on purpose; the *Revoke* lifecycle step runs on an isolated credential. Do not imply a visitor can revoke the main grant.
- The audit log is one shared demo log (all visitors) with a frozen clock; do not present its timestamps as real time.
- Receipt timestamps come from the frozen demo clock (2026-09-15T12:00:00Z).
- "Sixty scenarios" is read from the `/attacks` page (a build-time report), not computed on screen.
- The gateway accepts a single delegation link in P0; do not narrate multi-hop delegation.

---

## 0:00–0:08 — The problem
**Show:** the hero ("Trust is not a score") and the one-line contrast; the top bar shows the live `did:web` and Redis chips.

> "Agents will soon act for companies. Knowing who one is doesn't say what it may do."

## 0:08–0:18 — The trust model
**Show:** scroll to *Who is asking*; highlight boxes (not a drawn cursor) step through the three principals, the DID line (`did:web:abuzaro21.github.io:agents:support`, "✓ DID resolved"),
the "What it is allowed to do" card (`≤ 500 SAR`, evidence digest) and the "not by this page and not by history" line.

> "No trust score. Trust is evidence: a did:web identity, signed credentials,
> scoped authority, current revocation status, signed hash-chained history."

## 0:18–0:35 — ALLOW
**Show:** click **120 SAR** → green "Authorized · WITHIN_AUTHORITY" verdict; the stepper shows eight steps in the real order, all PASS, execution "SUCCEEDED (simulated)".

> "This Support Agent may refund up to five hundred SAR. A hundred-and-twenty
> request passes identity, replay, credential and revocation checks, then
> delegated authority — and policy says ALLOW. The simulated refund runs, with
> receipts."

## 0:35–0:50 — Contextual DENY
**Show:** click **5,000 SAR** → red "Denied · AUTHORITY_LIMIT_EXCEEDED" with the 5,000 / 500 SAR bar; the stepper shows verification 4 of 4 passed, **Policy decision** DENY, execution and outcome receipt not run; the side-by-side strip now holds both requests.

> "Same agent, same valid credential — only the number changed. Five thousand
> exceeds the delegation: DENY, authority limit exceeded. The agent can be
> trusted, but not for this action."

## 0:50–1:00 — Spoof
**Show:** scroll to *What happens when something is wrong?* → the **Spoofed agent** card → "Run this case" → Denied · IDENTITY_PROOF_INVALID; open "Show the pipeline": Identity is the first and only step that ran.

> "An impostor claims the Support Agent's DID but signs with its own key.
> Identity fails; policy never runs."

## 1:00–1:10 — Revocation
**Show:** **Revoked credential** card → "Run this case" → Denied · CREDENTIAL_REVOKED (note on the card: isolated credential).

> "Revoke a credential — one bit on a status list — and the next request
> carrying it is denied."

## 1:10–1:18 — Replay
**Show:** **Replayed request** card → "Run this case" → "First send: AUTHORIZED · identical re-send: DENIED" with REPLAY_DETECTED.

> "Send the identical signed request again: rejected. One authorization, one
> execution."

## 1:18–1:30 — Evidence / close
**Show:** (optional glance at the *Security test suite* card: 60 / 60) → open `/attacks`, hold on the 60/60 summary and the "generated at image build time" note, then back to the demo.

> "Sixty security scenarios, each judged on reason code and side effects.
> Trust isn't a score — it's verifiable, scoped, revocable authority."

---

## Recording checklist (do all before recording)

- [ ] hosting deployed (`/api/health` ok; `/api/demo/status`:
      `identityMode=web`, `replayStore=redis`, build SHA = release commit)
- [ ] rehearse on a private instance, then restart that instance once so the audit panel
      starts at zero receipts (deterministic demo world); do not restart the public demo
      while judges may be using it — record on a fresh private deployment of the same SHA if needed
- [ ] browser: private window, zoom 100%, bookmarks/toolbar hidden,
      public HTTPS URL visible (never present localhost as public)
- [ ] no editor and no terminal visible
- [ ] `DEMO_PUBLIC_URL=… pnpm smoke:live` = 45/45 immediately before recording
- [ ] retake any segment where a click misfires
- [ ] re-time against the real recording; trim words — not scenarios — if
      the public deployment is slower (cold did:web fetches only affect the first ~5 s)

## Timing status

The 167-token count is measured. Per-segment speech time (below) must each be at least ~1.5 s shorter than its window; the recording QA checks the real narration WAV length per segment, not only the total.

| Window | Seconds | Words | Speech at 145 wpm |
|---|---|---|---|
| 0:00–0:08 | 8 | 16 | 6.6 s |
| 0:08–0:18 | 10 | 19 | 7.9 s |
| 0:18–0:35 | 17 | 33 | 13.7 s |
| 0:35–0:50 | 15 | 28 | 11.6 s |
| 0:50–1:00 | 10 | 18 | 7.4 s |
| 1:00–1:10 | 10 | 17 | 7.0 s |
| 1:10–1:18 | 8 | 11 | 4.6 s |
| 1:18–1:30 | 12 | 20 | 8.3 s |

 The claim that each UI transition fits its
window has **not** been re-measured against the post-audit build or a public
deployment — treat the per-segment windows as targets until the recording is made.
