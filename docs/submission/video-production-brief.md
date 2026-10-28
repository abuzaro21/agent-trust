# Video Production Brief (handoff — not yet executed)

Status: **planning only.** Nothing here has been recorded or rendered. Execution
is gated on a validated public demo (see "Preconditions"). The challenge lists the
90-second video as **optional but recommended**; the live demo URL is the required deliverable.

Two deliverables, produced by one pipeline:

| Deliverable | Length | Purpose |
|---|---|---|
| `agent-trust-judge-90s.mp4` | 85–90 s | Official walkthrough — technical credibility, real application footage |
| `agent-trust-promo-20s.mp4` | 15–25 s | Optional promotional cut via the Brag workflow — separate from the evidence video |

Output spec (both): H.264 MP4, 1920×1080, 30 fps, `yuv420p`, AAC 48 kHz stereo,
`+faststart`. Plus `agent-trust-judge-90s.srt` (sidecar) and a burned-in-caption variant.

## Preconditions (hard gate — do not start before all are true)

1. Public HTTPS demo is up; `GET /api/health` returns `build.sha` equal to the release tag SHA.
2. `GET /api/demo/status` shows `identityMode=web`, `replayStore=redis`.
3. `DEMO_PUBLIC_URL=… pnpm smoke:live` reports 45/45.
4. The three `did:web` documents resolve (HTTP 200) at their public URLs.
5. Competition brief rules on the walkthrough: the challenge page (read 2026-10-28) names a 90-second length and
   states no single-take, hosting or subtitle rule; any form-level limits beyond the URL field are **UNVERIFIED**
   (see `submission-readiness.md`).
6. Music licence for the chosen track is documented (see "Audio").

## Evidence rule

Every ALLOW/DENY shown on screen must come from the real application, captured live.
Motion graphics may only *frame* real footage (captions, zoom, highlight boxes placed from DOM
bounding boxes, title/end cards). Never draw, re-type or composite a result state. The capture script
asserts the expected reason code in the DOM after each click and aborts if it differs.

## Pipeline

1. **Capture** (Sonnet orchestrates; Haiku executes)
   - `puppeteer-core` (already a dev dependency) driving `C:\Program Files\Google\Chrome\Application\chrome.exe`
     headless, viewport 1920×1080, deviceScaleFactor 1, `--hide-scrollbars`. Headless has no cursor and no address bar: add a lower-third showing the public HTTPS URL (Opus review; the earlier plan to hide the address bar was dropped) and a standing caption "executor simulated · demo clock 2026-09-15".
   - Re-time CDP frames to a steady 30 fps from their timestamps and capture PNG/quality 100 so reason codes stay sharp.
   - Record each segment with `page.screencast` if the installed puppeteer-core supports it (needs `ffmpeg` on PATH — present, 9.0.2); fallback:
     CDP `Page.startScreencast` frames → ffmpeg.
   - Per segment: click the real preset button, wait for the result element, assert text (table below),
     hold 1.5 s, write a JSON log `{segment, startedAt, apiResponse, domAssertion}`.
   - Start from a freshly started **private** instance of the same SHA so the audit panel begins at zero receipts (do not restart the public demo while judges may be using it). Record `/api/health` `build.sha` in the capture log.
   - Never type or display secrets, tokens, `.local` paths or terminals.
2. **Narration** — English, from `loom-script.md` (167 tokens ≈ 67 s). Method: Kokoro TTS through
   Hyperframes (Brag's `--voice` path), one WAV per segment; measure each duration; if a segment overruns its
   window trim words, not scenes. Pronunciation lexicon: `did:web` → "D-I-D web", `SAR` → "S-A-R",
   `ALLOW`/`DENY` as words, `OPA` is not narrated.
3. **Composition** (Hyperframes; custom 90 s timeline — do **not** use Brag's default 15–25 s short-form plan)
   - Layers: real footage → zoom/crop moves (scale + translate only) → highlight boxes at measured
     coordinates → lower-third captions → burned subtitles → title/end cards.
   - Visual identity = the real dashboard: dark navy, mono reason codes, green ALLOW / red DENY.
4. **Audio** — voice only by default. **No music and no click SFX** (music licence unverified; scripted clicks sound fake). If a licensed track is later approved: duck ≥ 18 dB under voice. Resample Kokoro's 24 kHz output to 48 kHz.
5. **Render** — Hyperframes → MP4; then `ffmpeg` pass for `+faststart` and loudness.
6. **Validate** (all must pass; record results in `docs/submission/video-qa.md`)
   - `ffprobe`: 1920×1080, 30 fps, H.264, AAC, duration 85–90 s.
   - Loudness −16 ±2 LUFS integrated, true peak ≤ −1 dBTP; no clipping.
   - Sample a frame at each segment's result time; reason code readable and equal to the capture log.
   - Per segment: narration WAV length ≤ window − 1.5 s (not only total duration).
   - No stale result from the previous beat visible when the next beat starts.
   - Subtitles: ≤ 2 lines, ≤ 42 chars/line, in sync ±150 ms with narration.
   - Frame scan for secrets: no key material, no `localhost`, no terminal, no private paths.
   - Claim table **and the narration text itself** reviewed by Codex (read-only) against the capture log and source.
   - SHA-256 of the final MP4 and SRT recorded in `video-qa.md`.

## Segment plan (90 s) — narration is in `loom-script.md`

| Time | Real action | DOM/API assertion before moving on | On-screen text (caption) |
|---|---|---|---|
| 0:00–0:08 | Open `/`; hold on the hero and the stage | h1 "Trust is a grant, not a score."; grant strip shows `may refund up to 500 SAR` | "Who an agent is ≠ what it may do" |
| 0:08–0:18 | Highlight boxes (DOM-placed, disclosed overlay) step through AcmeOrg, the `≤ 500 SAR` grant, SupportAgent "✓ DID resolved"; open and close "Credential and identity details" | grant strip + details disclosure | "Evidence, not a score" |
| 0:18–0:35 | Click **120 SAR** | verdict "Authorized" + `WITHIN_AUTHORITY`; rows "Authorization: Allowed by policy" / "Execution: Succeeded (simulated)"; in "How it was decided" step 7 = `SUCCEEDED (simulated)`, step 8 = `RECORDED` | "120 SAR → ALLOW (simulated refund)" |
| 0:35–0:50 | Click **5,000 SAR** | verdict "Denied" + `AUTHORITY_LIMIT_EXCEEDED`; "Authorization: Denied by policy", "Execution: Not run"; then the side-by-side comparison (✓ 120 / ✕ 5,000) appears | "5,000 SAR → DENY: trusted, not for this action" |
| 0:50–1:00 | *Failure cases* → **Spoofed agent** → Run this case | card shows `IDENTITY_PROOF_INVALID`; pipeline: step 1 DENY, rest — | "Spoof → DENY" |
| 1:00–1:10 | **Revoked credential** → Run this case | card shows `CREDENTIAL_REVOKED` | "Revoked → DENY" |
| 1:10–1:18 | **Replayed request** → Run this case | "First send: AUTHORIZED · identical re-send: DENIED"; `REPLAY_DETECTED` | "Replay → DENY" |
| 1:18–1:30 | Navigate to `/attacks`; hold on banner (52 attacks + 8 failure demos); back to `/` | banner reads 60/60 | "60 security scenarios" · repo URL |

## Claims that may be narrated (and their evidence)

| Claim | Evidence | Limits to respect |
|---|---|---|
| 120 SAR allowed, 5000 SAR denied for the same agent | capture log + `/api/trust/evaluate` responses | simulated executor |
| Spoofed identity denied before policy | `IDENTITY_PROOF_INVALID`, policy NOT_RUN | — |
| Revoked credential denied | `CREDENTIAL_REVOKED` | preset revokes an isolated credential |
| Replay denied | `REPLAY_DETECTED` | server sends the identical request twice |
| 60 scenarios | `/attacks` banner (build-time report) | not computed live |

**Do not narrate:** multi-hop delegation, per-day limits, human approval, "production-ready",
"real payments", or anything about the Wasm hash being reproducible across platforms.

## Audio and licensing

- Brag 0.4.0 bundles five "Happy Beats / Business Moves" tracks from ende.app and Kenney UI SFX.
  The bundle's own README says the **exact music licence terms must be verified** — treat as
  **UNVERIFIED** for a competition submission. Before use: read the ende.app licence, record the
  URL + terms in `video-qa.md`, or substitute a track with a clearly documented licence
  (CC0 / purchased). Kenney assets are published as CC0 on kenney.nl — confirm at use time.
- Voice: Kokoro — licence not verified in this session (believed permissive); confirm the model licence text when installing.
- AI-generated narration/music must be disclosed in the submission's AI-tools note.

## Tooling readiness (checked 2026-10-28)

| Item | State |
|---|---|
| Brag 0.4.0 plugin | installed (`brag`, `brag-slim`) |
| Hyperframes | **not installed**; `npx hyperframes@0.8.209` would fetch it (needs approval + network) |
| FFmpeg | 9.0.2 present |
| Chrome | present at `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| puppeteer-core | present (dev dependency) |
| Existing screenshots | 17 PNGs in `docs/screenshots/` (desktop light and dark, tablet, mobile light and dark) regenerated from the current UI with real clicks against a local backend (`pnpm shots:live`; `08-evidence-light.png` and `17-security-tests.png` were refreshed on 2026-10-28 from the deployed build `f004ae8`). Reusable as README imagery; for the video, capture fresh footage from the deployed demo, do not reuse stills as evidence |
| Prior TOTEX video workflow | not inspected (project rules forbid touching TOTEX during this work); user to point to a copy if wanted |
| Brag on Haiku | not automatic — Brag runs on whatever model the session uses; Opus 5.5 auto-switches to `brag-slim`. Run the session/delegate on Haiku 5.5 and verify the serving model from runtime metadata |

## Model routing

Opus 5.5 reviewed this concept once (narration + visuals); its accuracy fixes (gate order, isolated revoked credential, replay framing, "52 attacks + 8 failure demos", "signed, hash-chained history") are applied in `loom-script.md`. Disagreement preserved: Opus recommends showing the public URL, `did:web` JSON loading and an audit-verify result as extra trust evidence; the plan adopts the URL lower-third and standing caption, and leaves the extra inserts optional because they add scenes beyond the 90 s budget. Opus also advised against music, SFX and drawn cursors — adopted. Sonnet 5.5 orchestrates and owns quality gates.
Haiku 5.5 executes capture/compose/render. Codex GPT-6.1 Sol verifies narrated claims (read-only).
One delegate at a time; at most one corrected retry per task.

## Promo cut (20 s, optional)

Brag workflow, no voice or a 1-line voice, same palette. Beats: hook "Trust is not a score" (0–2 s) →
120 ALLOW / 5000 DENY real clips (2–9 s) → spoof / revoke / replay strip (9–14 s) → 60/60 + repo CTA
(14–20 s). Same evidence rule; clips are cut from the judge-video captures.
