# Submission readiness — The Agent That Earns Trust

**Status (2026-10-29): NOT SUBMITTED.** The release is deployed and was re-verified on 2026-10-29 (author-run: `/api/health` build `f004ae8`, `identityMode web`; `/api/demo/status` `replayStore redis`; `smoke:live` 45/45; public DID documents resolve with public keys only; rendered `/attacks` shows the stored 60/60 report with its build-time notice). The 90-second video is complete (see section 4). The DOO form has not been submitted and no form field has been filled. This page records the verified release metadata, the current official requirements (with sources), and what still has to happen. It is documentation only.

## 1. Verified release

| Item | Value |
|---|---|
| Public repository | https://github.com/abuzaro21/agent-trust |
| Live demo (required) | https://agent-trust.onrender.com |
| Production commit | `f004ae818cdbba9f8183d35f2147d318a73d1a42` (`f004ae8`), a regular merge commit of PR #3 |
| Production tree | `50b2c85e0500ca605f6cb2c1fe64fb82c4e6189f` (identical to the audited PR head `2f554ee`) |
| Render deployment | `dep-dbh4jf8n74is73bjpeb0` — created 2026-10-28T19:15:09Z, live 19:17:07Z; service on the Free plan, auto-deploy **off** |
| GitHub CI on `main` at `f004ae8` | success — https://github.com/abuzaro21/agent-trust/actions/runs/40750984910 |
| Policy artifact | `policy.wasm` SHA-256 `c0248310…eea8`, equal to the committed manifest (unchanged) |

Who verified what (kept separate on purpose):

- **GitHub CI** (on the merge commit): typecheck, Rego format/check/native tests, policy-artifact integrity, unit/property tests, web tests + production build, the attack suite, Redis integration.
- **Author-run, against the live deployment:** `/api/health` build `f004ae8` with `identityMode web`; `/api/demo/status` with `identityMode web` and `replayStore redis`; `pnpm smoke:live` **45/45**; a real-click browser check of the public site **15/15** (120 SAR authorized and executed in simulation, 5,000 SAR denied with the executor not run, comparison, spoof / revoked / replay, audit chain and signed checkpoint valid, mobile); a real-browser check of the public `/attacks` page and claim wording **15/15**; a scan of 400 build-log and 150 runtime-log entries with no real errors and no secret patterns.
- **Independent Codex review (read-only, repository code):** final bounded round on `2f554ee` returned APPROVE FOR PR; it re-ran typecheck, the 662 tests, the 60 scenarios, OPA and the Wasm digest, and reproduced its named negative controls. It did not run Redis, the production build or the browser check, and did not test the live service.
- **Stored attack-suite report served at `/attacks`:** 60/60 (52 attacks + 8 failure demos), generated when the container image was built; the page does not re-run it.

## 2. Official requirements — read 2026-10-28

Primary source (signed-in view, including the submit form; the submit button was **not** used): https://build.doo.ooo/challenges/agent-earns-trust. Homepage: https://build.doo.ooo/.

| # | Question | Finding | Evidence |
|---|---|---|---|
| 1 | Deadline and timezone | **November 15, 2026.** The page's metadata says the mission is open until that date and a live countdown read "18d 4h left" at 2026-10-28 19:25Z, which implies a close around the end of Nov 15 UTC (23:25Z–00:25Z window). **No timezone is stated — UNVERIFIED.** Plan to submit well before Nov 15 (in any timezone). | challenge-page `<meta name="description">` (open until Nov 15, 2026); countdown text on the page |
| 2 | Is the 90-second video mandatory? | **Optional, but recommended.** The submission checklist marks the 90-second walkthrough "optional, but recommended", the submit form labels that field optional, and the form states: "A live demo URL is required. The video walkthrough is optional." The deliverables list and the homepage nevertheless describe a 90-second demo as part of the entry, and the *Demo quality* criterion asks that the decision be visible and explainable in 90 seconds. | challenge page: Deliverables, Submission Checklist, Submit form; homepage hero requirements line (lists a 90-second demo among the items to ship) |
| 3 | Repository and live URL | Public repo URL (GitHub or GitLab; a clean clone must run). **Live demo URL is required** (a working link anyone can open). | challenge page: Submission Checklist; the repo-URL and live-demo-URL form fields (the latter labelled required) |
| 4 | Architecture snapshot | Deliverable: a diagram of identity → claims → verification → policy. No dedicated form field. | challenge page: Deliverables |
| 5 | Failure demonstration | Deliverable: a malicious or spoofed agent tries to act and trust catches it. No dedicated form field. Scoring: *Failure thinking* (15) — concrete, defended attack scenario. | challenge page: Deliverables, scoring table |
| 6 | Two-year thesis | **≤ 300 words** on agent identity and reputation. No dedicated form field. Repo thesis: 293 words (296 with the title). | challenge page: Deliverables |
| 7 | Release tag | **Not mentioned anywhere on the page — not required.** No tag has been created. | challenge page (no tag, release or version requirement) |
| 8 | Other fields / evidence | The form has four fields: repo URL, live demo URL (required), Loom/video (optional), and notes (what to look at, AI usage, decisions). Disqualifiers: a reputation score with no mechanism; no demo of a trust-gated decision. Bonus signals: DIDs/VCs standards; cross-agent demo. A Builders League account is required. **Notes limit: 2,000 characters** (the notes field's `maxlength`, read 2026-10-29; the URL fields have no client-side length or pattern limit). Any server-side validation: **UNVERIFIED**. | challenge page (re-read 2026-10-29: fields, checklist and "17d 8h left" countdown unchanged) |

**Discrepancies observed (not errors on our side):**

- The homepage still shows an Aug 31, 2026 deadline in two places and mentions eight open missions while showing three cards. The challenge page (countdown and metadata) says Nov 15, 2026; treat the challenge page as current.
- The video is a deliverable in one place and optional in another. The form and checklist (the operative submission surface) say optional.
- The thesis, architecture snapshot and failure test have no form fields, so they must be reachable from the repository and the notes.

## 3. Submission package

| Item | Where |
|---|---|
| GitHub URL | https://github.com/abuzaro21/agent-trust |
| Live demo URL | https://agent-trust.onrender.com (build `f004ae8`) |
| Architecture snapshot | [architecture.md](architecture.md) (one screen: identity → claims → verification → authority → policy → provenance); long form [../architecture.md](../architecture.md) |
| Trust-gated decision demo | live page `/#demo` — 120 SAR authorized and executed in simulation vs 5,000 SAR denied (`AUTHORITY_LIMIT_EXCEEDED`) with the comparison built from the two real responses |
| Failure demonstrations | live page `/#failures` (spoofed identity, revoked credential, replayed request; three more behind a disclosure) and `/attacks` (60 scenarios, 52 attacks + 8 failure demos); threat model [../threat-model.md](../threat-model.md); assurance account [../security-assurance.md](../security-assurance.md) |
| Two-year thesis | [two-year-thesis.md](two-year-thesis.md) — 293 words (296 with the title), under the 300 limit |
| AI tools and decisions | [ai-tools-and-decisions.md](ai-tools-and-decisions.md); out of scope: [out-of-scope.md](out-of-scope.md) |
| Limitations (stated, not hidden) | simulated refund executor (no money moves); frozen demo clock; shared in-memory, process-local audit/profile/status state that resets on restart; checkpoints signed by the demo's own signer with no external anchor; single delegation link through the gateway; `perDay` not enforced; no human-in-the-loop; public API signs demo requests server-side. See [final-submission.md](final-submission.md) and the threat model |
| Requirement-to-evidence map | [judge-checklist.md](judge-checklist.md) |
| Copy/paste form text | [final-submission.md](final-submission.md) "Form data" |

## 4. Video status

**Complete (2026-10-29).** The 90-second film (release candidate RC3) was approved by the author: https://youtu.be/z4uGR81ybV4. It shows real footage of the public demo (build `f004ae8`, captured 2026-10-28) and labelled explanatory motion graphics, with **AI-generated narration (Chatterbox TTS)**; the refund execution shown is simulated. Record, transcript, disclosures and file hashes: [video.md](video.md). The video field on the form is optional; this URL goes there.

## 5. Remaining blockers and tasks

Blockers (must be done by the owner before the deadline; none can be done by documentation):

1. **Submit the entry** through the signed-in form on the challenge page (not done). Fields: repo URL, live demo URL, video URL (https://youtu.be/z4uGR81ybV4), notes (≤ 2,000 characters).
2. **Re-verify the public URL immediately before submitting** (free-plan sleep; demo state resets on restart): `/api/health` build `f004ae8`, `/api/demo/status`, `corepack pnpm smoke:live` with `DEMO_PUBLIC_URL=https://agent-trust.onrender.com` → 45/45.

Open decisions / non-blocking:

3. ~~Decide whether to record the optional 90-second video~~ — done: the film is complete (section 4).
4. Confirm the deadline timezone if it matters (UNVERIFIED); until then treat Nov 15 as ending no later than the start of Nov 15 in the earliest timezone you care about, and submit early.
5. The `DEMO_BUILD_SHA` environment variable on Render is stale and ignored by the app (it prefers Render's own commit metadata); removing it is optional hygiene and was not done.
6. Deferred, non-blocking: an allocation limit for the attack-suite evidence snapshot (documented in [../security-assurance.md](../security-assurance.md)).
