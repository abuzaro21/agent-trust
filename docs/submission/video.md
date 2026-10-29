# 90-second video: final film record

**Status (2026-10-29): complete and approved by the author (release candidate RC3).**

- **Watch:** VIDEO_URL_PENDING (YouTube, unlisted: anyone with the link can watch, no sign-in needed)
- **Verified:** VIDEO_VERIFIED_PENDING

This is a documentation record. The film is not stored in this repository, and the application was not changed or redeployed to make it.

## What the film shows

The film is 90 seconds long and follows the canonical demo run on the public deployment:
1. **The grant:** the AcmeOrg → SupportAgent delegation, signed, scoped and limited to 500 SAR.
2. **120 SAR, authorized:** the 120 SAR request is authorized and the simulated refund runs.
3. **5,000 SAR, refused in full:** it is ten times the signed limit, and the executor does not run.
4. **How it was decided:** the four checks in order, then a deterministic policy.
5. **Three failures, each stopped:** a spoofed identity, a revoked credential and a replayed request.
6. **The 60-scenario report and the two-year thesis.**

| Element | What it is |
|---|---|
| Screens tagged **LIVE CAPTURE** | Real screen recordings of https://agent-trust.onrender.com: build `f004ae8`, captured 2026-10-28, with capture logs and passing assertions. The responses come from the running application, with nothing mocked or fabricated. The only additions are crops, highlight boxes and captions that restate what is on screen. |
| Screens tagged **ILLUSTRATION** | Original explanatory motion graphics: the agent, the grant, the "to scale" comparison of 120 SAR and 5,000 SAR against the 500 SAR limit, the thesis and the title. |
| Refund execution | **Simulated.** `DemoRefundExecutor` moves no money, and the film says so. |
| 60/60 report | The stored report generated when the container image was built (52 attacks and 8 failure demos), as served by `/attacks`. It is not re-run when the page opens, and the film's caption says this. |

## Narration as spoken (transcript; same as the caption track)

> An agent can prove who it is. What it may do is granted. AcmeOrg lets SupportAgent refund up to five hundred Saudi riyals. A hundred and twenty: inside the limit. Policy allows it, and a simulated refund runs. Ten times the limit. The identity was valid. The credential was valid. Five thousand was never granted. Four checks, in order. Then a deterministic policy decides. An impostor is stopped at the first check. A revoked credential. A replayed request. Sixty security scenarios, checked against their expected behavior. As agents start acting across organizations, this question becomes infrastructure. Trust is a grant. Not a score.

This narration was written for the produced edit and replaces the earlier draft in [loom-script.md](loom-script.md).

## Narration, AI use and production

- **Narration:** an AI-generated voice made with **Chatterbox TTS** 0.1.7 (Resemble AI, MIT licence), run locally with its built-in voice. There is no voice cloning, and Resemble's imperceptible Perth watermark is kept in the audio. All 13 lines were checked by speech recognition (Whisper small.en): each scored 100 % word accuracy, measured on the final mix.
- **Production:**
  - **Remotion** 4.0.539 (React and TypeScript, under the free individual licence).
  - Fonts: Instrument Serif, Geist and Geist Mono (SIL OFL 1.1).
  - Music and sound effects are original, synthesized for the film with no samples.
- **AI tools:** see [ai-tools-and-decisions.md](ai-tools-and-decisions.md#the-90-second-video-october-2026).

## File record

| Item | Value |
|---|---|
| Final file | `AgentTrust-Film-90s-RC3.mp4`, H.264 High, 1920×1080, 30 fps, 2,700 frames, 90.000 s; AAC-LC 48 kHz stereo |
| SHA-256 (MP4) | `da0520ce32909f28984aede7b56c37a8053437e7817b3144a91e90ed1a8deef4` |
| English captions | `AgentTrust-Film-90s-RC3.en.srt`, 13 cues, SHA-256 `a4f6323a5a0ae822c250875b946f918b0fbff4b3d1a11731993f1c42301291fa` (uploaded as the YouTube caption track) |
| Audio | −17.1 LUFS integrated, true peak −1.57 dBTP, 0 clipped samples |
| Independent review | Codex (GPT-6.1 Sol, read-only) checked the factual claims, the audio and the final timing pass. It found the evidence frames unchanged between releases and rated the film ready for the author's review. The author then watched and approved it. |

The editable production (the Remotion project, audio pipeline, lossless masters, release candidates and reviews) is kept outside the repository, in the author's working folder `agent-trust-remotion-film`.

## Limits of the film
- **Picture vs live service:** the film shows the build `f004ae8` as captured on 2026-10-28. The live service may differ later, but this document records the build it shows.
- **Narration:** the narration is synthetic, and a faint breathiness from the voice model is audible on some lines. The author accepted this.
- **Simplifications:** the "to scale" illustration simplifies the policy decision into a single amount comparison. The real decision is made by the policy described in [architecture.md](architecture.md).
