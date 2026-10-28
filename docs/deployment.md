# Deployment (Step 16) — Public Challenge Demo

The demo ships as one Docker image (`apps/web/Dockerfile`) plus one external
Redis. This document is the complete operational contract.

## Required end state (judge path)

```text
Public HTTPS URL → Trust Profile → 120 SAR ALLOW → 5000 SAR DENY
                 → spoof / revoked / replay denials → /attacks 60/60
```

## Environment contract

| Variable | Required | Meaning |
|---|---|---|
| `NODE_ENV` | prod | `production` |
| `PORT` / `HOSTNAME` | platform default | standalone server bind (`3000`, `0.0.0.0`) |
| `DEMO_IDENTITY_MODE` | **web (public demo)** | `web`: org/support/refund are REAL `did:web` identities resolved over public HTTPS by the hardened resolver. `fixture`: local in-memory identities (dev). Misconfiguration **fails startup — no silent fallback** (16H). |
| `DEMO_DID_DOMAIN` | when mode=web | Host serving the published `did.json` files (e.g. `abuzaro21.github.io`). Encoded ports use `%3A`. |
| `DEMO_ORG_KEY_JSON` / `DEMO_SUPPORT_KEY_JSON` / `DEMO_REFUND_KEY_JSON` | when mode=web | Private JWK per identity (output of `pnpm demo:did:init` / `LocalSigner.exportPrivateJwk()`). **Deployment secrets only** — never committed, never baked into the image, never sent to the browser. Stable across restarts (16C): the server loads them, it never (re)generates them. |
| `DEMO_REDIS_URL` | public demo | `redis://…`. If configured and unreachable at boot, startup **fails** (no in-memory downgrade). Runtime outages deny with `REPLAY_PROTECTION_UNAVAILABLE` (fail-closed) and auto-reconnect recovers when Redis returns. |
| `AGENT_TRUST_REPO_ROOT` | container=`/app` | Where `artifacts/policy/policy.wasm` (+`artifacts/attacks/`) live. |
| `DEMO_BUILD_SHA` | recommended | Short commit SHA exposed via `/api/health` + `/api/demo/status` so reviewers correlate demo↔commit (16O). |
| `DEMO_SKIP_SELF_RESOLUTION` | only if provider hairpin is impossible | Skips the in-process self-resolution proof (16I). It does NOT weaken the SSRF policy; external verification (smoke / `demo:did:resolve`) still proves public resolution. |

### Identity publishing

`DEMO_DID_DOMAIN=abuzaro21.github.io pnpm demo:did:init` writes:

- private keys → `.local/demo-keys/` (gitignored — this is the secret source)
- public documents → `.local/did-host/agents/{org,support,refund}/did.json`

Publish the `did-host` tree so each document sits at its derived URL
(`https://<domain>/agents/<name>/did.json`). This repo's identities are
published at **https://github.com/abuzaro21/abuzaro21.github.io** (the
`abuzaro21.github.io` Pages site — public keys only; no `.key.json` file
exists there). Cache-Control stays bounded (Pages sends `max-age=600`; the
resolver additionally caps its own cache at 10 min) so emergency key
rotation propagates in minutes (16F/16AL).

## State model (Pre-step review A)

| Component | Backing | Notes |
|---|---|---|
| Replay claims | **Redis** (`SET NX PX`) | external, survives app restarts (TTL-bounded) |
| Audit log / Action Receipts | in-memory | deterministic seed rebuilt at startup |
| Demo executor | in-memory simulation | no real payment movement (16S) |
| Status lists / quarantine | in-memory | revocation demo uses ISOLATED credentials |
| Trust Profile evidence | derived at request time | rebuilt from stores + fresh checkpoint |
| Attestation stores | in-memory seeded evidence | |
| Policy engine | baked hash-pinned Wasm | from the image |
| Attack report | baked at image build | 60/60 served statically |

**Consequence:** `replicas = 1` (see `deploy/fly.example.toml`). Do not
scale horizontally while authoritative demo state is process-local.
Production evolution would move audit/demo state to a transactional store
(Postgres) — deliberately out of P0 scope (16A).

## Restart semantics (Pre-step review B)

- Redis replay entries: survive (managed persistence) — proven by the
  web-restart rehearsal: replay claims stayed denied after restart.
- Audit/demo/profile state: **reset and deterministically reseeded** at
  startup. The UI says so honestly: "Challenge Demo Environment". No
  durable enterprise history is claimed.

## Deploying (any Docker host)

```bash
# 1) image (from repo root)
docker build -t agent-trust-demo -f apps/web/Dockerfile .
# 2) one app replica + external redis; secrets via the platform secret store
#    (env-file example below is LOCAL REHEARSAL only — .local/ is gitignored)
docker run -d -p 3000:3000 --env-file ./.local/live.secrets.env agent-trust-demo
# 3) verify exactly what a judge will experience
DEMO_PUBLIC_URL=https://<host> pnpm smoke:live
```

Templates: `deploy/fly.example.toml` (Fly.io: single machine, `/api/health`
check, managed Redis), `docker-compose.demo.yml` (+ `docker-compose.live.yml`
overlay for web identity mode). `smoke:live` is the deployment regression
gate (16AA/16Z): 45 checks incl. public DID resolution, judge scenarios,
leak scans of API responses + HTML + JS bundles.

## Public status (honesty statement, Step 16Y blocker rules)

The full public deployment (host + DNS + secrets custody) requires a cloud
account with billing credentials. As of this step the environment has no
provider CLI/token available (verified: flyctl/railway/render/heroku/vercel/
gcloud/az/doctl absent; docker credential store empty; AWS SSO token expired
2026-06-10). **Missing credential: a hosting provider login (e.g. Fly.io or
Railway). No public URL is invented.** Everything deployable is committed:
image, manifests, env contract, live-mode code, and the public did:web
identities themselves (GitHub Pages needs no billing). The live rehearsal
(`docker compose … up` + `smoke:live` 45/45) exercises the identical
configuration that goes public once a provider login exists — run the three
commands above and it is that demo.

## Abuse scope (16S/16W/16V)

This is a challenge demo, not an open financial endpoint: the only protected
execution is `DemoRefundExecutor` (simulation), all inputs are synthetic
(synthetic order IDs, fixed preset amounts; no PII), every normal run uses
fresh per-request task/jti so concurrent judges cannot collide (16U), and
the revoked/quarantine presets isolate or ref-count their state. No
application-level rate limiter is built; prefer platform edge limits (e.g.
Fly/railwall) if the host provides them.

## Logging hygiene (16X)

Server logs carry only taskId/reasonCode/receiptId/build SHA and transport
errors. No private JWK JSON, no Redis URLs/credentials, no environment dumps
are logged anywhere in the request path; the smoke's leak-scan step proves
nothing secret reaches the responses it fetches, the HTML shell or the (up to 12) JS bundles it can download — a best-effort scan, not a proof of absence.

## Hosting requirements (measured / derived)

| Item | Requirement | Evidence |
|---|---|---|
| App | **One** container replica of `apps/web/Dockerfile` (never scale out) | state is process-local (see State model) |
| CPU / RAM | 1 shared vCPU, 256 MB is sufficient | web container used ~51 MiB RSS after the 8 presets (Docker stats, local); image 330 MB |
| Redis | Redis **≥ 6** (the node-redis 6 client sends `HELLO`; a Redis 3.x server fails with `ERR unknown command 'HELLO'`). `redis:7-alpine` is what CI and the compose demo use. Persistence optional (claims are TTL-bounded) but recommended so replay denials survive a Redis restart | local Redis 3.0.504 failed the integration test; Redis 7 passed 5/5 |
| Network | inbound HTTPS → container port 3000; outbound HTTPS to the DID host (`DEMO_DID_DOMAIN`) | the web-mode resolver fetches `https://<domain>/agents/<name>/did.json` |
| Runtime user | the image runs as **root** (no `USER` in the Dockerfile) — acceptable for a synthetic-data demo; adding `USER node` is a recommended hardening, not done here to avoid changing a verified image | `docker exec … id` → uid 0 |

## Secrets and key handling

- Env names (values never go in Git, the image, logs or chat): `DEMO_ORG_KEY_JSON`, `DEMO_SUPPORT_KEY_JSON`,
  `DEMO_REFUND_KEY_JSON` (private JWKs), `DEMO_REDIS_URL` (may contain credentials).
- Source of the keys: `pnpm demo:did:init` writes them to `.local/demo-keys/` (gitignored). They must be the **same**
  keys whose public halves are published in the `did.json` files — a mismatch makes the live resolver reject the identities.
- Keep the env file ONLY under `.local/` (gitignored and excluded from Docker contexts) — any other filename may be committed or copied into an image. Load it through the provider's import mechanism (for Fly: `fly secrets import < .local/live.secrets.env`)
  rather than typing values on the command line or into shell history.
- A public `did.json` must contain no `d` member; `smoke:live` scans responses, HTML and JS bundles for key material.
- Rotation / suspected exposure: `demo:did:init` **reuses** an existing `.local/demo-keys/<name>.key.json`, so first delete (or move
  away) the key file of every affected identity, then run `demo:did:init` to mint replacements, republish the new `did.json` files,
  import the new secrets and redeploy. The resolver caches at most 10 minutes, so rotation propagates within that window.

## Release deployment procedure

1. **Preflight (on the release commit):** `git status` clean; `git rev-parse --short HEAD` = `<SHA>`; typecheck + tests green;
   do **not** run `pnpm build:policy` (the committed `policy.wasm` is hash-pinned and rebuilding on another platform changes it).
2. **Manifest:** copy `deploy/fly.example.toml` to `fly.toml`; set the app name/region and `DEMO_DID_DOMAIN=abuzaro21.github.io`.
   Keep `[http_service] min_machines_running = 1`, `auto_stop_machines = "off"`, and a single machine.
3. **Redis:** create a managed Redis ≥ 6; take its URL (a secret).
4. **Secrets:** import `DEMO_REDIS_URL`, the three `DEMO_*_KEY_JSON` and `DEMO_BUILD_SHA=<SHA>` from the gitignored env file.
5. **Deploy:** `fly deploy` (builds `apps/web/Dockerfile`; the image runs `test:attacks` — which fails the build on any failed scenario — and `build:web`). Then `fly scale count 1` and confirm `fly status` shows exactly one machine.
6. **Verify outside-in (all must pass before recording anything):**
   - `curl -s https://<host>/api/health` → `status: ok`, `identityMode: web`, `build.sha` = `<SHA>`.
   - `curl -s https://<host>/api/demo/status` → HTTP 200 with `identityMode: web`, `replayStore: redis`. (`/api/health` is **liveness only** — it does not load keys, Redis or the policy; `/api/demo/status` builds the world and is the readiness check. A misconfigured key/Redis/DID host fails at this request, not at process start.)
   - `curl -s -o /dev/null -w '%{http_code}' https://abuzaro21.github.io/agents/{org,support,refund}/did.json` → `200` each.
   - `DEMO_PUBLIC_URL=https://<host> pnpm smoke:live` → the documented 45 checks, **zero FAIL** (any FAIL blocks submission).
   - Click through the 8 presets and `/attacks` once by hand.
7. **Record** the walkthrough against this deployment (see `docs/submission/video-production-brief.md`), then create the tag
   `builders-league-submission-v1` on `<SHA>` and fill the form.

## Rollback

- **Bad release:** redeploy the previous image (`fly releases` to find it, then `fly deploy --image <previous image>`); no data to
  migrate — audit/profile state is rebuilt at start and replay claims are TTL-bounded.
- **Take the demo offline immediately:** `fly scale count 0` (or stop the container). Nothing else depends on it.
- **Key exposure:** follow "Rotation" above; then redeploy.
- **Wrong public DID documents:** revert the commit in the `abuzaro21.github.io` Pages repo (public keys only).
- Never roll forward by scaling to more than one replica.

## Reproducibility assessment (release verification, 2026-10-28)

| Question | Finding |
|---|---|
| Does the image build from a clean checkout? | **Yes** — built from a git worktree with `--frozen-lockfile` (pnpm 11.1.1 via corepack); build-time `demo:attacks` and `build:web` succeed |
| Is the shipped policy the committed one? | **Yes** — `sha256sum /app/artifacts/policy/policy.wasm` inside the image equals `artifacts/policy/manifest.json` (`c0248310…eea8`) |
| Is the image byte-for-byte reproducible? | **No** — `FROM node:24-alpine` is a floating tag (no digest pin) and layers carry timestamps; pin the digest for a stricter release |
| Is `policy.wasm` reproducible across machines? | Only per platform: rebuilding with OPA 1.20.2 on Windows produced `28b7918e…` instead of the committed `c0248310…`. The committed artifact is authoritative; never regenerate it during release |
| Does the compose demo start and serve the real gateway? | **Yes** — see the verification record |

## Verification record (release branch)

Executed locally (Windows 11, Docker 29.9.2, Node 24, OPA 1.20.2). `PASS` = executed and passed; `NOT RUN` = not executed; `BLOCKED` = could not run here.

| Gate | Result |
|---|---|
| TypeScript typecheck | PASS |
| Default `pnpm test` (OPA on PATH) | PASS — 480/480 in 46 files (435 package tests + the 45 `apps/web` tests); without OPA: 470 pass + 10 skipped |
| `pnpm test:frontend` (the `apps/web` subset alone) | PASS — 45/45 (5 files) |
| Redis integration (disposable `redis:7-alpine`) | PASS — 5/5 |
| OPA fmt / check / test | PASS — 13/13 |
| Adversarial suite | PASS — 60/60 (52 attacks + 8 failure demos) |
| Production web build | PASS |
| Docker image build (`apps/web/Dockerfile`) | PASS — 330 MB; the build now runs `test:attacks` (60/60 inside the image) so a failed scenario fails the build |
| Compose demo (`docker-compose.demo.yml` + Redis 7) | PASS — started on a free host port (3000 was occupied by an unrelated local container, which was not touched); `/api/health` ok, `replayStore: redis` |
| Demo presets (8) against the container | PASS — same reason codes as documented |
| Malformed-input exploit (`amount` −5 / 0 / "abc", `currency` "SARX") against the container | PASS — `REQUEST_MALFORMED`, no receipt, audit `chain.valid: true` |
| `GET /api/attacks/report?run=1` | PASS — serves the stored artifact; runs nothing |
| `smoke:live` (45 checks) | BLOCKED — needs private keys and a public URL |
| Public HTTPS deployment | NOT RUN |

Known cosmetic caveat: the `/attacks` page badge `baseline 414cbaa` is a historical constant in `packages/attacks/src/runner.ts`
(the commit the suite was first baselined at), **not** the build SHA — do not narrate it as the deployed commit.

## Alternative host: Render free plan (planned, not deployed)

`render.yaml` at the repository root is a Blueprint for the free plan (Docker runtime, single instance, `autoDeployTrigger: "off"`,
`PORT=3000` pinned, secrets as `sync: false`). It has **not** been applied or validated against Render (`render blueprints validate`
needs a logged-in workspace); only its YAML syntax was checked.

Facts from Render's public docs (checked 2026-10-28) that affect this demo:

- A Free web service **spins down after 15 minutes without traffic** and takes about one minute to start again; Render may also
  restart it at any time. Process-local demo state (audit/profile/status) therefore resets more often than on an always-on host.
- 750 free instance-hours per workspace per month: one always-on service fits (744 h), several do not; spun-down services use none.
- No persistent disk; one instance only (matches the single-replica requirement).
- Render's free Key Value is **in-memory only** (data lost on restart) and limited to one per workspace — an external Redis with
  persistence and TLS (`rediss://`) is preferable for replay claims. The client verifies certificates: against a TLS-only Redis the
  5 Redis integration tests pass with a trusted CA and fail closed with an untrusted one (tested locally).
- Free-instance bandwidth/build-minute allowances were not stated on Render's pages — read them from the dashboard.
- Whether the Free plan accepts the Docker runtime is not stated on the pages read; confirm at first deploy.
