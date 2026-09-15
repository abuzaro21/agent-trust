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
docker run -d -p 3000:3000 --env-file ./live.secrets.env agent-trust-demo
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
nothing secret reaches HTTP responses or browser bundles either.
