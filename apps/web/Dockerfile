# The Agent That Earns Trust — demo dashboard container.
#
# Build from the REPOSITORY ROOT:
#   docker build -t agent-trust-demo -f apps/web/Dockerfile .
# Run:
#   docker run -p 3000:3000 agent-trust-demo
# With real atomic replay protection:
#   docker run -p 3000:3000 -e DEMO_REDIS_URL=redis://host.docker.internal:6380 agent-trust-demo
#
# The hash-pinned policy artifact (artifacts/policy/policy.wasm) is committed
# and copied in — no OPA toolchain is needed to run the demo.

FROM node:24-alpine AS base
RUN corepack enable
WORKDIR /repo

# ---- deps: workspace manifests only (layer-cached) --------------------------
FROM base AS deps
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/schemas/package.json packages/schemas/
COPY packages/did/package.json packages/did/
COPY packages/vc/package.json packages/vc/
COPY packages/delegation/package.json packages/delegation/
COPY packages/status/package.json packages/status/
COPY packages/replay/package.json packages/replay/
COPY packages/policy/package.json packages/policy/
COPY packages/audit/package.json packages/audit/
COPY packages/gateway/package.json packages/gateway/
COPY packages/trust-profile/package.json packages/trust-profile/
COPY packages/attacks/package.json packages/attacks/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile

# ---- build: sources + committed artifacts → standalone server ---------------
FROM deps AS build
COPY packages ./packages
COPY artifacts ./artifacts
COPY apps/web ./apps/web
COPY scripts ./scripts
# Deterministic attack report baked in — the dashboard serves this artifact
# instead of running the 60-scenario suite on page load.
RUN pnpm demo:attacks
RUN pnpm build:web

# ---- runtime: standalone server + repo-root artifacts ------------------------
FROM node:24-alpine AS runtime
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
WORKDIR /app
COPY --from=build /repo/apps/web/.next/standalone ./
# Standalone does not bundle static browser assets; serve them from the cwd.
COPY --from=build /repo/apps/web/.next/static ./apps/web/.next/static
# The server locates these via findRepoRoot(): repo root must contain
# artifacts/policy/policy.wasm — /app does after this copy.
COPY --from=build /repo/artifacts/policy ./artifacts/policy
COPY --from=build /repo/artifacts/attacks ./artifacts/attacks
ENV AGENT_TRUST_REPO_ROOT=/app
EXPOSE 3000
# A root-level standalone build nests the app server under apps/web/.
CMD ["node", "apps/web/server.js"]
