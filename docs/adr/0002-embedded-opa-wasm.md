# ADR-0002: Rego compiled to OPA Wasm, embedded in the service process

- **Status:** Accepted (frozen)
- **Date:** 2026-09-13

## Context

We need a policy layer that emits structured decisions (not booleans) with deterministic reason codes, and we must decide between running OPA as a network sidecar/service or embedding it. Cedar was also evaluated: strong for principal/action/resource schemas, but weaker for building the rich trust/explanation object around arbitrary evidence; kept as a possible future adapter, not MVP.

## Decision

- Policies are authored in **Rego** under `policies/` and treated as code (reviewed, tested, versioned).
- CI compiles them: `opa build -t wasm` → `policy.wasm` + `policyManifest.json`, hashed with **SHA-256**.
- The Fastify trust-gateway process loads the Wasm module **in-process** via a `PolicyEngine` interface — no OPA container, no HTTP hop.
- Every decision records `policyVersion` + `policyHash`.
- If the bundle is missing, invalid, or fails to initialize: **write actions fail closed**. There is no permissive fallback.

## Consequences

- (+) Fewer moving parts for the live demo; no extra network hop or cold-start; simpler deployment (no OPA service to operate or secure).
- (+) Rego outputs structured objects, which is exactly what our decision/reason-code contract needs.
- (−) We lose OPA-service management features (decision logs UI, bundle service), so we own policy lifecycle explicitly: compilation, versioning, hashing, and decision logging are first-class code in `packages/policy-engine`.
- Rego receives **only pre-verified facts** from the verification plane; it is never a cryptographic parser.
