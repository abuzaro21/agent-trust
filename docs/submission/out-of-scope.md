# Out of Scope (deliberate)

The challenge goal was to **prove the trust mechanism**, not to build an
entire identity platform. These were considered and consciously excluded;
each exclusion is a scope statement, not an oversight.

| Not built | Why it stayed out |
|---|---|
| Full OAuth 2.0 / OIDC authorization server | Delegation credentials already carry scoped, attenuated, revocable authority natively; adding a token-exchange layer would demo a mechanism, not prove one |
| SPIFFE/SPIRE workload identity | Solves intra-mesh identity; this project's point is cross-organizational, cryptographic, portable identity |
| did:webvh / other DID methods | One method, fully hardened (SSRF-pinned transport, exact binding, bounded cache), beats three half-safe ones; the resolver seam (ADR-0001) makes another method an addition, not a redesign |
| A2A protocol integration | Orthogonal transport concern; the gateway validates protocol-agnostic signed requests |
| MCP integration | Agent-runtime plumbing; none of the trust semantics change |
| Postgres (or any) durable audit persistence | P0 demo state is in-memory + external Redis replay, honestly labeled and single-replica; a DB would add an availability story without adding proof |
| Kubernetes / multi-region | Directly contradicts the pinned single-replica correctness requirement |
| Cloud KMS / HSM signing | The `Signer` seam already isolates key custody; demo keys are local secrets held as deployment env only |
| BBS+ / zero-knowledge credentials | Selective-disclosure crypto is a credentials-plane upgrade; the enforcement pipeline consumes any verified credential the same way |
| Blockchain / transparency log / Rekor | A signed checkpoint over the hash-chained receipts already supports the claims made; public anchoring is a future verification surface, not a P0 requirement |
| ML reputation scoring | **The anti-goal.** A score can't be verified, scoped, or revoked; the entire thesis is that trust is evidence, not a number |
| Real payment/refund integration | The protected execution is `DemoRefundExecutor` (simulation) — making real payments contingent on this demo was never in scope |
| Multi-tenant admin / RBAC console | One org, one policy, one stream — governance surfaces were not the mechanism being proved |
| Application rate limiting / accounts / billing | Public demo with synthetic inputs and per-request fresh task/jti; edge limits belong to the host, not the fabric |

What the P0 instead spent its scope on: making every included layer
**actually correct** — 425 core tests, 27 frontend tests, 5 Redis
integration tests, 13 native Rego tests, 60/60 adversarial scenarios,
CI-gated on every push.
