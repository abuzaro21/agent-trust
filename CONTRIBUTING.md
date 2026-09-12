# Contributing

## Ground Rules

- **Policies are code.** Changes under `policies/**/*.rego` require tests, review, and a new bundle hash — like any security-critical change.
- **Architecture decisions go through ADRs** (`docs/adr/`). If a change contradicts a frozen ADR, the ADR conversation happens first.
- **Fail-closed semantics are inviolable.** No PR may introduce a permissive fallback for a failing dependency on a write path.
- **Tests precede UI.** The dashboard is built only after `pnpm demo:e2e` proves the core (see [docs/roadmap.md](docs/roadmap.md)).

## Commits

- Imperative subject line, ≤ 72 chars.
- Body explains **why**: the problem, the intervention, and how it was verified (exact command + result).

Example:

```text
Enforce delegation depth in chain verifier

A child credential with delegationDepth equal to its parent's remaining
depth passed validation, violating Authority(child) ⊆ Authority(parent).

Track remaining depth through the recursive verifier and reject when
the budget is exhausted.

Verified: pnpm -F @agent-trust/delegation test
  → 148 passed (incl. 40 property-based cases), 0 failed
```

## Before Every PR

```text
format + lint + typecheck
unit tests
VC validation tests
delegation property tests
opa fmt / check / test
integration tests
attack tests
```

The CI gate list lives in [docs/roadmap.md](docs/roadmap.md#ci-gates) and grows per phase.

## Never Commit

Private keys or key material of any kind, `.env` files, real customer data, raw PII. The `.gitignore` blocks common formats — if you find a gap, fixing it is itself a security PR.
