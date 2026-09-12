# ADR-0001: DID method strategy — `did:web` in P0, `did:webvh` as P1 adapter

- **Status:** Accepted (frozen)
- **Date:** 2026-09-13

## Context

We need a portable, standards-based agent identity layer. Candidates considered: `did:web`, `did:key`, `did:webvh` (and broader ledger-based methods, rejected outright for the MVP — DID Core does not require a blockchain, and one would add risk with no demo value).

`did:webvh` has real strengths — verifiable history, and it passed the DIF/ToIP Recommended DID Methods maturity review (June 2026). But it carries history/witness/resolver operational complexity that the live demo must not depend on. `did:web` resolves over plain HTTPS, is the most institutionally legible, and requires the least infrastructure.

## Decision

- **P0 (delivery):** `did:web` for all live-demo agent identities (e.g. `did:web:agents.acme.example:support-1`, resolving to HTTPS-hosted DID documents).
- **Fixtures/tests:** `did:key` — self-contained, no network, deterministic.
- **P1:** `did:webvh` via a resolver adapter implementing the shared `DidResolver` interface. No core code path may reference a concrete DID method.

## Consequences

- The `DidResolver` abstraction (`supports()` / `resolve()`) is the only seam; adding `did:webvh` later cannot touch VC, delegation, or policy code.
- We accept `did:web`'s limitations: domain control is the trust root, and there is no built-in history verifiability. For the demo's threat model this is acceptable; history-sensitive deployments get the P1 adapter.
- DID resolution inputs are untrusted: supported-method allowlist, timeouts, caching, and egress policy are mandatory from day one.
