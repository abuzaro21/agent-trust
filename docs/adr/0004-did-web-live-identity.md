# ADR-0004 — did:web for the live demo identity plane

Status: accepted (Step 12)
Date: 2026-09-15

## Context

The fabric verifies identities through the frozen `DidResolver` seam
(ADR-0001). Until now every component ran against in-memory DID documents.
A public, restartable demo needs identities whose key material is
discoverable over the open internet without running a blockchain, a
universal resolver, or a PKI: the smallest production-minded mechanism
that achieves this is **did:web** — a DID document published at an
HTTPS URL derived deterministically from the DID string.

## Decision

1. **did:web is the P0 live/demo method.** `WebDidResolver` implements the
   existing `DidResolver` seam and composes through `MultiDidResolver`
   exactly like `DidKeyResolver`. No higher layer (VC verifier, PoP check,
   gateway, attestation/checkpoint verifiers, trust profiles) branches on
   DID method — identity discovery is the only thing did:web changes.

2. **did:key stays for tests and offline fixtures.** Self-contained, no
   network, deterministic. Both methods coexist in every deployment via
   the resolver registry; unknown methods return `methodUnsupported`.

3. **did:webvh is deferred to P1** (history/versioning enhancement).
   Building it now would expand scope without demo value.

## Standards position (stated precisely)

- W3C **DID Core** is a Recommendation: the DID data model and
  architecture. `did:web` is **not** the DID Core Recommendation — it is
  an independent W3C DID **Method** specification (currently a working
  draft). This project implements the current did:web method's resolution
  rules relevant here: HTTPS derivation, percent-encoded ports, no
  query/fragment in the base DID, IP-literal prohibition, and the
  **returned-document-id must match the requested DID** requirement.

## Network trust assumptions (honesty clause)

did:web resolution inherits its trust from **DNS, TLS/CA infrastructure,
and the hosting domain operator**. It is not magically decentralized from
those systems. A domain owner controls which keys represent the DID; the
fabric's defense is layered BEHIND discovery: a DID document can prove
which public key authenticates an agent, but it can never grant
delegation, restore revoked credentials, create trusted attestations,
bypass replay protection, or override policy. That invariant is enforced
by the credential pipeline, not by the resolver, and is regression-tested
(Step 12 Gateway-compatibility suite).

Privacy: resolution contacts DNS and the DID host, which may reveal that
a DID was resolved. Anonymous resolution (DoH/Tor) is explicitly out of
P0 scope.

## Security design

- **HTTPS only** — the transport is constructed with `https:`; there is no
  HTTP fallback.
- **Strict parser before any I/O** — malformed identifiers are rejected
  deterministically (`invalidDid`) and never reach DNS or sockets; WHATWG
  URL normalization cannot resurrect an invalid DID into a different
  valid target.
- **SSRF boundary** (`NodeHttpsDidWebClient`): the derived destination is
  treated as attacker-influenced. Resolved addresses are classified
  against loopback/RFC1918/link-local/metadata/multicast/unspecified/ULA
  plus IPv4-mapped and NAT64 embedding forms; **the validated address is
  pinned for the connection** (custom `lookup`), so DNS-rebinding TOCTOU
  has no second resolution to race. Host/port allowlisting supported for
  the demo deployment.
- **Redirects are rejected** (301/302/307/308 fail resolution) — a public
  DID URL cannot bounce to an internal service.
- **Hard bounds**: timeout (default 5 s), response size (256 KiB), and
  document size (64 KiB). No uncontrolled retries.
- **Document validation**: exact `id` binding, structurally valid methods,
  absolute DID-URL method ids owned by the document, P-256/ES256 key
  profile only, **private JWK fields (`d`,`p`,`q`,`dp`,`dq`,`qi`,…) are
  rejected** — resolution is public-key discovery only. An `expectedKid`
  that is absent fails closed; the resolver never silently substitutes a
  different key.
- **No remote JSON-LD context fetching** during resolution. The fabric
  consumes only the fields it needs for cryptographic verification.

## Caching / freshness

Validated documents are cached keyed by the exact DID, with
`fetchedAt`/`expiresAt`; invalid documents and parse failures are never
cached. TTL = `min(Cache-Control max-age, maxCacheTtl)` (default cap 1 h,
default fallback 5 min) — a server can never pin a year of stale identity
state. `noCache` forces refresh (key rotation, incident response, demo
refresh). On network failure: a **fresh** cache entry MAY serve (documented
transient-outage tolerance); a **stale** entry fails closed. Key rotation
(A→B) is observable through expiry/refresh; it is distinct from credential
revocation, which remains a status-list concern.

## Key handling

`demo:did:init` generates one ES256 key per demo identity ONCE into
`.local/demo-keys/` (gitignored, mode 0600) and writes the public
documents to `.local/did-host/`. Execution paths (`demo:e2e:web`) reuse
the persisted key — the public identity is stable across restarts.
Deployment can instead supply keys via environment secret through the
unchanged `Signer` seam; Cloud KMS remains P1 behind that same seam.

## Consequences

- CI runs did:web semantics against controlled transports and address
  doubles only — never an arbitrary public internet endpoint.
- The live commands are deployment-gated by `DEMO_DID_DOMAIN`; without a
  configured host they exit with setup instructions (not a red build).
- Operational rotation becomes a plain file publish + cache expiry; no
  re-issuance ceremony for identity keys (credentials are unaffected).
