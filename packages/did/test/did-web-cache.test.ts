import { describe, expect, it } from 'vitest';

import { WebDidResolver, type DidWebHttpClient, type DidWebHttpResponse } from '../src/index.js';

/**
 * Step 12Q–12U — cache semantics and key rotation, all with an injected
 * clock (no sleeps). Cache stores ONLY fully validated documents; TTL is
 * bounded by maxCacheTtl regardless of server Cache-Control; fresh cache
 * serves through transient network failure; stale cache fails closed.
 */

const DID = 'did:web:trust.example.com:agents:support';
const KEY_A = { kty: 'EC', crv: 'P-256', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', y: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' };
const KEY_B = { kty: 'EC', crv: 'P-256', x: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', y: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' };

function docFor(key: { x: string; y: string }) {
  return {
    id: DID,
    verificationMethod: [{ id: `${DID}#key-1`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: key }],
  };
}

function docOf(jwk: { x: string; y: string }, kid = 'key-1') {
  return {
    id: DID,
    verificationMethod: [{ id: `${DID}#${kid}`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: jwk }],
  };
}

function clientOf(responder: (url: URL) => Promise<DidWebHttpResponse>): DidWebHttpClient {
  return { get: responder };
}

describe('cache semantics (12Q–12T)', () => {
  it('valid response is cached; second lookup within TTL makes NO network call', async () => {
    let calls = 0;
    const clock = { now: 1_000_000 };
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      http: clientOf(async () => {
        calls += 1;
        return { status: 200, headers: {}, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    await resolver.resolve(DID);
    await resolver.resolve(DID);
    await resolver.resolve(DID);
    expect(calls).toBe(1);
    expect(resolver.peekCache(DID)?.expiresAt).toBeGreaterThan(clock.now);
  });

  it('noCache (force refresh) bypasses a fresh cache entry → network called', async () => {
    let calls = 0;
    const clock = { now: 1_000_000 };
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      http: clientOf(async () => {
        calls += 1;
        return { status: 200, headers: {}, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    await resolver.resolve(DID);
    await resolver.resolve(DID, { noCache: true });
    expect(calls).toBe(2);
  });

  it('TTL expiry triggers a network call again (injected clock, no sleeps)', async () => {
    let calls = 0;
    const clock = { now: 1_000_000 };
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      defaultCacheTtlMs: 60_000,
      http: clientOf(async () => {
        calls += 1;
        return { status: 200, headers: {}, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    await resolver.resolve(DID);
    clock.now += 59_000;
    await resolver.resolve(DID);
    expect(calls).toBe(1); // still fresh
    clock.now += 2_000; // past expiry
    await resolver.resolve(DID);
    expect(calls).toBe(2);
  });

  it('Cache-Control max-age is honored but CAPPED by maxCacheTtl (12R)', async () => {
    const clock = { now: 1_000_000 };
    // Server demands a year of caching; policy says 10 minutes max.
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      maxCacheTtlMs: 600_000,
      http: clientOf(async () => ({
        status: 200,
        headers: { 'cache-control': 'max-age=31536000' },
        body: JSON.stringify(docFor(KEY_A)),
      })),
    });
    await resolver.resolve(DID);
    const entry = resolver.peekCache(DID)!;
    expect(entry.expiresAt - entry.fetchedAt).toBe(600_000);
  });

  it('EXPLICIT max-age=0 → immediately stale: never cached as fresh (emergency-rotation semantics)', async () => {
    // Pre-Step-13 review found the old behavior installed a 1 ms "fresh"
    // entry — under key compromise the server publishing max-age=0 must
    // WIN, so the next resolution always re-fetches.
    let calls = 0;
    const clock = { now: 1_000_000 };
    const resolver = new WebDidResolver({
      clock: () => clock.now, // frozen: a fresh-cache shortcut would show here
      http: clientOf(async () => {
        calls += 1;
        return { status: 200, headers: { 'cache-control': 'max-age=0' }, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    const r1 = await resolver.resolve(DID);
    expect(r1.didDocument?.id).toBe(DID);
    expect(resolver.peekCache(DID)).toBeUndefined();
    await resolver.resolve(DID);
    expect(calls).toBe(2); // re-fetched — the stale marker is honored
  });

  it('max-age=0 + network failure → FAIL CLOSED (no cache to fall back to)', async () => {
    let broken = false;
    const clock = { now: 1_000_000 };
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      http: clientOf(async () => {
        if (broken) throw new Error('ECONNRESET');
        return { status: 200, headers: { 'cache-control': 'max-age=0' }, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    await resolver.resolve(DID);
    broken = true;
    const r = await resolver.resolve(DID);
    expect(r.didDocument).toBeNull();
  });

  it('no Cache-Control header → bounded defaultCacheTtl applies (documented)', async () => {
    const clock = { now: 1_000_000 };
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      defaultCacheTtlMs: 30_000,
      http: clientOf(async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify(docFor(KEY_A)),
      })),
    });
    await resolver.resolve(DID);
    const entry = resolver.peekCache(DID)!;
    expect(entry.expiresAt - entry.fetchedAt).toBe(30_000);
  });

  it('invalid response (wrong id) is NEVER cached; a later valid response succeeds (12V poisoning)', async () => {
    let calls = 0;
    const clock = { now: 1_000_000 };
    let serveEvil = true;
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      http: clientOf(async () => {
        calls += 1;
        if (serveEvil) return { status: 200, headers: {}, body: JSON.stringify({ ...docFor(KEY_A), id: 'did:web:evil.example' }) };
        return { status: 200, headers: {}, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    const r1 = await resolver.resolve(DID);
    expect(r1.didDocument).toBeNull();
    expect(resolver.peekCache(DID)).toBeUndefined();
    serveEvil = false;
    const r2 = await resolver.resolve(DID);
    expect(r2.didDocument?.id).toBe(DID);
    expect(calls).toBe(2);
  });

  it('fresh cache + network failure → fresh cache MAY serve (documented 12T)', async () => {
    const clock = { now: 1_000_000 };
    let broken = false;
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      defaultCacheTtlMs: 60_000,
      http: clientOf(async () => {
        if (broken) throw new Error('ECONNRESET');
        return { status: 200, headers: {}, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    await resolver.resolve(DID);
    broken = true;
    // Cache-hit path: the fresh entry serves without even attempting the network.
    const r = await resolver.resolve(DID);
    expect(r.didDocument?.id).toBe(DID);
    // Explicit force-refresh + network failure: the fresh entry may still
    // serve, with the documented degradation message.
    const refreshed = await resolver.resolve(DID, { noCache: true });
    expect(refreshed.didDocument?.id).toBe(DID);
    expect(refreshed.didResolutionMetadata.message).toContain('fresh cache');
  });

  it('stale cache + network failure → FAIL CLOSED (12T)', async () => {
    const clock = { now: 1_000_000 };
    let broken = false;
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      defaultCacheTtlMs: 60_000,
      http: clientOf(async () => {
        if (broken) throw new Error('ECONNRESET');
        return { status: 200, headers: {}, body: JSON.stringify(docFor(KEY_A)) };
      }),
    });
    await resolver.resolve(DID);
    clock.now += 120_000; // cache now stale
    broken = true;
    const r = await resolver.resolve(DID);
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.message).toContain('fail closed');
  });

  it('parse failures are not cached as valid results', async () => {
    const clock = { now: 1_000_000 };
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      http: clientOf(async () => ({ status: 200, headers: {}, body: '{broken json' })),
    });
    await resolver.resolve(DID);
    expect(resolver.peekCache(DID)).toBeUndefined();
  });
});

describe('key rotation (12U)', () => {
  it('document v1 (key A) → resolve; v2 (key B) after TTL expiry → key B resolves, key A is gone', async () => {
    const clock = { now: 1_000_000 };
    let current: unknown = docFor(KEY_A);
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      defaultCacheTtlMs: 60_000,
      http: clientOf(async () => ({ status: 200, headers: {}, body: JSON.stringify(current) })),
    });

    const v1 = await resolver.resolve(DID);
    expect(v1.didDocument?.verificationMethod?.[0]?.publicKeyJwk).toEqual(KEY_A);

    // Server rotates: key A removed, key B installed.
    current = docFor(KEY_B);
    clock.now += 61_000; // past TTL → fresh fetch
    const v2 = await resolver.resolve(DID);
    expect(v2.didDocument?.verificationMethod?.[0]?.publicKeyJwk).toEqual(KEY_B);

    // force refresh gives the same result even BEFORE expiry.
    current = docFor(KEY_A);
    const v3 = await resolver.resolve(DID, { noCache: true });
    expect(v3.didDocument?.verificationMethod?.[0]?.publicKeyJwk).toEqual(KEY_A);
  });

  it('overlap: document with A+B → both kids resolve; removal of A observable after refresh', async () => {
    const clock = { now: 1_000_000 };
    let current: unknown = {
      id: DID,
      verificationMethod: [
        { id: `${DID}#key-a`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: KEY_A },
        { id: `${DID}#key-b`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: KEY_B },
      ],
    };
    const resolver = new WebDidResolver({
      clock: () => clock.now,
      defaultCacheTtlMs: 60_000,
      http: clientOf(async () => ({ status: 200, headers: {}, body: JSON.stringify(current) })),
    });

    const overlap = await resolver.resolve(DID);
    expect(overlap.didDocument?.verificationMethod).toHaveLength(2);

    current = docOf(KEY_B, 'key-b'); // A removed
    const rotated = await resolver.resolve(DID, { noCache: true });
    expect(rotated.didDocument?.verificationMethod).toHaveLength(1);
    expect(rotated.didDocument?.verificationMethod?.[0]?.id).toBe(`${DID}#key-b`);
  });
});
