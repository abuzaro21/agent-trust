import { describe, expect, it } from 'vitest';

import { InMemoryReplayStore } from '../src/memory-store.js';
import {
  JTI_PATTERN,
  canonicalReplayNamespace,
  isValidJti,
  replayKey,
} from '../src/key.js';
import { ReplayProtector } from '../src/protector.js';
import { ReplayStoreUnavailableError } from '../src/types.js';

const NOW = 1_757_800_000;

function claim(overrides: Partial<{ namespace: string; jti: string; expiresAt: number }> = {}) {
  return {
    namespace: 'https://gateway.example/v1/evaluate\u0000did:key:zAgent#key',
    jti: 'jti-0123456789abcdef',
    expiresAt: NOW + 300,
    ...overrides,
  };
}

describe('replay key design (7D)', () => {
  it('namespaces are canonicalized and hashed — raw input never reaches the key', () => {
    const ns = canonicalReplayNamespace({
      audience: 'https://gateway.example/v1/evaluate',
      kid: 'did:key:zAgent#abc',
    });
    const key = replayKey(ns, 'jti-0123456789abcdef');
    expect(key).toMatch(/^replay:v1:[a-f0-9]{64}:jti-0123456789abcdef$/);
    expect(key).not.toContain('gateway.example');
  });

  it('different audience or kid → different key; same inputs → same key', () => {
    const a = canonicalReplayNamespace({ audience: 'https://a', kid: 'k1' });
    const b = canonicalReplayNamespace({ audience: 'https://b', kid: 'k1' });
    const c = canonicalReplayNamespace({ audience: 'https://a', kid: 'k2' });
    expect(replayKey(a, 'jti-x')).not.toBe(replayKey(b, 'jti-x'));
    expect(replayKey(a, 'jti-x')).not.toBe(replayKey(c, 'jti-x'));
    expect(replayKey(a, 'jti-x')).toBe(replayKey(canonicalReplayNamespace({ audience: 'https://a', kid: 'k1' }), 'jti-x'));
  });

  it('jti validation: bounded charset, 8–128 chars (7N)', () => {
    expect(isValidJti('jti-0123456789abcdef')).toBe(true);
    expect(isValidJti('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')).toBe(true); // 128
    expect(isValidJti('short7')).toBe(false); // < 8
    expect(isValidJti(`${'a'.repeat(129)}`)).toBe(false); // > 128
    expect(isValidJti('')).toBe(false);
    expect(isValidJti('has spaces here')).toBe(false);
    expect(isValidJti('ünïcödé-jti-1')).toBe(false);
    expect(isValidJti('../path-traversal')).toBe(false); // '/' not in charset
    expect(JTI_PATTERN.test('a'.repeat(8))).toBe(true);
  });
});

describe('InMemoryReplayStore (7B)', () => {
  it('claims once, rejects the duplicate', async () => {
    const store = new InMemoryReplayStore({ clock: () => NOW });
    expect(await store.claim(claim())).toEqual({ claimed: true });
    expect(await store.claim(claim())).toEqual({ claimed: false, reason: 'already_claimed' });
  });

  it('same jti in different namespaces does not collide', async () => {
    const store = new InMemoryReplayStore({ clock: () => NOW });
    expect(await store.claim(claim({ namespace: 'ns-A' }))).toEqual({ claimed: true });
    expect(await store.claim(claim({ namespace: 'ns-B' }))).toEqual({ claimed: true });
  });

  it('different jtis in the same namespace do not collide', async () => {
    const store = new InMemoryReplayStore({ clock: () => NOW });
    expect(await store.claim(claim({ jti: 'jti-aaaaaaaaaaaaaaaa' }))).toEqual({ claimed: true });
    expect(await store.claim(claim({ jti: 'jti-bbbbbbbbbbbbbbbb' }))).toEqual({ claimed: true });
  });

  it('expired claims free the jti (store semantics only, independent of proof validity)', async () => {
    let now = NOW;
    const store = new InMemoryReplayStore({ clock: () => now });
    expect(await store.claim(claim({ expiresAt: NOW + 10 }))).toEqual({ claimed: true });
    now = NOW + 10;
    expect(await store.claim(claim({ expiresAt: NOW + 10 }))).toEqual({ claimed: true });
  });

  it('an unexpired claim blocks reuse even as time passes within the window', async () => {
    let now = NOW;
    const store = new InMemoryReplayStore({ clock: () => now });
    await store.claim(claim({ expiresAt: NOW + 100 }));
    for (const step of [1, 25, 50, 99]) {
      now = NOW + step;
      expect(await store.claim(claim({ expiresAt: NOW + 100 }))).toEqual({
        claimed: false,
        reason: 'already_claimed',
      });
    }
  });
});

describe('ReplayProtector (7F/7E/7G)', () => {
  const base = {
    audience: 'https://gateway.example/v1/evaluate',
    kid: 'did:key:zAgent#abc',
    jti: 'jti-0123456789abcdef',
    iat: NOW - 5,
    exp: NOW + 300,
    now: NOW,
  };

  it('claims a verified proof once and reports deterministic facts', async () => {
    const protector = new ReplayProtector(new InMemoryReplayStore({ clock: () => NOW }));
    const first = await protector.verifyAndClaim(base);
    expect(first).toMatchObject({
      outcome: 'claimed',
      replayChecked: true,
      replayClaimed: true,
      retentionSeconds: 300,
    });
    const second = await protector.verifyAndClaim(base);
    expect(second).toEqual({
      outcome: 'denied',
      reasonCode: 'REPLAY_DETECTED',
      replayChecked: true,
      replayClaimed: false,
    });
  });

  it('TTL derives from the proof lifetime + skew, never a constant', async () => {
    const store = new InMemoryReplayStore({ clock: () => NOW });
    const protector = new ReplayProtector(store, { clockSkew: 30 });
    const d = await protector.verifyAndClaim({ ...base, exp: NOW + 42 });
    expect(d.outcome === 'claimed' && d.retentionSeconds).toBe(72);
  });

  it('rejects malformed jti before touching the store (7N)', async () => {
    const store = new InMemoryReplayStore({ clock: () => NOW });
    const protector = new ReplayProtector(store);
    const before = store.size;
    const d = await protector.verifyAndClaim({ ...base, jti: 'bad jti!!' });
    expect(d).toEqual({
      outcome: 'denied',
      reasonCode: 'REQUEST_MALFORMED',
      replayChecked: false,
      replayClaimed: false,
    });
    expect(store.size).toBe(before);
  });

  it('rejects ttl <= 0 (already expired beyond skew) and oversized ttl', async () => {
    const protector = new ReplayProtector(new InMemoryReplayStore({ clock: () => NOW }));
    const expired = await protector.verifyAndClaim({ ...base, exp: NOW - 1 });
    expect(expired).toMatchObject({ outcome: 'denied', reasonCode: 'VC_EXPIRED' });

    const huge = await protector.verifyAndClaim({ ...base, exp: NOW + 100_000 });
    expect(huge).toMatchObject({ outcome: 'denied', reasonCode: 'REQUEST_MALFORMED' });
  });

  it('maps store outage to REPLAY_PROTECTION_UNAVAILABLE (7K)', async () => {
    const failing: import('../src/types.js').ReplayStore = {
      async claim() {
        throw new ReplayStoreUnavailableError(new Error('connection refused'));
      },
    };
    const protector = new ReplayProtector(failing);
    const d = await protector.verifyAndClaim(base);
    expect(d).toEqual({
      outcome: 'denied',
      reasonCode: 'REPLAY_PROTECTION_UNAVAILABLE',
      replayChecked: true,
      replayClaimed: false,
    });
  });
});
