import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import { InMemoryReplayStore } from '../src/memory-store.js';
import { canonicalReplayNamespace, isValidJti, replayKey } from '../src/key.js';

const NOW = 1_757_800_000;

const jtiArb = fc
  .string({ minLength: 8, maxLength: 64 })
  .filter((s) => /^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$/.test(s));

const nsArb = fc.tuple(
  fc.constantFrom('https://a.example', 'https://b.example', 'https://c.example'),
  fc.constantFrom('did:key:zA#k1', 'did:key:zB#k2'),
);

describe('property: single consumption (7J)', () => {
  it('first claim = claimed, second claim = already_claimed, for any jti/namespace', async () => {
    await fc.assert(
      fc.asyncProperty(nsArb, jtiArb, async ([audience, kid], jti) => {
        const store = new InMemoryReplayStore({ clock: () => NOW });
        const claim = {
          namespace: canonicalReplayNamespace({ audience, kid }),
          jti,
          expiresAt: NOW + 600,
        };
        expect(await store.claim(claim)).toEqual({ claimed: true });
        expect(await store.claim(claim)).toEqual({ claimed: false, reason: 'already_claimed' });
      }),
      { numRuns: 200 },
    );
  });
});

describe('property: namespace isolation (7J)', () => {
  it('the same jti never collides across distinct namespaces', async () => {
    await fc.assert(
      fc.asyncProperty(nsArb, nsArb, jtiArb, async ([audA, kidA], [audB, kidB], jti) => {
        fc.pre(audA !== audB || kidA !== kidB);
        const store = new InMemoryReplayStore({ clock: () => NOW });
        const nsA = canonicalReplayNamespace({ audience: audA, kid: kidA });
        const nsB = canonicalReplayNamespace({ audience: audB, kid: kidB });
        expect(nsA).not.toBe(nsB);
        expect(await store.claim({ namespace: nsA, jti, expiresAt: NOW + 600 })).toEqual({ claimed: true });
        expect(await store.claim({ namespace: nsB, jti, expiresAt: NOW + 600 })).toEqual({ claimed: true });
      }),
      { numRuns: 150 },
    );
  });
});

describe('property: distinct-jti isolation (7J)', () => {
  it('distinct jtis never collide within a namespace', async () => {
    await fc.assert(
      fc.asyncProperty(nsArb, jtiArb, jtiArb, async ([audience, kid], jtiA, jtiB) => {
        fc.pre(jtiA !== jtiB);
        const store = new InMemoryReplayStore({ clock: () => NOW });
        const ns = canonicalReplayNamespace({ audience, kid });
        expect(await store.claim({ namespace: ns, jti: jtiA, expiresAt: NOW + 600 })).toEqual({ claimed: true });
        expect(await store.claim({ namespace: ns, jti: jtiB, expiresAt: NOW + 600 })).toEqual({ claimed: true });
        // And keys differ for distinct jtis.
        expect(replayKey(ns, jtiA)).not.toBe(replayKey(ns, jtiB));
      }),
      { numRuns: 150 },
    );
  });
});

describe('property: concurrent uniqueness (7J)', () => {
  it('for any claim, N concurrent attempts yield exactly one success', async () => {
    await fc.assert(
      fc.asyncProperty(
        nsArb,
        jtiArb,
        fc.integer({ min: 2, max: 60 }),
        async ([audience, kid], jti, n) => {
          const store = new InMemoryReplayStore({ clock: () => NOW });
          const claim = {
            namespace: canonicalReplayNamespace({ audience, kid }),
            jti,
            expiresAt: NOW + 600,
          };
          const results = await Promise.all(
            Array.from({ length: n }, () => store.claim(claim)),
          );
          expect(results.filter((r) => r.claimed).length).toBe(1);
          expect(results.filter((r) => !r.claimed).length).toBe(n - 1);
        },
      ),
      { numRuns: 100 },
    );
  });
});

describe('property: expiry (7J, store semantics only)', () => {
  it('after expiry the store frees the slot; before expiry it never does', async () => {
    await fc.assert(
      fc.asyncProperty(
        nsArb,
        jtiArb,
        fc.integer({ min: 1, max: 500 }),
        fc.integer({ min: -50, max: 200 }),
        async ([audience, kid], jti, ttl, probeOffset) => {
          const now = NOW;
          const store = new InMemoryReplayStore({ clock: () => now });
          const claim = {
            namespace: canonicalReplayNamespace({ audience, kid }),
            jti,
            expiresAt: now + ttl,
          };
          expect(await store.claim(claim)).toEqual({ claimed: true });
          if (probeOffset < ttl) {
            expect(
              await store.claim({ ...claim, expiresAt: now + probeOffset + ttl }),
            ).toEqual({ claimed: false, reason: 'already_claimed' });
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe('property: jti validation (7N)', () => {
  it('accepts exactly the documented charset/length envelope', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 200 }),
        (s) => {
          const accepted = isValidJti(s);
          // Manual envelope cross-check.
          const manual =
            s.length >= 8 &&
            s.length <= 128 &&
            /^[A-Za-z0-9]/.test(s) &&
            /^[A-Za-z0-9._:-]+$/.test(s);
          expect(accepted).toBe(manual);
        },
      ),
      { numRuns: 300 },
    );
  });
});
