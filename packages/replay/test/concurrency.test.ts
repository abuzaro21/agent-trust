import { describe, expect, it } from 'vitest';

import { InMemoryReplayStore } from '../src/memory-store.js';
import type { ReplayClaim } from '../src/types.js';

const NOW = 1_757_800_000;

const sameClaim: ReplayClaim = {
  namespace: 'https://concurrency.example/eval\u0000did:key:zAgent#k',
  jti: 'jti-concurrent-012345678',
  expiresAt: NOW + 300,
};

/**
 * 7I — mandatory concurrency invariant: for a given namespace + jti,
 * EXACTLY ONE concurrent claim succeeds. The in-memory store's
 * check-and-set is synchronous within one event-loop turn, so N parallel
 * claims (one macrotask each) cannot interleave.
 */
describe('concurrency: at-most-once under parallel claims', () => {
  it('100 concurrent identical claims → exactly 1 claimed', async () => {
    const store = new InMemoryReplayStore({ clock: () => NOW });
    const results = await Promise.all(
      Array.from({ length: 100 }, () => store.claim(sameClaim)),
    );
    const winners = results.filter((r) => r.claimed);
    const losers = results.filter((r) => !r.claimed && r.reason === 'already_claimed');
    expect(winners.length).toBe(1);
    expect(losers.length).toBe(99);
  });

  it('1000 concurrent claims across mixed namespaces/jtis keep isolation', async () => {
    const store = new InMemoryReplayStore({ clock: () => NOW });
    const claims = Array.from({ length: 1000 }, (_, i) => ({
      namespace: `ns-${i % 7}`,
      jti: `jti-mix-${String(i).padStart(6, '0')}`,
      expiresAt: NOW + 300,
    }));
    const results = await Promise.all(claims.map((c) => store.claim(c)));
    expect(results.filter((r) => r.claimed).length).toBe(1000);
    // Every distinct (namespace, jti) claimed exactly once; duplicates of
    // each would have been rejected.
    const secondRound = await Promise.all(claims.map((c) => store.claim(c)));
    expect(secondRound.filter((r) => r.claimed).length).toBe(0);
  });

  it('sequential bursts after expiry can reclaim exactly once per window', async () => {
    let now = NOW;
    const store = new InMemoryReplayStore({ clock: () => now });
    const c = { ...sameClaim, expiresAt: NOW + 5 };
    expect((await store.claim(c)).claimed).toBe(true);
    now = NOW + 1;
    expect((await store.claim(c)).claimed).toBe(false);
    now = NOW + 5; // window over
    expect((await store.claim(c)).claimed).toBe(true);
  });
});
