import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createClient, type RedisClientType } from 'redis';

import { RedisReplayStore } from '../src/redis-store.js';
import { InMemoryReplayStore } from '../src/memory-store.js';
import { verifyProofWithReplay } from '../src/verify-with-replay.js';
import { ReplayProtector } from '../src/protector.js';
import { LocalSigner, createProof, requestBodyDigestOf } from '@agent-trust/crypto';

const NOW = 1_757_800_000;
const HTU = 'https://gateway.example/v1/trust/evaluate';

/**
 * 7C/7I — REAL Redis integration. Skipped (never mocked) unless
 * TEST_REDIS_URL is set — e.g.
 *
 *   docker compose up -d redis
 *   TEST_REDIS_URL=redis://127.0.0.1:6379 pnpm test:integration
 *
 * CI runs it against a Redis service container. Do not fake Redis
 * atomicity with in-process doubles.
 */

const REDIS_URL = process.env.TEST_REDIS_URL;

describe.skipIf(!REDIS_URL)('RedisReplayStore — real Redis integration', () => {
  let client: RedisClientType;
  let store: RedisReplayStore;

  beforeAll(async () => {
    client = createClient({ url: REDIS_URL }) as RedisClientType;
    await client.connect();
    store = new RedisReplayStore(client, { clock: () => NOW });
  }, 15_000);

  afterAll(async () => {
    if (client) await client.quit();
  });

  beforeEach(async () => {
    await client.flushDb();
  });

  it('claims once atomically (SET NX PX), rejects the duplicate', async () => {
    const claim = { namespace: 'ns-redis-a', jti: 'jti-redis-012345678', expiresAt: NOW + 300 };
    expect(await store.claim(claim)).toEqual({ claimed: true });
    expect(await store.claim(claim)).toEqual({ claimed: false, reason: 'already_claimed' });
    // The key really is in Redis with a TTL.
    const keys = await client.keys('replay:v1:*');
    expect(keys.length).toBe(1);
    const ttlMs = await client.pTTL(keys[0]!);
    expect(ttlMs).toBeGreaterThan(0);
    expect(ttlMs).toBeLessThanOrEqual(300_000);
  });

  it('namespace isolation holds in Redis', async () => {
    const base = { jti: 'jti-redis-iso-01234567', expiresAt: NOW + 300 };
    expect(await store.claim({ ...base, namespace: 'ns-A' })).toEqual({ claimed: true });
    expect(await store.claim({ ...base, namespace: 'ns-B' })).toEqual({ claimed: true });
  });

  it('100 concurrent identical claims → exactly 1 winner (Redis is the authority)', async () => {
    const claim = { namespace: 'ns-redis-cc', jti: 'jti-redis-conc-0123456', expiresAt: NOW + 300 };
    const results = await Promise.all(
      Array.from({ length: 100 }, () => store.claim(claim)),
    );
    expect(results.filter((r) => r.claimed).length).toBe(1);
    expect(results.filter((r) => !r.claimed).length).toBe(99);
  });

  it('full path: valid signed proof consumed once through real Redis', async () => {
    const signer = LocalSigner.generate();
    const jwk = await signer.publicKey();
    const body = { actor: 'did:key:zAgent', action: 'refund:create', amount: 120 };
    const digest = requestBodyDigestOf(body);
    const proof = await createProof(signer, {
      htu: HTU,
      requestBodyDigest: digest,
      jti: 'jti-redis-full-0123456',
      iat: NOW - 5,
      exp: NOW + 300,
    });
    const protector = new ReplayProtector(store);
    const input = { proof, publicJwk: jwk, htu: HTU, requestBodyDigest: digest, now: NOW };
    const first = await verifyProofWithReplay(input, protector);
    expect(first.ok).toBe(true);
    const second = await verifyProofWithReplay(input, protector);
    expect(second).toEqual({
      ok: false,
      stage: 'replay',
      reasonCode: 'REPLAY_DETECTED',
      replayChecked: true,
    });
  });

  it('parity: InMemoryReplayStore agrees with Redis on the same sequence', async () => {
    const memory = new InMemoryReplayStore({ clock: () => NOW });
    const claim = { namespace: 'ns-parity', jti: 'jti-parity-0123456789', expiresAt: NOW + 300 };
    for (let i = 0; i < 5; i++) {
      const [m, r] = [await memory.claim(claim), await store.claim(claim)];
      expect(r).toEqual(m);
    }
  });
});
