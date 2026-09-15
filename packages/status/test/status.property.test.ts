import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import { StatusBitstring } from '../src/bitstring.js';
import { InMemoryStatusListStore } from '../src/store.js';
import { StatusListError, StatusListManager } from '../src/index.js';

/**
 * Property-based status tests. The manager's clock is a counter — no
 * wall-clock dependence; fast-check prints its seed on failure.
 */

const NOW = 1_757_800_000;

function makeManager(sizeBits: number): { manager: StatusListManager; tick: () => void } {
  const store = new InMemoryStatusListStore();
  let t = NOW;
  const manager = new StatusListManager(store, { clock: () => t });
  return { manager, tick: () => { t += 1; } };
}

describe('property: index isolation', () => {
  it('revoke(A) sets A and leaves every distinct B untouched', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 8, max: 2048 }),
        fc.nat(),
        fc.nat(),
        async (sizeBitsMultiple, aSeed, bSeed) => {
          const sizeBits = sizeBitsMultiple * 8;
          const A = aSeed % sizeBits;
          let B = bSeed % sizeBits;
          if (B === A) B = (A + 1) % sizeBits;
          const { manager, tick } = makeManager(sizeBits);
          const listId = 'https://p.example/rev/1';
          await manager.createList({
            id: listId,
            purpose: 'revocation',
            controllerDid: 'did:web:p.example',
            sizeBits,
          });
          tick();
          await manager.revoke(listId, A);
          expect((await manager.readStatus(listId, A)).set).toBe(true);
          expect((await manager.readStatus(listId, B)).set).toBe(false);
        },
      ),
      { numRuns: 150 },
    );
  });
});

describe('property: revocation irreversibility', () => {
  it('revoke(index) then any restore attempt keeps the bit set', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 256 }),
        fc.nat(),
        async (sizeBytes, seed) => {
          const sizeBits = sizeBytes * 8;
          const index = seed % sizeBits;
          const { manager, tick } = makeManager(sizeBits);
          const listId = 'https://p.example/rev/1';
          await manager.createList({
            id: listId,
            purpose: 'revocation',
            controllerDid: 'did:web:p.example',
            sizeBits,
          });
          tick();
          await manager.revoke(listId, index);
          // Every restore-shaped operation is structurally rejected…
          await expect(manager.unsuspend(listId, index)).rejects.toBeInstanceOf(StatusListError);
          await expect(manager.suspend(listId, index)).rejects.toBeInstanceOf(StatusListError);
          // …and the revoked bit is still set.
          const { set } = await manager.readStatus(listId, index);
          expect(set).toBe(true);
        },
      ),
      { numRuns: 100 },
    );
  });
});

describe('property: suspension reversibility', () => {
  it('suspend(index) then unsuspend(index) → active again, version +2', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 256 }),
        fc.nat(),
        async (sizeBytes, seed) => {
          const sizeBits = sizeBytes * 8;
          const index = seed % sizeBits;
          const { manager, tick } = makeManager(sizeBits);
          const listId = 'https://p.example/susp/1';
          await manager.createList({
            id: listId,
            purpose: 'suspension',
            controllerDid: 'did:web:p.example',
            sizeBits,
          });
          tick();
          await manager.suspend(listId, index);
          expect((await manager.readStatus(listId, index)).set).toBe(true);
          tick();
          const restored = await manager.unsuspend(listId, index);
          expect((await manager.readStatus(listId, index)).set).toBe(false);
          expect(restored.version).toBe(3); // create=1, suspend=2, unsuspend=3
        },
      ),
      { numRuns: 100 },
    );
  });
});

describe('property: encode/decode roundtrip', () => {
  it('decode(encode(bits)) is semantically identical for any bit pattern', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 512 }),
        fc.array(fc.boolean(), { minLength: 0, maxLength: 4096 }),
        (sizeBytes, flags) => {
          const sizeBits = sizeBytes * 8;
          const bits = new StatusBitstring(sizeBits);
          for (let k = 0; k < flags.length; k++) {
            const index = (k * 7 + k * k) % sizeBits; // deterministic scatter
            bits.set(index, flags[k]!);
          }
          const decoded = StatusBitstring.fromBase64Url(bits.toBase64Url());
          expect(decoded.sizeBits).toBe(sizeBits);
          expect(decoded.equalsBits(bits)).toBe(true);
          for (let i = 0; i < sizeBits; i++) {
            expect(decoded.get(i)).toBe(bits.get(i));
          }
        },
      ),
      { numRuns: 150 },
    );
  });
});
