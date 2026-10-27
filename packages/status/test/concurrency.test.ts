import { beforeEach, describe, expect, it } from 'vitest';

import { InMemoryStatusListStore, StatusListError, StatusListManager } from '../src/index.js';
import { LIST_BITS, NOW, ORG_DID, REV_LIST, SUS_LIST } from './fixture.js';

describe('StatusListManager — concurrent writers on one list (lost-update regression)', () => {
  let manager: StatusListManager;

  beforeEach(async () => {
    manager = new StatusListManager(new InMemoryStatusListStore(), { clock: () => NOW });
    await manager.createList({ id: REV_LIST, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: LIST_BITS });
    await manager.createList({ id: SUS_LIST, purpose: 'suspension', controllerDid: ORG_DID, sizeBits: LIST_BITS });
  });

  it('two concurrent revokes of different indexes both persist', async () => {
    await Promise.all([manager.revoke(REV_LIST, 0), manager.revoke(REV_LIST, 1)]);
    expect((await manager.readStatus(REV_LIST, 0)).set).toBe(true);
    expect((await manager.readStatus(REV_LIST, 1)).set).toBe(true);
  });

  it('many concurrent revokes all persist and the version advances once per operation', async () => {
    const before = (await manager.readStatus(REV_LIST, 0)).list.version;
    const indexes = Array.from({ length: 48 }, (_, i) => i);
    await Promise.all(indexes.map((i) => manager.revoke(REV_LIST, i)));
    for (const i of indexes) expect((await manager.readStatus(REV_LIST, i)).set).toBe(true);
    expect((await manager.readStatus(REV_LIST, 0)).list.version).toBe(before + 48);
  });

  it('concurrent suspend/unsuspend on different indexes keep each other', async () => {
    await manager.suspend(SUS_LIST, 5);
    await Promise.all([manager.suspend(SUS_LIST, 6), manager.unsuspend(SUS_LIST, 5), manager.suspend(SUS_LIST, 7)]);
    expect((await manager.readStatus(SUS_LIST, 5)).set).toBe(false);
    expect((await manager.readStatus(SUS_LIST, 6)).set).toBe(true);
    expect((await manager.readStatus(SUS_LIST, 7)).set).toBe(true);
  });

  it('a failing operation in the queue rejects alone and does not block or undo the others', async () => {
    const results = await Promise.allSettled([
      manager.revoke(REV_LIST, 2),
      manager.revoke(REV_LIST, 9999), // out of range
      manager.unsuspend(REV_LIST, 3), // wrong purpose
      manager.revoke(REV_LIST, 4),
    ]);
    expect(results.map((r) => r.status)).toEqual(['fulfilled', 'rejected', 'rejected', 'fulfilled']);
    expect((results[1] as PromiseRejectedResult).reason).toBeInstanceOf(StatusListError);
    expect((results[1] as PromiseRejectedResult).reason.code).toBe('INDEX_OUT_OF_RANGE');
    expect((results[2] as PromiseRejectedResult).reason.code).toBe('PURPOSE_MISMATCH');
    expect((await manager.readStatus(REV_LIST, 2)).set).toBe(true);
    expect((await manager.readStatus(REV_LIST, 4)).set).toBe(true);
    expect((await manager.readStatus(REV_LIST, 3)).set).toBe(false);
  });

  it('revocation stays permanent: unsuspend is still rejected on a revocation list', async () => {
    await manager.revoke(REV_LIST, 1);
    await expect(manager.unsuspend(REV_LIST, 1)).rejects.toMatchObject({ code: 'PURPOSE_MISMATCH' });
    expect((await manager.readStatus(REV_LIST, 1)).set).toBe(true);
  });

  it('a stalled write on one list does not block mutations of another list', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const inner = new InMemoryStatusListStore();
    const store = {
      get: (id: string) => inner.get(id),
      put: async (list: Parameters<typeof inner.put>[0]) => {
        if (list.id === REV_LIST && list.version > 1) await gate; // stall REV_LIST writes only
        return inner.put(list);
      },
    };
    const m = new StatusListManager(store, { clock: () => NOW });
    await m.createList({ id: REV_LIST, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: LIST_BITS });
    await m.createList({ id: SUS_LIST, purpose: 'suspension', controllerDid: ORG_DID, sizeBits: LIST_BITS });

    const stalled = m.revoke(REV_LIST, 0); // blocked inside put()
    await m.suspend(SUS_LIST, 0); // must complete while REV_LIST is stalled
    expect((await m.readStatus(SUS_LIST, 0)).set).toBe(true);
    expect((await m.readStatus(REV_LIST, 0)).set).toBe(false); // not yet written

    release();
    await stalled;
    expect((await m.readStatus(REV_LIST, 0)).set).toBe(true);
  });
});
