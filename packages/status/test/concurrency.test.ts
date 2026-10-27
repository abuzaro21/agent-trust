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

  it('operations on different lists do not serialize behind each other incorrectly', async () => {
    await Promise.all([manager.revoke(REV_LIST, 0), manager.suspend(SUS_LIST, 0)]);
    expect((await manager.readStatus(REV_LIST, 0)).set).toBe(true);
    expect((await manager.readStatus(SUS_LIST, 0)).set).toBe(true);
  });
});
