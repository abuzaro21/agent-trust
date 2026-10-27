import { beforeEach, describe, expect, it } from 'vitest';

import { NOW_UNIX, buildWorld, canonicalNow, taskRequest, type World } from './fixture.js';

/**
 * The authority window lives inside the SIGNED delegation credential
 * (authority.validFrom/validUntil). It must reach the policy as a
 * VerifiedFact — a credential whose own lifetime is still valid but whose
 * authority window has closed (or not opened) must not authorize.
 */
describe('TrustGateway — authority validity window reaches the policy', () => {
  let world: World;
  beforeEach(async () => {
    world = await buildWorld();
  });

  async function run(authority: Record<string, unknown>, taskId: string) {
    const jws = await world.issueDelegationWith(authority);
    return world.gateway.handleTask(await taskRequest(world, { taskId, credentials: [jws] }));
  }

  it('authority inside its window → ALLOW', async () => {
    const result = await run(
      { validFrom: canonicalNow(NOW_UNIX - 600), validUntil: canonicalNow(NOW_UNIX + 600) },
      'task_win_ok',
    );
    expect(result.outcome).toBe('AUTHORIZED');
    expect(world.executor.successfulRefundCount).toBe(1);
  });

  it('authority not yet valid → DENY AUTHORITY_NOT_YET_VALID, executor untouched', async () => {
    const result = await run({ validFrom: canonicalNow(NOW_UNIX + 600) }, 'task_win_future');
    expect(result.outcome).toBe('DENIED');
    expect(result.reasonCodes).toEqual(['AUTHORITY_NOT_YET_VALID']);
    expect(result.stages.policy).toBe('DENY');
    expect(world.executor.callCount.total).toBe(0);
  });

  it('authority expired while the credential itself is still valid → DENY AUTHORITY_EXPIRED', async () => {
    const result = await run({ validUntil: canonicalNow(NOW_UNIX - 60) }, 'task_win_expired');
    expect(result.outcome).toBe('DENIED');
    expect(result.reasonCodes).toEqual(['AUTHORITY_EXPIRED']);
    expect(world.executor.callCount.total).toBe(0);
  });

  it('either bound alone, and neither bound, behave as optional', async () => {
    expect((await run({ validFrom: canonicalNow(NOW_UNIX - 60) }, 'task_win_from_only')).outcome).toBe('AUTHORIZED');
    expect((await run({ validUntil: canonicalNow(NOW_UNIX + 60) }, 'task_win_until_only')).outcome).toBe('AUTHORIZED');
    expect((await run({}, 'task_win_none')).outcome).toBe('AUTHORIZED');
    expect(world.executor.successfulRefundCount).toBe(3);
  });

  it('client-supplied temporal fields cannot stand in for the signed window', async () => {
    const req = await taskRequest(world, { taskId: 'task_win_client' });
    (req as unknown as Record<string, unknown>).authority = { validUntil: '2999-01-01T00:00:00Z' };
    const result = await world.gateway.handleTask(req);
    expect(result.reasonCodes).toEqual(['REQUEST_MALFORMED']);
    expect(world.executor.callCount.total).toBe(0);
  });
});
