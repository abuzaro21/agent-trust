import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';

import { buildWorld, taskRequest, type World } from './fixture.js';

describe('gateway property tests', () => {
  let world: World;

  beforeAll(async () => {
    world = await buildWorld();
  });

  it('amount boundary: any amount ≤ 500 executes; any amount > 500 denies with the exact code; executor NEVER runs on deny', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 500 }),
        fc.integer({ min: 501, max: 100_000 }),
        fc.integer({ min: 0, max: 2 ** 31 - 1 }),
        async (under, over, seed) => {
          const w = await buildWorld(); // isolated ledger per case
          const underResult = await w.gateway.handleTask(
            await taskRequest(w, { amount: under, taskId: `task_under_${seed}` }),
          );
          expect(underResult.outcome).toBe('AUTHORIZED');
          const overResult = await w.gateway.handleTask(
            await taskRequest(w, { amount: over, taskId: `task_over_${seed}` }),
          );
          expect(overResult.outcome).toBe('DENIED');
          expect(overResult.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
          expect(w.executor.callCount.total).toBe(1); // only the ALLOW ran
        },
      ),
      { numRuns: 30 },
    );
  }, 120_000); // each case builds a real world (Wasm engine + keys)

  it('stage ordering invariants: policy NOT_RUN whenever identity/replay/credential/authority fails', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('spoof', 'tamper', 'no-credentials', 'garbage-credential'),
        fc.integer({ min: 0, max: 2 ** 31 - 1 }),
        async (attack, seed) => {
          const w = await buildWorld();
          const request = await taskRequest(w, {
            taskId: `task_${attack}_${seed}`,
            ...(attack === 'spoof' ? { actor: SUPPORT_ACTOR, signer: w.evilAgent } : {}),
            amount: 120,
            ...(attack === 'tamper'
              ? { mutate: (r: Parameters<typeof taskRequest>[1] extends infer O ? O extends { mutate?: (req: infer M) => void } ? M : never : never) => { (r as { parameters?: { amount?: number; currency?: string } }).parameters = { amount: 9999, currency: 'SAR' }; } }
              : {}),
            ...(attack === 'no-credentials' ? { credentials: [] } : {}),
            ...(attack === 'garbage-credential' ? { credentials: ['not.a.jws'] } : {}),
          });
          const result = await w.gateway.handleTask(request);
          expect(result.outcome).toBe('DENIED');
          if (
            result.stages.identity === 'FAIL' ||
            result.stages.replay === 'FAIL' ||
            result.stages.credential === 'FAIL' ||
            result.stages.authority === 'FAIL'
          ) {
            expect(result.stages.policy).toBe('NOT_RUN');
            expect(result.stages.execution).toBe('NOT_RUN');
          }
        },
      ),
      { numRuns: 40 },
    );
  });

  it('same taskId idempotency: direct double execution yields one logical refund (10Z)', async () => {
    const w = await buildWorld();
    const action = {
      taskId: 'task-idem-123',
      actorDid: 'did:web:agents.acme.example:support-1',
      audienceDid: 'did:web:payments.example:refund-agent',
      action: 'refund:create',
      resource: 'order:ORD-918',
      parameters: { amount: 120, currency: 'SAR' },
      decisionReceiptId: 'rcpt_direct_01',
    };
    const first = await w.executor.execute(action);
    const second = await w.executor.execute(action);
    expect(first.state).toBe('SUCCEEDED');
    expect(second.state).toBe('SUCCEEDED');
    expect(second).toEqual({ ...first, detail: 'idempotent-replay' });
    expect(w.executor.successfulRefundCount).toBe(1);
    expect(w.executor.ledger.length).toBe(1);
  });

  it('fresh proofs never collide: N distinct task requests all authorize', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 2, max: 8 }), async (n) => {
        const w = await buildWorld();
        for (let i = 0; i < n; i++) {
          const result = await w.gateway.handleTask(
            await taskRequest(w, { amount: 100 + i, taskId: `task_multi_${i}` }),
          );
          expect(result.outcome).toBe('AUTHORIZED');
        }
        expect(w.executor.successfulRefundCount).toBe(n);
      }),
      { numRuns: 20 },
    );
  });
});

const SUPPORT_ACTOR = 'did:web:agents.acme.example:support-1';
