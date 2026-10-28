import { describe, expect, it } from 'vitest';

import { resultDigestOf, verifyAuditChain, type ActionReceipt } from '@agent-trust/audit';

import { STREAM, buildWorld, taskRequest } from './fixture.js';

describe('TrustGateway — execution-outcome receipt binds the executor result', () => {
  it('stores resultDigest = digest of the executor result, covered by chain integrity', async () => {
    const world = await buildWorld();
    const result = await world.gateway.handleTask(await taskRequest(world, { amount: 120, taskId: 'task_digest_1' }));
    expect(result.outcome).toBe('AUTHORIZED');

    const receipts = await world.auditLog.readStream(STREAM);
    const outcome = receipts.find((r) => r.body.receiptId === result.executionReceiptId)!;
    const record = world.executor.ledger.find((r) => r.taskId === 'task_digest_1')!;
    expect(outcome.body.execution?.state).toBe('SUCCEEDED');
    expect(outcome.body.execution?.resultDigest).toBe(resultDigestOf(record));

    // The digest is part of the hashed body: altering it breaks the chain at that receipt.
    expect(verifyAuditChain(STREAM, receipts).valid).toBe(true);
    const tampered: ActionReceipt[] = structuredClone(receipts);
    const idx = tampered.findIndex((r) => r.body.receiptId === result.executionReceiptId);
    tampered[idx]!.body.execution!.resultDigest = '0'.repeat(64);
    const verdict = verifyAuditChain(STREAM, tampered);
    expect(verdict.valid).toBe(false);
    if (!verdict.valid) expect(verdict.firstBrokenSequence).toBe(idx + 1);
  });

  it('a failed execution records no digest and the decision receipt has no execution block', async () => {
    const world = await buildWorld();
    const { DemoRefundExecutor } = await import('../src/executor.js');
    const { TrustGateway } = await import('../src/gateway.js');
    const executor = new DemoRefundExecutor({ failTaskIds: ['task_digest_fail'] });
    const gateway = new TrustGateway({ ...world.deps, executor });
    const result = await gateway.handleTask(await taskRequest(world, { amount: 120, taskId: 'task_digest_fail' }));
    expect(result.outcome).toBe('EXECUTION_FAILED');
    const receipts = await world.auditLog.readStream(STREAM);
    const decision = receipts.find((r) => r.body.receiptId === 'rcpt_dec_task_digest_fail')!;
    const outcome = receipts.find((r) => r.body.receiptId === 'rcpt_out_task_digest_fail')!;
    expect(decision.body.execution).toBeUndefined();
    expect(outcome.body.execution).toEqual({ state: 'FAILED' });
  });
});
