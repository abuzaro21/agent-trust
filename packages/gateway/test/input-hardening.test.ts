import { beforeEach, describe, expect, it } from 'vitest';

import { verifyAuditChain } from '@agent-trust/audit';

import { createTaskRequest, type AgentTaskRequest } from '../src/request.js';
import { REFUND_AGENT_DID, STREAM, SUPPORT_AGENT_DID, buildWorld, taskRequest, type World } from './fixture.js';

/** Sign arbitrary `parameters` (the fixture only signs {amount,currency}). */
async function signed(world: World, taskId: string, parameters: unknown, action = 'refund:create'): Promise<AgentTaskRequest> {
  return createTaskRequest({
    signer: world.supportAgent,
    taskId,
    actor: SUPPORT_AGENT_DID,
    audience: REFUND_AGENT_DID,
    action,
    resource: 'order:ORD-918',
    parameters: parameters as never,
    credentials: [world.delegationJws],
    now: world.clock.now,
  });
}

async function expectSafeDenial(world: World, req: AgentTaskRequest): Promise<void> {
  const execBefore = world.executor.callCount.total;
  const receiptsBefore = (await world.auditLog.readStream(STREAM)).length;
  const result = await world.gateway.handleTask(req);
  expect(result.outcome).toBe('DENIED');
  expect(result.reasonCodes).toEqual(['REQUEST_MALFORMED']);
  expect(result.stages.execution).toBe('NOT_RUN');
  expect(world.executor.callCount.total).toBe(execBefore);
  const receipts = await world.auditLog.readStream(STREAM);
  expect(receipts.length).toBe(receiptsBefore); // malformed input never reaches the chain
  expect(verifyAuditChain(STREAM, receipts).valid).toBe(true);
}

describe('TrustGateway — refund:create input hardening (audit-chain poisoning)', () => {
  let world: World;
  beforeEach(async () => {
    world = await buildWorld();
  });

  it.each([
    ['negative', -5],
    ['zero', 0],
    ['string', 'abc'],
    ['numeric string', '120'],
    ['NaN-like string', 'NaN'],
    ['null', null],
    ['boolean', true],
    ['array', [120]],
    ['object', {}],
  ])('rejects a signed amount that is %s', async (_label, amount) => {
    await expectSafeDenial(world, await signed(world, `task_amt_${String(_label).replaceAll(' ', '_')}`, { amount, currency: 'SAR' }));
  });

  it.each([
    ['lowercase', 'sar'],
    ['too long', 'SARX'],
    ['too short', 'SA'],
    ['numeric', 123],
    ['null', null],
  ])('rejects a signed currency that is %s', async (_label, currency) => {
    await expectSafeDenial(world, await signed(world, `task_cur_${String(_label).replaceAll(' ', '_')}`, { amount: 120, currency }));
  });

  it('rejects refund:create with a missing amount, missing currency, or no parameters', async () => {
    await expectSafeDenial(world, await signed(world, 'task_no_amount', { currency: 'SAR' }));
    await expectSafeDenial(world, await signed(world, 'task_no_currency', { amount: 120 }));
    await expectSafeDenial(world, await signed(world, 'task_no_params', undefined));
  });

  it('rejects unexpected refund parameters', async () => {
    await expectSafeDenial(world, await signed(world, 'task_extra', { amount: 120, currency: 'SAR', note: 'x' }));
  });

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('rejects a non-finite %s amount injected on the wire', async (_label, amount) => {
    const req = await taskRequest(world, {
      taskId: `task_wire_${_label}`,
      mutate: (r) => {
        r.parameters = { amount, currency: 'SAR' };
      },
    });
    const execBefore = world.executor.callCount.total;
    const result = await world.gateway.handleTask(req);
    expect(result.outcome).toBe('DENIED');
    expect(world.executor.callCount.total).toBe(execBefore);
    expect(verifyAuditChain(STREAM, await world.auditLog.readStream(STREAM)).valid).toBe(true);
  });

  it('an unrelated action with unsupported parameters is denied without corrupting the chain', async () => {
    const execBefore = world.executor.callCount.total;
    const result = await world.gateway.handleTask(await signed(world, 'task_other_action', { foo: 1 }, 'ticket:close'));
    expect(result.outcome).toBe('DENIED');
    expect(world.executor.callCount.total).toBe(execBefore);
    expect(verifyAuditChain(STREAM, await world.auditLog.readStream(STREAM)).valid).toBe(true);
  });

  it('valid requests and valid denial receipts still behave correctly after malformed attempts', async () => {
    await expectSafeDenial(world, await signed(world, 'task_poison_1', { amount: -5, currency: 'SAR' }));
    const ok = await world.gateway.handleTask(await taskRequest(world, { amount: 120, taskId: 'task_after_ok' }));
    expect(ok.outcome).toBe('AUTHORIZED');
    const over = await world.gateway.handleTask(await taskRequest(world, { amount: 5000, taskId: 'task_after_over' }));
    expect(over.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    expect(over.decisionReceiptId).toBeDefined(); // valid denial receipt preserved
    const receipts = await world.auditLog.readStream(STREAM);
    expect(receipts.length).toBe(3); // decision+outcome for 120, decision for 5000
    expect(verifyAuditChain(STREAM, receipts).valid).toBe(true);
    expect(world.executor.successfulRefundCount).toBe(1);
  });

  it('a policy-engine crash denies without writing a schema-invalid receipt (chain stays valid)', async () => {
    const { TrustGateway } = await import('../src/gateway.js');
    const gateway = new TrustGateway({
      ...world.deps,
      policyEngine: { evaluate: async () => { throw new Error('wasm runtime gone'); } },
    });
    const result = await gateway.handleTask(await taskRequest(world, { taskId: 'task_pol_crash' }));
    expect(result.reasonCodes).toEqual(['POLICY_EVALUATION_ERROR']);
    expect(world.executor.callCount.total).toBe(0);
    const receipts = await world.auditLog.readStream(STREAM);
    expect(verifyAuditChain(STREAM, receipts).valid).toBe(true);
  });
});
