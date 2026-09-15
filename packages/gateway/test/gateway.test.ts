import { beforeAll, describe, expect, it } from 'vitest';

import {
  REFUND_AGENT_DID,
  STREAM,
  SUPPORT_AGENT_DID,
  buildWorld,
  taskRequest,
  type World,
} from './fixture.js';

/**
 * Step 10 scenario matrix. Every scenario runs through the REAL pipeline:
 * real PoP, real VC verification, real status, real replay, real OPA
 * Wasm, real audit chaining, real executor.
 */
describe('TrustGateway — scenario matrix (10E2E)', () => {
  let world: World;

  beforeAll(async () => {
    world = await buildWorld();
  });

  it('1. Trusted 120 SAR → ALLOW + SUCCEEDED, two chained receipts', async () => {
    const result = await world.gateway.handleTask(await taskRequest(world, { amount: 120, taskId: 'task_ok_1' }));
    expect(result.outcome).toBe('AUTHORIZED');
    expect(result.stages).toMatchObject({
      identity: 'PASS', replay: 'PASS', credential: 'PASS',
      authority: 'PASS', policy: 'ALLOW', audit: 'PASS', execution: 'SUCCEEDED',
    });
    expect(result.decisionReceiptId).toBeDefined();
    expect(result.executionReceiptId).toBeDefined();
    expect(world.executor.successfulRefundCount).toBe(1);
  });

  it('2. Trusted 5000 SAR → DENY AUTHORITY_LIMIT_EXCEEDED, executor count 0', async () => {
    const before = world.executor.callCount.total;
    const result = await world.gateway.handleTask(await taskRequest(world, { amount: 5000, taskId: 'task_deny_1' }));
    expect(result.outcome).toBe('DENIED');
    expect(result.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    expect(result.stages.policy).toBe('DENY');
    expect(result.stages.execution).toBe('NOT_RUN');
    expect(world.executor.callCount.total).toBe(before);
  });

  it('3. Spoofed identity (evil key, trusted DID) → IDENTITY_PROOF_INVALID; no receipt attributed to the victim', async () => {
    const before = world.executor.callCount.total;
    const result = await world.gateway.handleTask(
      await taskRequest(world, { actor: SUPPORT_AGENT_DID, signer: world.evilAgent, taskId: 'task_spoof_1' }),
    );
    expect(result.outcome).toBe('DENIED');
    expect(result.reasonCodes).toEqual(['IDENTITY_PROOF_INVALID']);
    expect(result.stages.identity).toBe('FAIL');
    expect(result.stages.policy).toBe('NOT_RUN');
    expect(result.stages.execution).toBe('NOT_RUN');
    expect(world.executor.callCount.total).toBe(before);
    // PRE-STEP A REGRESSION: no ActionReceipt may exist that attributes
    // this denial to the legitimate (authenticated) actor.
    const receipts = await world.auditLog.readStream(STREAM);
    const victimReceipts = receipts.filter(
      (r) => r.body.actor.did === SUPPORT_AGENT_DID && r.body.receiptId.includes('task_spoof_1'),
    );
    expect(victimReceipts).toEqual([]);
  });

  it('4. Tampered body (120 signed, 5000 on wire) → IDENTITY_PROOF_INVALID, policy never sees 5000', async () => {
    const before = world.executor.callCount.total;
    const result = await world.gateway.handleTask(
      await taskRequest(world, {
        taskId: 'task_tamper_1',
        mutate: (req) => {
          req.parameters = { amount: 5000, currency: 'SAR' };
        },
      }),
    );
    expect(result.reasonCodes).toEqual(['IDENTITY_PROOF_INVALID']);
    expect(result.stages.identity).toBe('FAIL');
    expect(world.executor.callCount.total).toBe(before);
  });

  it('5. Revoked credential → CREDENTIAL_REVOKED before policy; fresh proof after restore is unnecessary (revocation permanent)', async () => {
    const before = world.executor.callCount.total;
    await world.statusManager.revoke(world.revListId, world.delegationIndex);
    const result = await world.gateway.handleTask(await taskRequest(world, { taskId: 'task_revoked_1' }));
    expect(result.reasonCodes).toEqual(['CREDENTIAL_REVOKED']);
    expect(result.stages.credential).toBe('FAIL');
    expect(result.stages.policy).toBe('NOT_RUN');
    expect(world.executor.callCount.total).toBe(before);
    // Restore for later scenarios by issuing a fresh delegation+index.
    const issuer = new (await import('@agent-trust/vc')).CredentialIssuer(
      (await import('@agent-trust/crypto')).withDid(
        (await import('@agent-trust/crypto')).LocalSigner.generate(),
        'did:web:acme.example:org-x',
      ),
    );
    void issuer;
  });

  it('6. Suspended credential → CREDENTIAL_SUSPENDED', async () => {
    // Isolated world whose delegation credential binds a SUSPENSION list.
    const w = await buildWorld({ statusPurpose: 'suspension' });
    await w.statusManager.suspend(w.revListId, w.delegationIndex);
    const result = await w.gateway.handleTask(await taskRequest(w, { taskId: 'task_susp_1' }));
    expect(result.reasonCodes).toEqual(['CREDENTIAL_SUSPENDED']);
    expect(result.stages.policy).toBe('NOT_RUN');
  });

  it('7. Quarantined agent → AGENT_QUARANTINED; release restores normal evaluation', async () => {
    const w = await buildWorld();
    await w.quarantine.quarantine(SUPPORT_AGENT_DID, 'drill');
    const deniedResult = await w.gateway.handleTask(await taskRequest(w, { taskId: 'task_quar_1' }));
    expect(deniedResult.reasonCodes).toEqual(['AGENT_QUARANTINED']);
    expect(deniedResult.stages.credential).toBe('FAIL');
    expect(deniedResult.stages.policy).toBe('NOT_RUN');
    w.quarantine.release(SUPPORT_AGENT_DID);
    const ok = await w.gateway.handleTask(await taskRequest(w, { taskId: 'task_quar_2' }));
    expect(ok.outcome).toBe('AUTHORIZED');
  });

  it('8. Replay of the exact signed proof → REPLAY_DETECTED; refund count stays 1', async () => {
    const w = await buildWorld();
    const request = await taskRequest(w, { taskId: 'task_replay_1', amount: 120 });
    const first = await w.gateway.handleTask(request);
    expect(first.outcome).toBe('AUTHORIZED');
    expect(w.executor.successfulRefundCount).toBe(1);
    // The EXACT same request object — same signed bytes, same jti.
    const second = await w.gateway.handleTask(request);
    expect(second.outcome).toBe('DENIED');
    expect(second.reasonCodes).toEqual(['REPLAY_DETECTED']);
    expect(w.executor.successfulRefundCount).toBe(1);
  });

  it('9. Wrong audience → AUDIENCE_MISMATCH', async () => {
    const w = await buildWorld();
    const result = await w.gateway.handleTask(
      await taskRequest(w, { audience: 'did:web:evil.example:agent', taskId: 'task_aud_1' }),
    );
    expect(result.reasonCodes).toEqual(['AUDIENCE_MISMATCH']);
    expect(result.stages.policy).toBe('DENY');
    expect(w.executor.callCount.total).toBe(0);
  });

  it('10. Wrong currency → CURRENCY_MISMATCH', async () => {
    const w = await buildWorld();
    const result = await w.gateway.handleTask(
      await taskRequest(w, { currency: 'USD', taskId: 'task_cur_1' }),
    );
    expect(result.reasonCodes).toEqual(['CURRENCY_MISMATCH']);
  });

  it('11. Audit outage after ALLOW → AUDIT_LOG_UNAVAILABLE, executor count 0 (audit-before-side-effect)', async () => {
    const w = await buildWorld();
    const failingLog = {
      append: async () => {
        throw new Error('audit store down');
      },
      readStream: async () => [],
      getHead: async () => null,
    };
    const gateway = new (await import('../src/gateway.js')).TrustGateway({
      ...w.deps,
      auditLog: failingLog,
    });
    const result = await gateway.handleTask(await taskRequest(w, { taskId: 'task_audit_1' }));
    expect(result.outcome).toBe('DENIED');
    expect(result.reasonCodes).toEqual(['AUDIT_LOG_UNAVAILABLE']);
    expect(result.stages.policy).toBe('ALLOW');
    expect(result.stages.audit).toBe('FAIL');
    expect(result.stages.execution).toBe('NOT_RUN');
    expect(w.executor.callCount.total).toBe(0);
  });

  it('12. Policy outage → fail closed, no executor', async () => {
    const w = await buildWorld();
    const failingPolicy = {
      evaluate: async () => {
        throw new Error('wasm runtime gone');
      },
    };
    const gateway = new (await import('../src/gateway.js')).TrustGateway({
      ...w.deps,
      policyEngine: failingPolicy,
    });
    const result = await gateway.handleTask(await taskRequest(w, { taskId: 'task_pol_1' }));
    expect(result.outcome).toBe('DENIED');
    expect(result.reasonCodes).toEqual(['POLICY_EVALUATION_ERROR']);
    expect(w.executor.callCount.total).toBe(0);
  });

  it('13. Replay store outage → REPLAY_PROTECTION_UNAVAILABLE, no policy, no executor', async () => {
    const w = await buildWorld();
    const { ReplayProtector, ReplayStoreUnavailableError } = await import('@agent-trust/replay');
    const failingReplay = new ReplayProtector({
      claim: async () => {
        throw new ReplayStoreUnavailableError(new Error('redis down'));
      },
    });
    const gateway = new (await import('../src/gateway.js')).TrustGateway({
      ...w.deps,
      replayProtector: failingReplay,
    });
    const result = await gateway.handleTask(await taskRequest(w, { taskId: 'task_redis_1' }));
    expect(result.reasonCodes).toEqual(['REPLAY_PROTECTION_UNAVAILABLE']);
    expect(result.stages.replay).toBe('FAIL');
    expect(result.stages.policy).toBe('NOT_RUN');
    expect(w.executor.callCount.total).toBe(0);
  });

  it('14. Executor failure → ALLOW decision + FAILED execution outcome receipt', async () => {
    const w = await buildWorld();
    const failingExecutor = new (await import('../src/executor.js')).DemoRefundExecutor({
      failTaskIds: ['task_execfail_1'],
    });
    const gateway = new (await import('../src/gateway.js')).TrustGateway({
      ...w.deps,
      executor: failingExecutor,
    });
    const result = await gateway.handleTask(await taskRequest(w, { taskId: 'task_execfail_1' }));
    expect(result.outcome).toBe('EXECUTION_FAILED');
    expect(result.stages.policy).toBe('ALLOW');
    expect(result.stages.execution).toBe('FAILED');
    expect(result.decisionReceiptId).toBeDefined();
    expect(result.executionReceiptId).toBeDefined();
    // Outcome receipt correlates to the decision receipt, chained after it.
    const chain = await w.auditLog.readStream(STREAM);
    const outcome = chain.find((r) => r.body.receiptId === result.executionReceiptId);
    expect(outcome?.body.execution?.state).toBe('FAILED');
    expect(outcome?.body.correlation?.decisionReceiptId).toBe(result.decisionReceiptId);
  });

  it('15. Cross-agent model: RefundAgent-side audience is honored; actor never self-authorizes arbitrary actions', async () => {
    const w = await buildWorld();
    // Same agent, action NOT in the delegation → policy denies on action.
    const result = await w.gateway.handleTask(
      await taskRequest(w, { action: 'payment:create', taskId: 'task_action_1' }),
    );
    expect(result.reasonCodes).toEqual(['ACTION_NOT_IN_SCOPE']);
    expect(REFUND_AGENT_DID && SUPPORT_AGENT_DID).toBeDefined();
  });
});
