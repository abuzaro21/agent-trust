import type { AttackScenario } from './types.js';
import { NOW, buildAttackWorld, STREAM } from './world.js';

/**
 * Step 13M — Infrastructure failure scenarios. These are FAILURE DEMOS,
 * not attacks: they prove the honest fail-closed / fail-honest behavior
 * when trusted dependencies disappear mid-flight.
 */

export const INFRA_001: AttackScenario = {
  id: 'INFRA-001',
  category: 'INFRASTRUCTURE',
  kind: 'FAILURE_DEMO',
  title: 'Audit store unavailable after policy ALLOW — no side effect without a durable decision',
  expected: { verdict: 'FAILED_SAFE', outcome: 'DENY, executor never runs', reasonCode: 'AUDIT_LOG_UNAVAILABLE' },
  async run() {
    const w = await buildAttackWorld();
    const failingLog = {
      append: async () => {
        throw new Error('audit store down');
      },
      readStream: async () => [],
      getHead: async () => null,
    };
    const gateway = new (await import('../../gateway/src/gateway.js')).TrustGateway({ ...w.gatewayDeps, auditLog: failingLog });
    const result = await gateway.handleTask(await w.task({ taskId: 'atk_audit_outage' }));
    return {
      outcome: result.effect === 'DENY' && result.stages.policy === 'ALLOW'
        ? `policy allowed, but audit-before-side-effect denied (audit=${result.stages.audit})`
        : result.outcome,
      verdict: result.effect === 'DENY' ? 'FAILED_SAFE' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyAllowedThenAuditVeto: result.stages.policy === 'ALLOW' },
    };
  },
};

export const INFRA_002: AttackScenario = {
  id: 'INFRA-002',
  category: 'INFRASTRUCTURE',
  kind: 'FAILURE_DEMO',
  title: 'Executor fails after a legitimate ALLOW — honest FAILED outcome receipt',
  expected: { verdict: 'FAILED_SAFE', outcome: 'ALLOW decision preserved; execution outcome is FAILED (never faked as success)', reasonCode: 'WITHIN_SCOPE' },
  async run() {
    const w = await buildAttackWorld();
    const failing = new (await import('../../gateway/src/executor.js')).DemoRefundExecutor({ failTaskIds: ['atk_exec_fail'] });
    const gateway = new (await import('../../gateway/src/gateway.js')).TrustGateway({ ...w.gatewayDeps, executor: failing });
    const result = await gateway.handleTask(await w.task({ taskId: 'atk_exec_fail' }));
    const chain = await w.auditLog.readStream(STREAM);
    // Both receipts must be FOUND in the chain by id (an absent id never matches anything).
    const decision = result.decisionReceiptId === undefined ? undefined : chain.find((r) => r.body.receiptId === result.decisionReceiptId);
    const outcome = result.executionReceiptId === undefined ? undefined : chain.find((r) => r.body.receiptId === result.executionReceiptId);
    const chained =
      decision !== undefined &&
      outcome !== undefined &&
      outcome.body.correlation?.decisionReceiptId === decision.body.receiptId &&
      outcome.body.sequence > decision.body.sequence;
    return {
      outcome: `decision=${result.effect}, execution=${result.stages.execution}, outcome receipt=${outcome?.body.execution?.state}`,
      verdict: result.effect === 'ALLOW' && outcome?.body.execution?.state === 'FAILED' && chained ? 'FAILED_SAFE' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: {
        decisionEffect: result.effect,
        decisionReceiptEffect: decision?.body.decision.effect ?? null,
        outcomeState: outcome?.body.execution?.state ?? null,
        decisionAndOutcomeChained: chained,
      },
    };
  },
};

export const INFRA_003: AttackScenario = {
  id: 'INFRA-003',
  category: 'INFRASTRUCTURE',
  kind: 'FAILURE_DEMO',
  title: 'Execution succeeds but outcome receipt cannot be persisted — EXECUTION_UNCERTAIN, never blind retry',
  expected: { verdict: 'FAILED_SAFE', outcome: 'EXECUTION_UNCERTAIN + AUDIT_OUTCOME_UNRECORDED; side effect not re-run', reasonCode: 'AUDIT_OUTCOME_UNRECORDED' },
  async run() {
    const w = await buildAttackWorld();
    // Decision append (1st) succeeds; outcome append (2nd) fails.
    let appends = 0;
    const flakyLog = {
      append: async (streamId: string, body: never) => {
        appends += 1;
        if (appends === 2) throw new Error('audit store dropped the outcome write');
        return w.auditLog.append(streamId, body);
      },
      readStream: (streamId: string) => w.auditLog.readStream(streamId),
      getHead: (streamId: string) => w.auditLog.getHead(streamId),
    };
    const gateway = new (await import('../../gateway/src/gateway.js')).TrustGateway({ ...w.gatewayDeps, auditLog: flakyLog });
    const result = await gateway.handleTask(await w.task({ taskId: 'atk_uncertain' }));
    // Prove the side effect ran EXACTLY ONCE and was not blindly retried.
    return {
      outcome: `result=${result.outcome}; executor calls=${w.executor.callCount.total} (no retry)`,
      verdict: result.outcome === 'EXECUTION_UNCERTAIN' && w.executor.callCount.total === 1 ? 'FAILED_SAFE' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, outcome: result.outcome, auditAppendAttempts: appends },
    };
  },
};

export const INFRA_004: AttackScenario = {
  id: 'INFRA-004',
  category: 'INFRASTRUCTURE',
  kind: 'FAILURE_DEMO',
  title: 'OPA engine crash inside evaluate — fail closed (no receipt: policy identity unknown; chain stays valid)',
  expected: { verdict: 'FAILED_SAFE', outcome: 'DENY, executor untouched', reasonCode: 'POLICY_EVALUATION_ERROR' },
  async run() {
    const w = await buildAttackWorld();
    const brokenPolicy = {
      evaluate: async () => {
        throw new Error('wasm memory fault');
      },
    };
    const gateway = new (await import('../../gateway/src/gateway.js')).TrustGateway({ ...w.gatewayDeps, policyEngine: brokenPolicy });
    const result = await gateway.handleTask(await w.task({ taskId: 'atk_opa_crash' }));
    return {
      outcome: `policy=${result.stages.policy}, executor calls=${w.executor.callCount.total}`,
      verdict: result.effect === 'DENY' ? 'FAILED_SAFE' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total },
    };
  },
};

export const INFRA_005: AttackScenario = {
  id: 'INFRA-005',
  category: 'INFRASTRUCTURE',
  kind: 'FAILURE_DEMO',
  title: 'Redis (replay store) outage on a protected write — fail closed before policy',
  expected: { verdict: 'FAILED_SAFE', outcome: 'DENY before policy evaluation', reasonCode: 'REPLAY_PROTECTION_UNAVAILABLE' },
  async run() {
    const w = await buildAttackWorld();
    const { ReplayProtector } = await import('@agent-trust/replay');
    const { ReplayStoreUnavailableError } = await import('@agent-trust/replay');
    const broken = new ReplayProtector({
      claim: async () => {
        throw new ReplayStoreUnavailableError(new Error('ECONNREFUSED 127.0.0.1:6379'));
      },
    });
    const gateway = new (await import('../../gateway/src/gateway.js')).TrustGateway({ ...w.gatewayDeps, replayProtector: broken });
    const result = await gateway.handleTask(await w.task({ taskId: 'atk_redis_down' }));
    return {
      outcome: `replay=${result.stages.replay}, policy=${result.stages.policy}, executor calls=${w.executor.callCount.total}`,
      verdict: result.effect === 'DENY' ? 'FAILED_SAFE' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policySkipped: result.stages.policy === 'NOT_RUN' },
    };
  },
};

export const INFRA_SCENARIOS = [INFRA_001, INFRA_002, INFRA_003, INFRA_004, INFRA_005];
void NOW;
