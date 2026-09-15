import type { AttackScenario } from './types.js';
import { NOW, buildAttackWorld } from './world.js';
import { CredentialIssuer } from '@agent-trust/vc';

/**
 * Step 13F — Delegation / authority attacks. AUTHORITY-001 is the
 * showcase: every upstream gate passes, only the POLICY denies.
 */

export const AUTHORITY_001: AttackScenario = {
  id: 'AUTHORITY-001',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Amount escalation: 5000 SAR against a 500 SAR delegation',
  expected: { outcome: 'DENY at policy — identity/credential/status/replay all PASS', reasonCode: 'AUTHORITY_LIMIT_EXCEEDED' },
  async run() {
    const w = await buildAttackWorld();
    const result = await w.gateway.handleTask(await w.task({ amount: 5000, taskId: 'atk_amount' }));
    return {
      outcome:
        result.effect === 'DENY' && result.stages.identity === 'PASS' && result.stages.credential === 'PASS'
          ? `DENY at policy (identity=${result.stages.identity}, credential=${result.stages.credential}, replay=${result.stages.replay})`
          : result.outcome,
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const AUTHORITY_002: AttackScenario = {
  id: 'AUTHORITY-002',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Action escalation: request refund:create with an order:read-only delegation',
  expected: { outcome: 'DENY at policy', reasonCode: 'ACTION_NOT_IN_SCOPE' },
  async run() {
    const w = await buildAttackWorld();
    const index = await w.nextRevIndex();
    const { jws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['order:read'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
      credentialStatus: { id: `${w.revListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: w.revListId },
    });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_action', credentials: [jws] }));
    return {
      outcome: result.effect === 'DENY' ? `DENY at policy (policy=${result.stages.policy})` : result.outcome,
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total },
    };
  },
};

export const AUTHORITY_003: AttackScenario = {
  id: 'AUTHORITY-003',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Resource escalation: request outside the delegated resource pattern',
  expected: { outcome: 'DENY at policy', reasonCode: 'RESOURCE_NOT_IN_SCOPE' },
  async run() {
    const w = await buildAttackWorld();
    // Properly SIGNED for an out-of-scope resource — the policy denies on
    // delegated scope (an after-signing edit would fail at PoP first).
    const request = await w.task({ taskId: 'atk_resource', resource: 'tenant:beta' });
    const result = await w.gateway.handleTask(request);
    return {
      outcome: result.effect === 'DENY' ? `DENY at policy` : result.outcome,
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total },
    };
  },
};

export const AUTHORITY_004: AttackScenario = {
  id: 'AUTHORITY-004',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Audience escalation: delegation bound to RefundAgent, used against another service',
  expected: { outcome: 'DENY at policy', reasonCode: 'AUDIENCE_MISMATCH' },
  async run() {
    const w = await buildAttackWorld();
    // Delegation delegates to RefundAgent; the request targets evil.
    const index = await w.nextRevIndex();
    const { jws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
      credentialStatus: { id: `${w.revListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: w.revListId },
    });
    const request = await w.task({
      taskId: 'atk_aud_esc',
      credentials: [jws],
      audience: 'did:web:evil.example:agent',
    });
    const result = await w.gateway.handleTask(request);
    return {
      outcome: result.effect === 'DENY' ? `DENY at policy` : result.outcome,
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total },
    };
  },
};

export const AUTHORITY_005: AttackScenario = {
  id: 'AUTHORITY-005',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Child delegation broadens parent authority (attenuation walker)',
  expected: { outcome: 'delegation walker denies before policy', reasonCode: 'DELEGATION_ACTION_ESCALATION' },
  async run() {
    const w = await buildAttackWorld();
    // The gateway feeds VERIFIED credentials into validateDelegationChain;
    // every signature on such a chain can be perfectly valid — attenuation
    // is the control that catches a broadened child.
    const { validateDelegationChain } = await import('@agent-trust/delegation');
    const parent = {
      did: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 1 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
    };
    const child = {
      did: 'did:web:trust.example.com:agents:runner',
      authority: { actions: ['refund:create', 'user:delete'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
    };
    const result = validateDelegationChain([parent, child]);
    return {
      outcome: !result.ok
        ? `broadened child rejected by the walker (${result.reasonCodes.join(', ')})`
        : 'UNEXPECTED: broadening accepted',
      reasonCodes: result.ok ? [] : result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const AUTHORITY_006: AttackScenario = {
  id: 'AUTHORITY-006',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Delegation depth escalation beyond remaining budget (attenuation walker)',
  expected: { outcome: 'attenuation denies before policy', reasonCode: 'DELEGATION_DEPTH_EXCEEDED' },
  async run() {
    const w = await buildAttackWorld();
    const { validateDelegationChain } = await import('@agent-trust/delegation');
    // Leaf parent with ZERO budget; forged child claims one more hop.
    const parent = {
      did: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
    };
    const child = {
      did: 'did:web:trust.example.com:agents:runner',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 3 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
    };
    const result = validateDelegationChain([parent, child]);
    return {
      outcome: !result.ok
        ? `depth budget enforced (${result.reasonCodes.join(', ')})`
        : 'UNEXPECTED: depth escalation accepted',
      reasonCodes: result.ok ? [] : result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const AUTHORITY_SCENARIOS = [AUTHORITY_001, AUTHORITY_002, AUTHORITY_003, AUTHORITY_004, AUTHORITY_005, AUTHORITY_006];
