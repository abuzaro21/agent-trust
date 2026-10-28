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
  expected: { verdict: 'DENIED', outcome: 'DENY at policy — identity/credential/status/replay all PASS', reasonCode: 'AUTHORITY_LIMIT_EXCEEDED' },
  async run() {
    const w = await buildAttackWorld();
    const result = await w.gateway.handleTask(await w.task({ amount: 5000, taskId: 'atk_amount' }));
    return {
      outcome:
        result.effect === 'DENY' && result.stages.identity === 'PASS' && result.stages.credential === 'PASS'
          ? `DENY at policy (identity=${result.stages.identity}, credential=${result.stages.credential}, replay=${result.stages.replay})`
          : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
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
  expected: { verdict: 'DENIED', outcome: 'DENY at policy', reasonCode: 'ACTION_NOT_IN_SCOPE' },
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
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const AUTHORITY_003: AttackScenario = {
  id: 'AUTHORITY-003',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Resource escalation: request outside the delegated resource pattern',
  expected: { verdict: 'DENIED', outcome: 'DENY at policy', reasonCode: 'RESOURCE_NOT_IN_SCOPE' },
  async run() {
    const w = await buildAttackWorld();
    // Properly SIGNED for an out-of-scope resource — the policy denies on
    // delegated scope (an after-signing edit would fail at PoP first).
    const request = await w.task({ taskId: 'atk_resource', resource: 'tenant:beta' });
    const result = await w.gateway.handleTask(request);
    return {
      outcome: result.effect === 'DENY' ? `DENY at policy` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const AUTHORITY_004: AttackScenario = {
  id: 'AUTHORITY-004',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Audience escalation: delegation bound to RefundAgent, used against another service',
  expected: { verdict: 'DENIED', outcome: 'DENY at policy', reasonCode: 'AUDIENCE_MISMATCH' },
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
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const AUTHORITY_005: AttackScenario = {
  id: 'AUTHORITY-005',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Child delegation broadens parent authority (attenuation walker)',
  expected: { verdict: 'REFUSED', outcome: 'delegation walker rejects the broadened child (the gateway composes the walker before policy; it accepts a single delegation link, so the walker is exercised directly)', reasonCode: 'DELEGATION_ACTION_ESCALATION' },
  async run() {
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
    // Control: the SAME chain with a properly attenuated child is accepted, so the
    // rejection above is caused by the broadening and not by a broken fixture.
    const attenuated = { ...child, authority: { ...child.authority, actions: ['refund:create'] } };
    const control = validateDelegationChain([parent, attenuated]);
    return {
      outcome: !result.ok
        ? `broadened child rejected by the walker (${result.reasonCodes.join(', ')})`
        : 'UNEXPECTED: broadening accepted',
      verdict: !result.ok ? 'REFUSED' : 'BREACHED',
      reasonCodes: result.ok ? [] : result.reasonCodes,
      invariants: { walkerRejected: !result.ok, controlAttenuatedChainAccepted: control.ok === true },
    };
  },
};

export const AUTHORITY_006: AttackScenario = {
  id: 'AUTHORITY-006',
  category: 'AUTHORITY',
  kind: 'ATTACK',
  title: 'Delegation depth escalation beyond remaining budget (attenuation walker)',
  expected: { verdict: 'REFUSED', outcome: 'attenuation walker rejects a depth beyond the remaining budget (exercised directly: the gateway accepts a single delegation link)', reasonCode: 'DELEGATION_DEPTH_EXCEEDED' },
  async run() {
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
    // Control: with a parent that DOES have budget (depth 1) and a leaf child (depth 0) the chain is accepted.
    const control = validateDelegationChain([
      { ...parent, authority: { ...parent.authority, delegationDepth: 1 } },
      { ...child, authority: { ...child.authority, delegationDepth: 0 } },
    ]);
    return {
      outcome: !result.ok
        ? `depth budget enforced (${result.reasonCodes.join(', ')})`
        : 'UNEXPECTED: depth escalation accepted',
      verdict: !result.ok ? 'REFUSED' : 'BREACHED',
      reasonCodes: result.ok ? [] : result.reasonCodes,
      invariants: { walkerRejected: !result.ok, controlWithinBudgetChainAccepted: control.ok === true },
    };
  },
};

export const AUTHORITY_SCENARIOS = [AUTHORITY_001, AUTHORITY_002, AUTHORITY_003, AUTHORITY_004, AUTHORITY_005, AUTHORITY_006];
