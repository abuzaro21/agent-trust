import type { AttackScenario } from './types.js';
import { NOW, buildAttackWorld } from './world.js';

/**
 * Step 13G — Status attacks (revocation / suspension / quarantine /
 * status-list integrity).
 */

export const STATUS_001: AttackScenario = {
  id: 'STATUS-001',
  category: 'STATUS',
  kind: 'ATTACK',
  title: 'Revoked credential — same legitimate agent and key',
  expected: { verdict: 'DENIED', outcome: 'DENY at status stage, before policy', reasonCode: 'CREDENTIAL_REVOKED' },
  async run() {
    const w = await buildAttackWorld();
    await w.statusManager.revoke(w.revListId, w.delegationStatusIndex);
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_revoked' }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const STATUS_002: AttackScenario = {
  id: 'STATUS-002',
  category: 'STATUS',
  kind: 'ATTACK',
  title: 'Suspended credential (reversible mechanism)',
  expected: { verdict: 'DENIED', outcome: 'DENY at status stage', reasonCode: 'CREDENTIAL_SUSPENDED' },
  async run() {
    const w = await buildAttackWorld();
    // Re-issue the delegation anchored on the SUSPENSION list.
    const index = await w.statusManager.assignIndex(w.suspListId);
    const { jws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
      credentialStatus: { id: `${w.suspListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'suspension', statusListIndex: String(index), statusListCredential: w.suspListId },
    });
    await w.statusManager.suspend(w.suspListId, index);
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_susp', credentials: [jws] }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n },
    };
  },
};

export const STATUS_003: AttackScenario = {
  id: 'STATUS-003',
  category: 'STATUS',
  kind: 'ATTACK',
  title: 'Quarantined agent — everything else valid (per-identity kill switch)',
  expected: { verdict: 'DENIED', outcome: 'DENY at quarantine stage', reasonCode: 'AGENT_QUARANTINED' },
  async run() {
    const w = await buildAttackWorld();
    const SUPPORT = 'did:web:trust.example.com:agents:support';
    const verifier = w.gatewayDeps.verifier;
    const codes = (v: { valid: boolean; reasonCodes?: string[] }): string[] => (v.valid ? ['ACCEPTED'] : (v.reasonCodes ?? []));
    // A credential for a DIFFERENT subject, to isolate the early (caller-attested actor) quarantine stage.
    const { jws: otherSubjectJws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:runner',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
    });
    // Control: BEFORE quarantine the same credential verifies without any expected subject.
    const control = await verifier.verify(w.delegationJws, { now: NOW });
    w.quarantine.quarantine(SUPPORT, 'suspected key compromise');
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_quar' }));
    // Verifier-level cases, each reaching exactly ONE of the two quarantine stages:
    //  - verified-subject stage: no expectedSubject, so only the check on the signature-bound subject can catch it;
    //  - early actor stage: the quarantined actor presents a credential for ANOTHER subject (otherwise WRONG_SUBJECT).
    const verifiedSubjectStage = await verifier.verify(w.delegationJws, { now: NOW });
    const earlyActorStage = await verifier.verify(otherSubjectJws, { now: NOW, expectedSubject: SUPPORT });
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage identity=${result.stages.identity})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: {
        executorCalls: w.executor.callCount.total,
        policyCalls: w.policyCalls.n,
        verifierControlBeforeQuarantine: codes(control),
        verifiedSubjectStageReasons: codes(verifiedSubjectStage),
        earlyActorStageReasons: codes(earlyActorStage),
      },
    };
  },
};

export const STATUS_004: AttackScenario = {
  id: 'STATUS-004',
  category: 'STATUS',
  kind: 'ATTACK',
  title: 'Tampered status list (corrupted bitstring in the status store)',
  expected: { verdict: 'DENIED', outcome: 'fail closed on undecodable status data', reasonCode: 'CREDENTIAL_STATUS_UNAVAILABLE' },
  async run() {
    const w = await buildAttackWorld();
    // Full-database attacker: poison the encoded bitstring behind the
    // delegation's status list. The checker must fail closed (UNKNOWN),
    // never guess.
    const fresh = await w.statusManager.readStatus(w.revListId, w.delegationStatusIndex);
    await w.statusStore.put({ ...fresh.list, encodedList: '!!!corrupted!!!' });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_statustamper' }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n, credentialStage: result.stages.credential },
    };
  },
};

export const STATUS_005: AttackScenario = {
  id: 'STATUS-005',
  category: 'STATUS',
  kind: 'ATTACK',
  title: 'Foreign issuer status list (controller ≠ credential issuer)',
  expected: { verdict: 'DENIED', outcome: 'fail closed — status list controlled by someone else', reasonCode: 'CREDENTIAL_STATUS_UNAVAILABLE' },
  async run() {
    const w = await buildAttackWorld();
    // Credential claims the AUDITOR's list while being issued by the org.
    const index = await w.statusManager.assignIndex(w.audListId);
    const { jws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
      credentialStatus: { id: `${w.audListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: w.audListId },
    });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_foreign', credentials: [jws] }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n, credentialStage: result.stages.credential },
    };
  },
};

export const STATUS_006: AttackScenario = {
  id: 'STATUS-006',
  category: 'STATUS',
  kind: 'ATTACK',
  title: 'Declared status mechanism, checker unavailable',
  expected: { verdict: 'DENIED', outcome: 'fail closed', reasonCode: 'CREDENTIAL_STATUS_UNAVAILABLE' },
  async run() {
    const w = await buildAttackWorld();
    // Present a credential with a status entry whose list does not exist.
    const { jws } = await w.issuer.issueDelegation({
      subjectDid: 'did:web:trust.example.com:agents:support',
      authority: { actions: ['refund:create'], resources: ['order:*'], audience: ['did:web:trust.example.com:agents:refund'], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
      validFrom: NOW - 3600,
      validUntil: NOW + 86_400,
      credentialStatus: {
        id: 'https://missing.example/status/rev/1#0', type: 'BitstringStatusListEntry', statusPurpose: 'revocation',
        statusListIndex: '0', statusListCredential: 'https://missing.example/status/rev/1',
      },
    });
    const result = await w.gateway.handleTask(await w.task({ taskId: 'atk_nostatus', credentials: [jws] }));
    return {
      outcome: result.effect === 'DENY' ? `DENY (stage credential=${result.stages.credential})` : result.outcome,
      verdict: result.effect === 'DENY' ? 'DENIED' : 'BREACHED',
      reasonCodes: result.reasonCodes,
      invariants: { executorCalls: w.executor.callCount.total, policyCalls: w.policyCalls.n, credentialStage: result.stages.credential },
    };
  },
};

export const STATUS_SCENARIOS = [STATUS_001, STATUS_002, STATUS_003, STATUS_004, STATUS_005, STATUS_006];
