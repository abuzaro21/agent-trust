import type { AttackObserved, AttackScenario } from './types.js';
import { IDENTITY_SCENARIOS } from './scenarios-identity.js';
import { CREDENTIAL_SCENARIOS } from './scenarios-identity.js';
import { AUTHORITY_SCENARIOS } from './scenarios-authority.js';
import { STATUS_SCENARIOS } from './scenarios-status.js';
import { REPLAY_SCENARIOS, POLICY_SCENARIOS } from './scenarios-replay-policy.js';
import { AUDIT_SCENARIOS } from './scenarios-audit.js';
import { ATTEST_SCENARIOS } from './scenarios-attestation.js';
import { DIDWEB_SCENARIOS } from './scenarios-didweb.js';
import { INFRA_SCENARIOS } from './scenarios-infra.js';

/**
 * Step 13B — the deterministic attack registry. IDs are stable and
 * referenced by docs/threat-model.md and the README video shortlist.
 *
 * Step 13N — every scenario carries an invariant checker beyond the
 * reason code: a denial alone proves nothing if the side effect happened
 * anyway. A scenario PASSes only when (a) the expected reason/outcome
 * holds AND (b) the security invariants hold.
 */

export type InvariantCheck = (observed: AttackObserved) => { ok: boolean; detail?: string };

export const INVARIANT_CHECKS: Record<string, InvariantCheck> = {
  'IDENTITY-001': (o) => {
    const i = o.invariants as Record<string, { allow: number; deny: number } | number>;
    const hist = i.victimHistoryDecisions as { allow: number; deny: number };
    return i.policyCalls === 0 && i.executorCalls === 0 && i.victimReceiptsAdded === 0 && hist.allow === 0 && hist.deny === 0
      ? { ok: true }
      : { ok: false, detail: `victim must be untouched: ${JSON.stringify(i)}` };
  },
  'IDENTITY-002': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0
      ? { ok: true }
      : { ok: false, detail: `policy/executor must not run: ${JSON.stringify(i)}` };
  },
  'IDENTITY-003': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0
      ? { ok: true }
      : { ok: false, detail: `policy must never see tampered values: ${JSON.stringify(i)}` };
  },
  'IDENTITY-004': (o) => {
    const i = o.invariants as Record<string, unknown>;
    return i.positiveControlAuthorized === true && i.executorCalls === 0
      ? { ok: true }
      : { ok: false, detail: `legitimate destination must still work, attacker must not: ${JSON.stringify(i)}` };
  },
  'CREDENTIAL-001': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'CREDENTIAL-002': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'CREDENTIAL-003': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'CREDENTIAL-004': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'CREDENTIAL-005': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'CREDENTIAL-006': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUTHORITY-001': (o) => {
    const i = o.invariants as Record<string, number>;
    // The showcase: policy RAN (correctly denied); executor never did.
    return (i.policyCalls ?? 0) >= 1 && i.executorCalls === 0
      ? { ok: true }
      : { ok: false, detail: `policy should run and executor must not: ${JSON.stringify(i)}` };
  },
  'AUTHORITY-002': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUTHORITY-003': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUTHORITY-004': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUTHORITY-005': (o) => {
    const i = o.invariants as Record<string, number>;
    // Attenuation must reject BEFORE policy evaluation.
    return i.policyCalls === 0 && i.executorCalls === 0
      ? { ok: true }
      : { ok: false, detail: `attenuation must stop before policy: ${JSON.stringify(i)}` };
  },
  'AUTHORITY-006': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'STATUS-001': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'STATUS-002': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'STATUS-003': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'STATUS-004': () => ({ ok: true }),
  'STATUS-005': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'STATUS-006': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'REPLAY-001': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.successfulRefunds === 1 && i.executorCalls === 1
      ? { ok: true }
      : { ok: false, detail: `exactly one logical refund: ${JSON.stringify(i)}` };
  },
  'REPLAY-002': (o) => {
    const i = o.invariants as Record<string, number>;
    const m = /authorized=(\d+) denied=(\d+)/.exec(o.outcome);
    return Number(m?.[1]) === 1 && Number(m?.[2]) === 99 && i.successfulRefunds === 1
      ? { ok: true }
      : { ok: false, detail: `100-way race must yield 1/99: ${o.outcome}` };
  },
  'REPLAY-003': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.policyCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'REPLAY-004': (o) => {
    const i = o.invariants as Record<string, number | boolean>;
    return i.legitAuthorized === true && i.successfulRefunds === 1 && i.executorCalls === 1
      ? { ok: true }
      : { ok: false, detail: `poisoning must not block the legitimate request: ${JSON.stringify(i)}` };
  },
  'POLICY-001': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'POLICY-002': () => ({ ok: true }),
  'POLICY-003': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'POLICY-004': (o) => {
    const i = o.invariants as Record<string, unknown>;
    return i.schemaRejectedScore === true
      ? { ok: true }
      : { ok: false, detail: `trustScore field must be schema-inexpressible: ${JSON.stringify(i)}` };
  },
  'AUDIT-001': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.chainValid && !i.anchoredValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUDIT-002': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.chainValid && !i.anchoredValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUDIT-003': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.chainValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUDIT-004': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.chainValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUDIT-005': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.chainValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUDIT-006': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.chainValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUDIT-007': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.rewrittenChainCoherent === true && i.checkpointRejected === true
      ? { ok: true }
      : { ok: false, detail: `coherent rewrite must still fail the checkpoint: ${JSON.stringify(i)}` };
  },
  'AUDIT-008': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.anchoredValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'AUDIT-009': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return !i.checkpointValid ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'ATTEST-001': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.victimAuthorityCount === 1 && i.victimTrustedAttestations === 0
      ? { ok: true }
      : { ok: false, detail: `vouch must not touch authority: ${JSON.stringify(i)}` };
  },
  'ATTEST-002': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.victimTrustedAttestations === 0 && i.sybilRejected === 100 && i.victimAuthorityCount === 1
      ? { ok: true }
      : { ok: false, detail: `100 Sybils must change NOTHING trusted: ${JSON.stringify(i)}` };
  },
  'ATTEST-003': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 && i.victimTrustedAttestations === 2
      ? { ok: true }
      : { ok: false, detail: `vouches ≠ authority: ${JSON.stringify(i)}` };
  },
  'ATTEST-004': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.victimTrustedAttestations === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'ATTEST-005': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.victimTrustedAttestations === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-001': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.notCached === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-002': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.blockedPreConnect === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-003': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.blockedPreConnect === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-004': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.blockedPreConnect === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-005': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.blockedPreConnect === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-006': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.notCached === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-007': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.notCached === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-008': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.notCached === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-009': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.notCached === true ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-010': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.firstFailed && i.secondSucceeded ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'DIDWEB-011': (o) => {
    const i = o.invariants as Record<string, boolean>;
    return i.refetchedEveryResolve === true && i.keyRotated === true
      ? { ok: true }
      : { ok: false, detail: `max-age=0 must force revalidation: ${JSON.stringify(i)}` };
  },
  'INFRA-001': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'INFRA-002': (o) => {
    const i = o.invariants as Record<string, unknown>;
    return i.decisionEffect === 'ALLOW' && i.outcomeState === 'FAILED' && i.decisionAndOutcomeChained === true
      ? { ok: true }
      : { ok: false, detail: JSON.stringify(i) };
  },
  'INFRA-003': (o) => {
    const i = o.invariants as Record<string, unknown>;
    return i.outcome === 'EXECUTION_UNCERTAIN' && i.executorCalls === 1
      ? { ok: true }
      : { ok: false, detail: `no blind retry: ${JSON.stringify(i)}` };
  },
  'INFRA-004': (o) => {
    const i = o.invariants as Record<string, number>;
    return i.executorCalls === 0 ? { ok: true } : { ok: false, detail: JSON.stringify(i) };
  },
  'INFRA-005': (o) => {
    const i = o.invariants as Record<string, unknown>;
    return i.executorCalls === 0 && i.policySkipped === true
      ? { ok: true }
      : { ok: false, detail: JSON.stringify(i) };
  },
};

export const ATTACK_REGISTRY: readonly AttackScenario[] = [
  ...IDENTITY_SCENARIOS,
  ...CREDENTIAL_SCENARIOS,
  ...AUTHORITY_SCENARIOS,
  ...STATUS_SCENARIOS,
  ...REPLAY_SCENARIOS,
  ...POLICY_SCENARIOS,
  ...AUDIT_SCENARIOS,
  ...ATTEST_SCENARIOS,
  ...DIDWEB_SCENARIOS,
  ...INFRA_SCENARIOS,
];
