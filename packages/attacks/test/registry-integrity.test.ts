import { beforeAll, describe, expect, it } from 'vitest';

import {
  ATTACK_REGISTRY,
  INVARIANT_CHECKS,
  judge,
  runAttackSuite,
  type AttackObserved,
  type AttackReport,
} from '../src/index.js';

/**
 * Registry integrity + mutation testing. These tests exist so the suite can
 * never silently degrade into "everything passes": they prove, for EVERY
 * scenario, that the oracle can fail.
 */

let report: AttackReport;
beforeAll(async () => {
  report = await runAttackSuite();
}, 120_000);

/** Scenarios that legitimately have no gateway ReasonCode to assert, with the reason recorded in the registry. */
const INTENTIONAL_NO_REASON_CODE = [
  'DIDWEB-001', 'DIDWEB-002', 'DIDWEB-003', 'DIDWEB-004', 'DIDWEB-005', 'DIDWEB-006', 'DIDWEB-007', 'DIDWEB-008', 'DIDWEB-009', 'DIDWEB-010', 'DIDWEB-011',
  'INFRA-002',
];

describe('registry structure', () => {
  it('has 60 unique scenarios (52 attacks + 8 failure demos)', () => {
    const ids = ATTACK_REGISTRY.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toHaveLength(60);
    expect(ATTACK_REGISTRY.filter((s) => s.kind === 'ATTACK')).toHaveLength(52);
    expect(ATTACK_REGISTRY.filter((s) => s.kind === 'FAILURE_DEMO')).toHaveLength(8);
  });

  it('every scenario has a registered invariant checker and every checker belongs to a scenario', () => {
    const ids = new Set(ATTACK_REGISTRY.map((s) => s.id));
    for (const id of ids) expect(INVARIANT_CHECKS[id], `no checker for ${id}`).toBeTypeOf('function');
    for (const id of Object.keys(INVARIANT_CHECKS)) expect(ids.has(id), `orphan checker ${id}`).toBe(true);
  });

  it('every scenario declares a machine-checked verdict and exactly one reason-code policy', () => {
    for (const s of ATTACK_REGISTRY) {
      expect(s.expected.verdict, `${s.id} verdict`).toBeTypeOf('string');
      const policies = [s.expected.reasonCode !== undefined, s.expected.reasonCodesMatch !== undefined, s.expected.noReasonCode !== undefined].filter(Boolean);
      expect(policies, `${s.id} reason policy`).toHaveLength(1);
    }
  });

  it('only the documented scenarios opt out of a reason code, each with a written justification', () => {
    const optedOut = ATTACK_REGISTRY.filter((s) => s.expected.noReasonCode !== undefined);
    expect(optedOut.map((s) => s.id).sort()).toEqual([...INTENTIONAL_NO_REASON_CODE].sort());
    for (const s of optedOut) expect(s.expected.noReasonCode!.trim().length, `${s.id} justification`).toBeGreaterThan(20);
    // 48 of 60 assert a concrete reason code; 12 are the documented exceptions above.
    expect(ATTACK_REGISTRY.length - optedOut.length).toBe(48);
  });
});

describe('no checker passes by default', () => {
  const empty: AttackObserved = { outcome: '', verdict: 'DENIED', reasonCodes: [], invariants: {} };

  it.each(ATTACK_REGISTRY.map((s) => s.id))('%s: its invariant checker REJECTS an empty observation', (id) => {
    const verdict = INVARIANT_CHECKS[id]!(empty);
    expect(verdict.ok, `${id} accepted an observation that recorded nothing`).toBe(false);
  });
});

describe('the whole suite', () => {
  it('passes 60/60 under the strict oracle with no failure detail', () => {
    expect(report.summary.total).toBe(60);
    expect(report.summary.passed).toBe(60);
    expect(report.scenarios.filter((r) => r.status !== 'PASS').map((r) => `${r.id}: ${r.detail}`)).toEqual([]);
    for (const r of report.scenarios) expect(r.failures, r.id).toBeUndefined();
  });

  it('every observation carries a typed verdict equal to the declared one (never BREACHED)', () => {
    for (const r of report.scenarios) {
      expect(r.observed.verdict, r.id).toBe(r.expected.verdict);
      expect(r.observed.verdict, r.id).not.toBe('BREACHED');
    }
  });
});

describe('mutation testing: every scenario depends on what it records', () => {
  const sc = (id: string) => ATTACK_REGISTRY.find((s) => s.id === id)!;
  const mutate = (v: unknown): unknown => (typeof v === 'boolean' ? !v : typeof v === 'number' ? v + 1 : typeof v === 'string' ? `${v}~mutated` : '~mutated');

  it('flipping the typed verdict to BREACHED fails every scenario', () => {
    for (const r of report.scenarios) {
      const j = judge(sc(r.id), { ...r.observed, verdict: 'BREACHED' }, INVARIANT_CHECKS[r.id]);
      expect(j.status, r.id).toBe('FAIL');
    }
  });

  it('removing every reason code fails each scenario that asserts one', () => {
    for (const r of report.scenarios) {
      const s = sc(r.id);
      if (s.expected.noReasonCode !== undefined) continue;
      const j = judge(s, { ...r.observed, reasonCodes: [] }, INVARIANT_CHECKS[r.id]);
      expect(j.status, `${r.id} passes with no reason code`).toBe('FAIL');
    }
  });

  it('each checker rejects at least one single-key deletion AND at least one single-key corruption of its real observation', () => {
    for (const r of report.scenarios) {
      const check = INVARIANT_CHECKS[r.id]!;
      const keys = Object.keys(r.observed.invariants);
      expect(keys.length, `${r.id} records no invariants`).toBeGreaterThan(0);
      let rejectedDeletions = 0;
      let rejectedCorruptions = 0;
      for (const k of keys) {
        const without = { ...r.observed.invariants };
        delete without[k];
        if (!check({ ...r.observed, invariants: without }).ok) rejectedDeletions += 1;
        if (!check({ ...r.observed, invariants: { ...r.observed.invariants, [k]: mutate(r.observed.invariants[k]) } }).ok) rejectedCorruptions += 1;
      }
      expect(rejectedDeletions, `${r.id}: deleting any recorded invariant is still accepted`).toBeGreaterThan(0);
      expect(rejectedCorruptions, `${r.id}: corrupting any recorded invariant is still accepted`).toBeGreaterThan(0);
    }
  });

  it('the real observation passes, so the mutation results above are caused by the mutation', () => {
    for (const r of report.scenarios) expect(INVARIANT_CHECKS[r.id]!(r.observed).ok, r.id).toBe(true);
  });
});

describe('controls: the scenarios prove their own fixtures work', () => {
  const get = (id: string) => report.scenarios.find((r) => r.id === id)!.observed.invariants;

  it('audit scenarios run on a history that verified cleanly before it was tampered with', () => {
    for (let n = 1; n <= 8; n++) {
      const inv = get(`AUDIT-00${n}`);
      expect(inv.controlIntact, `AUDIT-00${n}`).toBe(true);
      expect(inv.controlConsumerHistoryVerified, `AUDIT-00${n}`).toBe(true);
    }
    expect(get('AUDIT-009').controlPinnedGenuineVerifies).toBe(true);
  });

  it('SSRF scenarios: the same transport DOES connect to a public address, and never connected for the blocked ones', () => {
    for (const id of ['DIDWEB-002', 'DIDWEB-003', 'DIDWEB-004', 'DIDWEB-005']) {
      expect(get(id).connectAttempts, id).toBe(0);
      expect(get(id).controlPublicAddressConnects, id).toBe(true);
    }
  });

  it('did:web refusal scenarios: the same transport serves a good document that resolves', () => {
    for (const id of ['DIDWEB-001', 'DIDWEB-006', 'DIDWEB-007', 'DIDWEB-008', 'DIDWEB-009']) {
      expect(get(id).controlResolves, id).toBe(true);
      expect(get(id).resolutionError, id).toBeTypeOf('string');
    }
  });
});
