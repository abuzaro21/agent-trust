import { describe, expect, it } from 'vitest';

import { allOf, judge, requireAtLeast, requireInvariants, strictEqual, type AttackObserved, type AttackScenario } from '../src/index.js';

/**
 * Negative controls for the scenario oracle. Each test hands `judge` a
 * deliberately defective scenario/observation and requires a FAIL — so a
 * future edit that turns any of these gates into a pass-by-default is caught
 * here, not by a green suite that stopped checking anything.
 */

const base = (over: Partial<AttackScenario['expected']> = {}): AttackScenario => ({
  id: 'TEST-001',
  category: 'IDENTITY',
  kind: 'ATTACK',
  title: 'synthetic',
  expected: { verdict: 'DENIED', outcome: 'display only', reasonCode: 'IDENTITY_PROOF_INVALID', ...over },
  run: async () => {
    throw new Error('not used');
  },
});

const good: AttackObserved = {
  outcome: 'DENY (stage identity=FAIL)',
  verdict: 'DENIED',
  reasonCodes: ['IDENTITY_PROOF_INVALID'],
  invariants: { executorCalls: 0, policyCalls: 0 },
};
const strictZero = (o: AttackObserved) => requireInvariants(o, { executorCalls: 0, policyCalls: 0 });

describe('judge — a correct observation passes', () => {
  it('passes only when verdict, reason code and invariants all hold', () => {
    expect(judge(base(), good, strictZero)).toEqual({ status: 'PASS', failures: [] });
  });
});

describe('judge — every gate has a negative control', () => {
  it('FAILS when the observation carries the wrong typed verdict, even with a perfect outcome string', () => {
    const j = judge(base(), { ...good, verdict: 'BREACHED' }, strictZero);
    expect(j.status).toBe('FAIL');
    expect(j.failures.join()).toMatch(/verdict BREACHED, expected DENIED/);
  });

  it('FAILS when the observation has no typed verdict at all (text alone is not an oracle)', () => {
    const { verdict: _v, ...noVerdict } = good;
    void _v;
    expect(judge(base(), noVerdict as AttackObserved, strictZero).status).toBe('FAIL');
  });

  it('FAILS when the scenario declares no expected verdict', () => {
    const sc = base();
    delete (sc.expected as { verdict?: unknown }).verdict;
    expect(judge(sc, good, strictZero).failures.join()).toMatch(/declares no expected verdict/);
  });

  it('FAILS when the required reason code is absent', () => {
    expect(judge(base(), { ...good, reasonCodes: ['REPLAY_DETECTED'] }, strictZero).status).toBe('FAIL');
    expect(judge(base(), { ...good, reasonCodes: [] }, strictZero).status).toBe('FAIL');
  });

  it('FAILS when the scenario declares NO reason-code policy (an omission can no longer pass)', () => {
    const sc = base();
    delete (sc.expected as { reasonCode?: unknown }).reasonCode;
    expect(judge(sc, good, strictZero).failures.join()).toMatch(/exactly one reason-code policy.*found 0/);
  });

  it('FAILS when the scenario declares MORE than one reason-code policy', () => {
    expect(judge(base({ noReasonCode: 'because' }), good, strictZero).failures.join()).toMatch(/found 2/);
  });

  it('FAILS an empty noReasonCode justification', () => {
    const sc = base({ noReasonCode: '   ' });
    delete (sc.expected as { reasonCode?: unknown }).reasonCode;
    expect(judge(sc, good, strictZero).status).toBe('FAIL');
  });

  it('accepts an explicit noReasonCode justification and a predicate policy (the intentional exceptions)', () => {
    const none = base({ noReasonCode: 'resolver reports a DID-Core error, not a ReasonCode' });
    delete (none.expected as { reasonCode?: unknown }).reasonCode;
    expect(judge(none, { ...good, reasonCodes: [] }, strictZero).status).toBe('PASS');
    const pred = base({ reasonCodesMatch: (c) => c.includes('IDENTITY_PROOF_INVALID') });
    delete (pred.expected as { reasonCode?: unknown }).reasonCode;
    expect(judge(pred, good, strictZero).status).toBe('PASS');
    expect(judge(pred, { ...good, reasonCodes: ['REPLAY_DETECTED'] }, strictZero).status).toBe('FAIL');
  });

  it('FAILS when no invariant checker is registered (missing checker is NOT a pass)', () => {
    const j = judge(base(), good, undefined);
    expect(j.status).toBe('FAIL');
    expect(j.failures.join()).toMatch(/no invariant checker is registered/);
  });

  it('FAILS when the invariant checker rejects', () => {
    expect(judge(base(), { ...good, invariants: { executorCalls: 1, policyCalls: 0 } }, strictZero).status).toBe('FAIL');
  });

  it('FAILS when the outcome text carries a failure marker, regardless of everything else (defence in depth)', () => {
    for (const text of ['UNDETECTED', 'UNEXPECTED trust change', 'UNUSUAL', 'STALE KEY SURVIVED (bug)', 'connected (unexpected)']) {
      expect(judge(base(), { ...good, outcome: text }, strictZero).status).toBe('FAIL');
    }
  });

  it('does NOT let a reassuring outcome string rescue a breached observation', () => {
    const j = judge(base(), { ...good, outcome: 'DENIED safely, nothing happened', verdict: 'BREACHED', invariants: { executorCalls: 1, policyCalls: 1 } }, strictZero);
    expect(j.status).toBe('FAIL');
  });
});

describe('requireInvariants / requireAtLeast / allOf — strict, no pass-by-omission', () => {
  const obs = (invariants: Record<string, unknown>): AttackObserved => ({ ...good, invariants });

  it('a missing key fails (an unrecorded invariant can never satisfy a check)', () => {
    expect(requireInvariants(obs({}), { executorCalls: 0 }).ok).toBe(false);
    expect(requireInvariants(obs({ executorCalls: 0 }), { executorCalls: 0, policyCalls: 0 }).ok).toBe(false);
  });

  it('is strict about type: "0" and false are not 0', () => {
    expect(requireInvariants(obs({ executorCalls: '0' }), { executorCalls: 0 }).ok).toBe(false);
    expect(requireInvariants(obs({ executorCalls: false }), { executorCalls: 0 }).ok).toBe(false);
    expect(requireInvariants(obs({ flag: 1 }), { flag: true }).ok).toBe(false);
  });

  it('an undefined value does not equal a required value', () => {
    expect(requireInvariants(obs({ executorCalls: undefined }), { executorCalls: 0 }).ok).toBe(false);
  });

  it('requireAtLeast rejects missing, non-numeric and too-small values', () => {
    expect(requireAtLeast(obs({}), 'policyCalls', 1).ok).toBe(false);
    expect(requireAtLeast(obs({ policyCalls: '3' }), 'policyCalls', 1).ok).toBe(false);
    expect(requireAtLeast(obs({ policyCalls: 0 }), 'policyCalls', 1).ok).toBe(false);
    expect(requireAtLeast(obs({ policyCalls: 1 }), 'policyCalls', 1).ok).toBe(true);
  });

  it('allOf fails if any part fails and reports every detail', () => {
    const r = allOf({ ok: true }, { ok: false, detail: 'a' }, { ok: false, detail: 'b' });
    expect(r.ok).toBe(false);
    expect(r.detail).toBe('a | b');
    expect(allOf().ok).toBe(false); // an empty combination would pass vacuously
  });
});

describe('strict evidence comparison (no JSON-encoding collisions)', () => {
  const obs = (invariants: Record<string, unknown>): AttackObserved => ({ ...good, invariants });

  it('rejects a custom toJSON() object posing as a number (the executorCalls forgery)', () => {
    expect(requireInvariants(obs({ executorCalls: { toJSON: () => 0 } }), { executorCalls: 0 }).ok).toBe(false);
  });

  it('rejects NaN / Infinity against null or numbers, and undefined against undefined', () => {
    expect(requireInvariants(obs({ v: Number.NaN }), { v: null }).ok).toBe(false);
    expect(requireInvariants(obs({ v: Number.POSITIVE_INFINITY }), { v: null }).ok).toBe(false);
    expect(requireInvariants(obs({ v: undefined }), { v: undefined }).ok).toBe(false);
    expect(requireAtLeast(obs({ v: Number.NaN }), 'v', 0).ok).toBe(false);
    expect(requireAtLeast(obs({ v: Number.POSITIVE_INFINITY }), 'v', 0).ok).toBe(false);
  });

  it('distinguishes {a:1,b:undefined} from {a:1}, and accepts differently ordered keys', () => {
    expect(strictEqual({ a: 1, b: undefined }, { a: 1 })).toBe(false);
    expect(strictEqual({ a: 1, b: 2 }, { b: 2, a: 1 })).toBe(true);
    expect(requireInvariants(obs({ h: { allow: 0, deny: 0 } }), { h: { deny: 0, allow: 0 } }).ok).toBe(true);
  });

  it('compares arrays elementwise and rejects class instances and functions', () => {
    expect(strictEqual(['a', 'b'], ['a', 'b'])).toBe(true);
    expect(strictEqual(['a', 'b'], ['b', 'a'])).toBe(false);
    expect(strictEqual(new Date(0), new Date(0))).toBe(false);
    expect(strictEqual(() => 0, () => 0)).toBe(false);
  });

  it('rejects a sparse array posing as a dense one (holes are not skipped)', () => {
    const sparse = new Array(2); // two holes
    expect(strictEqual(sparse, [undefined, undefined])).toBe(false);
    expect(strictEqual([1, , 3], [1, 2, 3])).toBe(false); // eslint-disable-line no-sparse-arrays
    expect(strictEqual([1, 2, 3], [1, , 3])).toBe(false); // eslint-disable-line no-sparse-arrays
    expect(requireInvariants({ ...good, invariants: { r: new Array(1) } }, { r: [undefined] }).ok).toBe(false);
  });

  it('rejects arrays that are not plain data: prototype-filled holes, custom toJSON, subclasses, accessors', () => {
    const proto = Object.create(Array.prototype);
    proto[0] = 'AUDIT_SIGNER_UNTRUSTED';
    const inherited: string[] = Object.setPrototypeOf(new Array(1), proto);
    expect(inherited[0]).toBe('AUDIT_SIGNER_UNTRUSTED'); // looks populated, but the element is not an own element
    expect(strictEqual(inherited, ['AUDIT_SIGNER_UNTRUSTED'])).toBe(false);

    const withToJson = Object.assign(['AUDIT_SIGNER_UNTRUSTED'], { toJSON: () => ['ACCEPTED'] });
    expect(JSON.stringify(withToJson)).toBe('["ACCEPTED"]'); // contradictory machine evidence
    expect(strictEqual(withToJson, ['AUDIT_SIGNER_UNTRUSTED'])).toBe(false);

    class Evidence extends Array<string> {}
    expect(strictEqual(Evidence.from(['AUDIT_SIGNER_UNTRUSTED']), ['AUDIT_SIGNER_UNTRUSTED'])).toBe(false);

    const accessor: string[] = [];
    Object.defineProperty(accessor, '0', { get: () => 'AUDIT_SIGNER_UNTRUSTED', enumerable: true });
    expect(strictEqual(accessor, ['AUDIT_SIGNER_UNTRUSTED'])).toBe(false);
    const accessorObject = {};
    Object.defineProperty(accessorObject, 'a', { get: () => 1, enumerable: true });
    expect(strictEqual(accessorObject, { a: 1 })).toBe(false);
    expect(strictEqual(Object.assign({}, { [Symbol('s')]: 1 }), {})).toBe(false);
  });

  it('the malformed arrays above cannot make a REAL scenario checker (AUDIT-009) pass', async () => {
    const { ATTACK_REGISTRY, INVARIANT_CHECKS, runAttackSuite } = await import('../src/index.js');
    const r = (await runAttackSuite({ only: ['AUDIT-009'] })).scenarios[0]!;
    const sc = ATTACK_REGISTRY.find((s) => s.id === 'AUDIT-009')!;
    const forged = Object.assign(['AUDIT_SIGNER_UNTRUSTED'], { toJSON: () => ['ACCEPTED'] });
    const inv = { ...r.observed.invariants, wrongSignerReasons: forged };
    expect(judge(sc, { ...r.observed, invariants: inv }, INVARIANT_CHECKS['AUDIT-009']).status).toBe('FAIL');
    expect(judge(sc, r.observed, INVARIANT_CHECKS['AUDIT-009']).status).toBe('PASS');
  });

  it('an EMPTY expectation fails instead of passing vacuously', () => {
    expect(requireInvariants(obs({}), {}).ok).toBe(false);
    expect(requireInvariants(obs({ executorCalls: 0 }), {}).ok).toBe(false);
  });

  it('judge() turns a THROWING checker into a FAIL instead of propagating', () => {
    const throwing = () => {
      throw new Error('boom');
    };
    const j = judge(base(), good, throwing);
    expect(j.status).toBe('FAIL');
    expect(j.failures.join()).toMatch(/threw/);
  });
});
