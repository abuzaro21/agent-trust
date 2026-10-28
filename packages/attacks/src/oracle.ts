import type { AttackObserved, AttackScenario } from './types.js';

/**
 * The scenario oracle. A scenario PASSES only when ALL of these hold:
 *   1. it declares an expected machine-checked verdict AND exactly one
 *      reason-code policy (a reason code, a predicate, or an explicit
 *      `noReasonCode` justification) — a forgotten check can never pass;
 *   2. the observed typed verdict equals the expected one;
 *   3. the declared reason-code policy is satisfied;
 *   4. the human outcome text carries no failure marker (defence in depth
 *      only — the text is NOT the oracle);
 *   5. a registered invariant checker exists AND accepts the observation.
 * Missing pieces FAIL. Nothing here passes by default.
 */

export interface InvariantVerdict {
  ok: boolean;
  detail?: string;
}
export type InvariantCheck = (observed: AttackObserved) => InvariantVerdict;

export interface Judgement {
  status: 'PASS' | 'FAIL';
  failures: string[];
}

type Inv = Record<string, unknown>;
const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Defence in depth ONLY (human text). The typed verdict is the oracle. */
const FAILURE_MARKER = /UNDETECTED|UNEXPECTED|UNUSUAL|STALE KEY SURVIVED|connected \(unexpected\)/i;

/**
 * Strict invariant check. EVERY named key must be PRESENT and strictly equal
 * to the expected value; a missing key is a failure (never a pass), so an
 * observation that forgot to record an invariant cannot satisfy the check.
 */
export function requireInvariants(o: AttackObserved, expected: Record<string, unknown>): InvariantVerdict {
  const inv = o.invariants as Inv;
  const problems: string[] = [];
  for (const [key, want] of Object.entries(expected)) {
    if (!hasOwn(inv, key)) problems.push(`${key} was not recorded`);
    else if (JSON.stringify(inv[key]) !== JSON.stringify(want)) problems.push(`${key}=${JSON.stringify(inv[key])}, required ${JSON.stringify(want)}`);
  }
  return problems.length === 0 ? { ok: true } : { ok: false, detail: `${problems.join('; ')} (observed: ${JSON.stringify(inv)})` };
}

/** Strict numeric lower bound; a missing or non-numeric key fails. */
export function requireAtLeast(o: AttackObserved, key: string, min: number): InvariantVerdict {
  const inv = o.invariants as Inv;
  const v = inv[key];
  return hasOwn(inv, key) && typeof v === 'number' && v >= min
    ? { ok: true }
    : { ok: false, detail: `${key}=${JSON.stringify(v)}, required >= ${min}` };
}

/** Combine several verdicts: all must hold. */
export function allOf(...parts: InvariantVerdict[]): InvariantVerdict {
  const bad = parts.filter((p) => !p.ok);
  return bad.length === 0 ? { ok: true } : { ok: false, detail: bad.map((b) => b.detail ?? 'failed').join(' | ') };
}

export function judge(sc: AttackScenario, observed: AttackObserved, check: InvariantCheck | undefined): Judgement {
  const failures: string[] = [];
  const e = sc.expected;

  // 1. well-formed declaration
  if (e.verdict === undefined) failures.push('scenario declares no expected verdict');
  const policies = [e.reasonCode !== undefined, e.reasonCodesMatch !== undefined, typeof e.noReasonCode === 'string' && e.noReasonCode.trim().length > 0].filter(Boolean).length;
  if (policies !== 1) failures.push(`scenario must declare exactly one reason-code policy (reasonCode | reasonCodesMatch | noReasonCode), found ${policies}`);

  // 2. typed verdict
  if (observed.verdict === undefined) failures.push('observation carries no typed verdict');
  else if (e.verdict !== undefined && observed.verdict !== e.verdict) failures.push(`verdict ${observed.verdict}, expected ${e.verdict}`);

  // 3. reason-code policy
  if (e.reasonCodesMatch !== undefined) {
    if (!e.reasonCodesMatch(observed.reasonCodes)) failures.push(`reason codes [${observed.reasonCodes.join(', ')}] rejected by the scenario predicate`);
  } else if (e.reasonCode !== undefined) {
    if (!observed.reasonCodes.includes(e.reasonCode)) failures.push(`expected reason ${e.reasonCode}, observed [${observed.reasonCodes.join(', ')}]`);
  }

  // 4. defence in depth on the human text
  if (FAILURE_MARKER.test(observed.outcome)) failures.push(`outcome text carries a failure marker: ${observed.outcome}`);

  // 5. invariants
  if (check === undefined) failures.push('no invariant checker is registered for this scenario');
  else {
    const inv = check(observed);
    if (!inv.ok) failures.push(`invariant: ${inv.detail ?? 'failed'}`);
  }

  return { status: failures.length === 0 ? 'PASS' : 'FAIL', failures };
}
