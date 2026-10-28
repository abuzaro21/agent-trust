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

/**
 * Strict structural equality for recorded evidence. Supports only JSON-like data (finite numbers, strings, booleans, null,
 * arrays, plain objects). Anything else (undefined, NaN/Infinity, class instances, objects with toJSON, functions) is NOT
 * equal to anything, so malformed evidence can never masquerade as a legitimate value. Object key order is irrelevant;
 * an own key holding `undefined` is a different shape from a missing key.
 */
export function strictEqual(a: unknown, b: unknown): boolean {
  if (a === null || b === null) return a === b;
  const ta = typeof a;
  if (ta !== typeof b) return false;
  if (ta === 'number') return Number.isFinite(a as number) && a === b;
  if (ta === 'string' || ta === 'boolean') return a === b;
  if (ta !== 'object') return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      // A sparse array's holes are skipped by every()/forEach(); compare by index and require both sides to have the slot.
      if (!(i in a) || !(i in b) || !strictEqual(a[i], b[i])) return false;
    }
    return true;
  }
  const plain = (o: object) => { const p = Object.getPrototypeOf(o); return p === Object.prototype || p === null; };
  if (!plain(a as object) || !plain(b as object)) return false;
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => hasOwn(b as object, k) && strictEqual((a as Inv)[k], (b as Inv)[k]));
}

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
  if (Object.keys(expected).length === 0) problems.push('no expectations declared (an empty check would pass vacuously)');
  for (const [key, want] of Object.entries(expected)) {
    if (!hasOwn(inv, key)) problems.push(`${key} was not recorded`);
    else if (!strictEqual(inv[key], want)) problems.push(`${key}=${safe(inv[key])}, required ${safe(want)}`);
  }
  return problems.length === 0 ? { ok: true } : { ok: false, detail: `${problems.join('; ')} (observed: ${JSON.stringify(inv)})` };
}

const safe = (v: unknown): string => {
  try { return JSON.stringify(v) ?? String(v); } catch { return String(v); }
};

/** Strict numeric lower bound; a missing or non-numeric key fails. */
export function requireAtLeast(o: AttackObserved, key: string, min: number): InvariantVerdict {
  const inv = o.invariants as Inv;
  const v = inv[key];
  return hasOwn(inv, key) && typeof v === 'number' && Number.isFinite(v) && v >= min
    ? { ok: true }
    : { ok: false, detail: `${key}=${JSON.stringify(v)}, required >= ${min}` };
}

/** A recorded string that must be present and non-empty (a typed cause marker, not free text to match). */
export function requireNonEmptyString(o: AttackObserved, key: string): InvariantVerdict {
  const inv = o.invariants as Inv;
  const v = inv[key];
  return hasOwn(inv, key) && typeof v === 'string' && v.length > 0 ? { ok: true } : { ok: false, detail: `${key} must be a non-empty string, got ${safe(v)}` };
}

/** Combine several verdicts: all must hold. An empty combination FAILS (it would pass vacuously). */
export function allOf(...parts: InvariantVerdict[]): InvariantVerdict {
  if (parts.length === 0) return { ok: false, detail: 'allOf() with no parts would pass vacuously' };
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
    try {
      const inv = check(observed);
      if (!inv.ok) failures.push(`invariant: ${inv.detail ?? 'failed'}`);
    } catch (e) {
      failures.push(`invariant checker threw: ${String(e)}`);
    }
  }

  return { status: failures.length === 0 ? 'PASS' : 'FAIL', failures };
}
