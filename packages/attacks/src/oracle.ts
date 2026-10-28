import { types } from 'node:util';

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
  if (!isPlainData(a as object) || !isPlainData(b as object)) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    // isPlainData guarantees only own DATA elements (no holes, no inherited slots, no extra properties)
    return a.every((_, i) => strictEqual(a[i], b[i]));
  }
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => hasOwn(b as object, k) && strictEqual((a as Inv)[k], (b as Inv)[k]));
}

/**
 * JSON-like DATA only: a plain Object/Array (exact prototype), every own property an enumerable string-keyed DATA
 * property (no accessors, no symbols, no non-index extras on arrays such as a custom toJSON), and arrays with every
 * index present as an OWN element (a hole filled by the prototype chain does not count).
 */
function isPlainData(o: object): boolean {
  // A Proxy can answer reflection (descriptors, prototype) and later reads differently: never trust one.
  if (types.isProxy(o)) return false;
  const proto = Object.getPrototypeOf(o);
  if (Array.isArray(o)) {
    if (proto !== Array.prototype) return false;
    if (Object.getOwnPropertySymbols(o).length > 0) return false;
    // own keys must be exactly the indices 0..length-1 (+ the non-enumerable length)
    const keys = Object.getOwnPropertyNames(o).filter((k) => k !== 'length');
    if (keys.length !== o.length) return false;
    for (let i = 0; i < o.length; i++) {
      const d = Object.getOwnPropertyDescriptor(o, String(i));
      if (d === undefined || !('value' in d) || d.enumerable !== true) return false;
    }
    return true;
  }
  if (proto !== Object.prototype && proto !== null) return false;
  if (Object.getOwnPropertySymbols(o).length > 0) return false;
  return Object.getOwnPropertyNames(o).every((k) => {
    const d = Object.getOwnPropertyDescriptor(o, k);
    return d !== undefined && 'value' in d && d.enumerable === true;
  });
}

/**
 * Read one recorded invariant WITHOUT invoking user code: the container must be plain data, and the key an own
 * enumerable DATA property (an accessor could return different values on each read; a Proxy trap could lie).
 */
function readEvidence(o: AttackObserved, key: string): { ok: true; value: unknown } | { ok: false; detail: string } {
  const inv = o.invariants as unknown;
  if (typeof inv !== 'object' || inv === null || !isPlainData(inv)) return { ok: false, detail: 'invariants container is not plain data' };
  const d = Object.getOwnPropertyDescriptor(inv, key);
  if (d === undefined) return { ok: false, detail: `${key} was not recorded` };
  if (!('value' in d) || d.enumerable !== true) return { ok: false, detail: `${key} is not an own enumerable data property` };
  return { ok: true, value: d.value };
}

export type Snapshot = { ok: true; value: unknown } | { ok: false; detail: string };

/**
 * Deep, one-pass snapshot of an observation into inert plain data. Rejects Proxies, accessors, symbols, class
 * instances, non-finite numbers, undefined, functions, cycles and absurd depth; reads only descriptors, so no user
 * code runs and nothing can change between validation and use. The oracle judges the SNAPSHOT.
 */
export function snapshotEvidence(v: unknown, path = '$', seen: object[] = []): Snapshot {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return { ok: true, value: v };
  if (typeof v === 'number') return Number.isFinite(v) ? { ok: true, value: v } : { ok: false, detail: `${path} is a non-finite number` };
  if (typeof v !== 'object') return { ok: false, detail: `${path} has unsupported type ${typeof v}` };
  if (!isPlainData(v)) return { ok: false, detail: `${path} is not plain data (proxy, accessor, symbol, custom prototype or extra property)` };
  if (seen.includes(v)) return { ok: false, detail: `${path} is cyclic` };
  if (seen.length > 24) return { ok: false, detail: `${path} is nested too deeply` };
  seen.push(v);
  try {
    const out: Inv | unknown[] = Array.isArray(v) ? [] : {};
    const keys = Array.isArray(v) ? v.map((_, i) => String(i)) : Object.keys(v);
    for (const k of keys) {
      const d = Object.getOwnPropertyDescriptor(v, k)!;
      const child = snapshotEvidence(d.value, `${path}.${k}`, seen);
      if (!child.ok) return child;
      Object.defineProperty(out, k, { value: child.value, enumerable: true, writable: true, configurable: true });
    }
    return { ok: true, value: out };
  } finally {
    seen.pop();
  }
}

/** Defence in depth ONLY (human text). The typed verdict is the oracle. */
const FAILURE_MARKER = /UNDETECTED|UNEXPECTED|UNUSUAL|STALE KEY SURVIVED|connected \(unexpected\)/i;

/**
 * Strict invariant check. EVERY named key must be PRESENT and strictly equal
 * to the expected value; a missing key is a failure (never a pass), so an
 * observation that forgot to record an invariant cannot satisfy the check.
 */
export function requireInvariants(o: AttackObserved, expected: Record<string, unknown>): InvariantVerdict {
  const problems: string[] = [];
  if (Object.keys(expected).length === 0) problems.push('no expectations declared (an empty check would pass vacuously)');
  for (const [key, want] of Object.entries(expected)) {
    const got = readEvidence(o, key);
    if (!got.ok) problems.push(got.detail);
    else if (!strictEqual(got.value, want)) problems.push(`${key}=${safe(got.value)}, required ${safe(want)}`);
  }
  return problems.length === 0 ? { ok: true } : { ok: false, detail: `${problems.join('; ')} (observed: ${safe(o.invariants)})` };
}

const safe = (v: unknown): string => {
  try { return JSON.stringify(v) ?? String(v); } catch { return String(v); }
};

/** Strict numeric lower bound; a missing or non-numeric key fails. */
export function requireAtLeast(o: AttackObserved, key: string, min: number): InvariantVerdict {
  const got = readEvidence(o, key);
  if (!got.ok) return { ok: false, detail: got.detail };
  const v = got.value;
  return typeof v === 'number' && Number.isFinite(v) && v >= min ? { ok: true } : { ok: false, detail: `${key}=${safe(v)}, required >= ${min}` };
}

/** A recorded string that must be present and non-empty (a typed cause marker, not free text to match). */
export function requireNonEmptyString(o: AttackObserved, key: string): InvariantVerdict {
  const got = readEvidence(o, key);
  if (!got.ok) return { ok: false, detail: got.detail };
  const v = got.value;
  return typeof v === 'string' && v.length > 0 ? { ok: true } : { ok: false, detail: `${key} must be a non-empty string, got ${safe(v)}` };
}

/** Combine several verdicts: all must hold. An empty combination FAILS (it would pass vacuously). */
export function allOf(...parts: InvariantVerdict[]): InvariantVerdict {
  if (parts.length === 0) return { ok: false, detail: 'allOf() with no parts would pass vacuously' };
  const bad = parts.filter((p) => !p.ok);
  return bad.length === 0 ? { ok: true } : { ok: false, detail: bad.map((b) => b.detail ?? 'failed').join(' | ') };
}

export function judge(sc: AttackScenario, rawObserved: AttackObserved, check: InvariantCheck | undefined): Judgement {
  const failures: string[] = [];
  // Judge an inert, validated snapshot — never live objects that could change (or answer differently) between reads.
  const snap = snapshotEvidence(rawObserved);
  if (!snap.ok) return { status: 'FAIL', failures: [`observation is not plain JSON-like data: ${snap.detail}`] };
  const observed = snap.value as AttackObserved;
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
