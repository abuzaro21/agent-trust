import type { Authority, FailedConstraint, ReasonCode } from '@agent-trust/schemas';

/**
 * One link in a delegation chain, reduced to the facts the attenuator
 * needs. Time windows are Unix seconds — the caller maps credential
 * claims (nbf/exp) before calling; the validator itself never reads the
 * wall clock, which is what keeps property tests deterministic.
 */
export interface DelegationParty {
  did: string;
  authority: Authority;
  validFrom: number;
  validUntil?: number;
}

export type AttenuationResult =
  | { ok: true; reasonCodes: ['ATTENUATION_VERIFIED'] }
  | { ok: false; reasonCodes: ReasonCode[]; failedConstraints: FailedConstraint[] };

const OK: AttenuationResult = { ok: true, reasonCodes: ['ATTENUATION_VERIFIED'] };

function violation(
  code: ReasonCode,
  field: string,
  actual: unknown,
  operator: string,
  expected: unknown,
): { code: ReasonCode; constraint: FailedConstraint } {
  return { code, constraint: { field, actual, operator, expected } };
}

/** ISO-8601 → epoch seconds; undefined passes through; invalid ISO fails closed. */
function isoEpoch(value: string | undefined): { ok: true; value?: number } | { ok: false } {
  if (value === undefined) return { ok: true };
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? { ok: false } : { ok: true, value: Math.floor(ms / 1000) };
}

function subsetOf(child: readonly string[], parent: readonly string[]): boolean {
  return child.every((item) => parent.includes(item));
}

function isSubsetViolation(
  parent: readonly string[] | undefined,
  child: readonly string[] | undefined,
): boolean {
  // Parent unconstrained → any child set is a narrowing.
  if (parent === undefined) return false;
  // Parent constrained but child unconstrained → broadening.
  if (child === undefined) return true;
  return !subsetOf(child, parent);
}

/**
 * The central invariant: Authority(child) ⊆ Authority(parent), checked
 * dimension by dimension. All violations are collected (deterministic
 * check order) so a denial explains every escalated dimension, not just
 * the first. Nothing here consults the wall clock.
 */
export function validateDelegation(input: {
  parent: DelegationParty;
  child: DelegationParty;
}): AttenuationResult {
  const { parent, child } = input;
  const violations: { code: ReasonCode; constraint: FailedConstraint }[] = [];
  const p = parent.authority;
  const c = child.authority;

  // A party delegating to itself is a trivial cycle.
  if (child.did === parent.did) {
    violations.push(
      violation('DELEGATION_CYCLE', 'child.did', child.did, '!=', parent.did),
    );
  }

  // Actions and resources: set containment.
  if (!subsetOf(c.actions, p.actions)) {
    violations.push(
      violation(
        'DELEGATION_ACTION_ESCALATION',
        'authority.actions',
        c.actions,
        'subsetOf',
        p.actions,
      ),
    );
  }
  if (!subsetOf(c.resources, p.resources)) {
    violations.push(
      violation(
        'DELEGATION_RESOURCE_ESCALATION',
        'authority.resources',
        c.resources,
        'subsetOf',
        p.resources,
      ),
    );
  }

  // Audience: same containment semantics, including undefined-is-broadening.
  if (isSubsetViolation(p.audience, c.audience)) {
    violations.push(
      violation(
        'DELEGATION_AUDIENCE_ESCALATION',
        'authority.audience',
        c.audience ?? '(any)',
        'subsetOf',
        p.audience,
      ),
    );
  }

  // Limits. An unset child limit under a set parent limit is broadening
  // (no limit = unlimited); a child limit under an unset parent is narrowing.
  const pl = p.limits ?? {};
  const cl = c.limits ?? {};
  if (pl.amount !== undefined && (cl.amount === undefined || cl.amount > pl.amount)) {
    violations.push(
      violation(
        'DELEGATION_LIMIT_ESCALATION',
        'authority.limits.amount',
        cl.amount ?? '(unlimited)',
        '<=',
        pl.amount,
      ),
    );
  }
  if (pl.perDay !== undefined && (cl.perDay === undefined || cl.perDay > pl.perDay)) {
    violations.push(
      violation(
        'DELEGATION_LIMIT_ESCALATION',
        'authority.limits.perDay',
        cl.perDay ?? '(unlimited)',
        '<=',
        pl.perDay,
      ),
    );
  }
  if (pl.currency !== undefined && cl.currency !== pl.currency) {
    violations.push(
      violation(
        'DELEGATION_LIMIT_ESCALATION',
        'authority.limits.currency',
        cl.currency ?? '(any)',
        '==',
        pl.currency,
      ),
    );
  }

  // Time — credential-level window (Unix seconds).
  if (child.validFrom < parent.validFrom) {
    violations.push(
      violation(
        'DELEGATION_TIME_ESCALATION',
        'validFrom',
        child.validFrom,
        '>=',
        parent.validFrom,
      ),
    );
  }
  if (parent.validUntil !== undefined && (child.validUntil === undefined || child.validUntil > parent.validUntil)) {
    violations.push(
      violation(
        'DELEGATION_TIME_ESCALATION',
        'validUntil',
        child.validUntil ?? '(no expiry)',
        '<=',
        parent.validUntil,
      ),
    );
  }

  // Time — authority-level window (ISO-8601). Invalid dates fail closed.
  const pFrom = isoEpoch(p.validFrom);
  const cFrom = isoEpoch(c.validFrom);
  const pUntil = isoEpoch(p.validUntil);
  const cUntil = isoEpoch(c.validUntil);
  if (!pFrom.ok || !cFrom.ok || !pUntil.ok || !cUntil.ok) {
    violations.push(
      violation('DELEGATION_TIME_ESCALATION', 'authority.validFrom/validUntil', '(invalid ISO-8601)', 'parses to', 'epoch seconds'),
    );
  } else {
    if (pFrom.value !== undefined && (cFrom.value === undefined || cFrom.value < pFrom.value)) {
      violations.push(
        violation('DELEGATION_TIME_ESCALATION', 'authority.validFrom', c.validFrom ?? '(unset)', '>=', p.validFrom),
      );
    }
    if (pUntil.value !== undefined && (cUntil.value === undefined || cUntil.value > pUntil.value)) {
      violations.push(
        violation('DELEGATION_TIME_ESCALATION', 'authority.validUntil', c.validUntil ?? '(unset)', '<=', p.validUntil),
      );
    }
  }

  // Depth: the parent must still have sub-delegation budget, and the child
  // consumes one level — strictly less than the parent's remaining depth.
  if (p.delegationDepth < 1) {
    violations.push(
      violation(
        'DELEGATION_DEPTH_EXCEEDED',
        'authority.delegationDepth (parent budget)',
        p.delegationDepth,
        '>=',
        1,
      ),
    );
  } else if (c.delegationDepth >= p.delegationDepth) {
    violations.push(
      violation(
        'DELEGATION_DEPTH_EXCEEDED',
        'authority.delegationDepth',
        c.delegationDepth,
        '<',
        p.delegationDepth,
      ),
    );
  }

  if (violations.length > 0) {
    return {
      ok: false,
      reasonCodes: violations.map((v) => v.code),
      failedConstraints: violations.map((v) => v.constraint),
    };
  }
  return OK;
}
