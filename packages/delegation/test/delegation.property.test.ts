import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import type { Authority, ReasonCode } from '@agent-trust/schemas';

import type { DelegationParty } from '../src/attenuate.js';
import { validateDelegation } from '../src/attenuate.js';
import { validateDelegationChain } from '../src/chain.js';

/**
 * Property-based attenuation tests. No wall clock anywhere: time windows
 * are generated integers, and child windows are derived from the parent's,
 * so runs are fully deterministic given fast-check's printed seed.
 */

const ACTIONS = ['refund:create', 'order:read', 'payment:create', 'data:export', 'order:cancel'];
const RESOURCES = ['tenant:acme', 'tenant:beta', 'order:legion', 'customer:pooled'];
const CURRENCIES = ['SAR', 'USD', 'EUR'];
const DIDS = ['did:web:payments.example:agent', 'did:web:shipping.example:agent', 'did:web:crm.example:agent'];

const ROOT_DID = 'did:web:acme.example:org';
const CHILD_DID = 'did:key:zChildAgent';
const GRANDCHILD_DID = 'did:key:zGrandChildAgent';

/** Small deterministic PRNG so mutations are reproducible per seed. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(arr: readonly T[], rnd: () => number): T {
  return arr[Math.floor(rnd() * arr.length)] as T;
}

/** Parent authority shape the generators fill in. */
interface ParentShape {
  actions: string[];
  resources: string[];
  audience: string[] | undefined;
  amount: number | undefined;
  perDay: number | undefined;
  currency: string | undefined;
  depth: number;
  validFrom: number;
  validUntilOffset: number;
}

const parentShapeArb = (minDepth: number, maxDepth: number) =>
  fc.record({
    actions: fc.subarray(ACTIONS, { minLength: 1 }),
    resources: fc.subarray(RESOURCES, { minLength: 1 }),
    audience: fc.option(fc.subarray(DIDS, { minLength: 1 }), { nil: undefined }),
    amount: fc.option(fc.integer({ min: 1, max: 100_000 }), { nil: undefined }),
    perDay: fc.option(fc.integer({ min: 1, max: 500 }), { nil: undefined }),
    currency: fc.option(fc.constantFrom(...CURRENCIES), { nil: undefined }),
    depth: fc.integer({ min: minDepth, max: maxDepth }),
    validFrom: fc.integer({ min: 1_700_000_000, max: 1_780_000_000 }),
    validUntilOffset: fc.integer({ min: 3_600, max: 31_536_000 }),
  });

function toParty(shape: ParentShape, did: string): DelegationParty {
  const authority: Authority = {
    actions: [...shape.actions],
    resources: [...shape.resources],
    ...(shape.audience !== undefined ? { audience: [...shape.audience] } : {}),
    ...(shape.amount !== undefined || shape.perDay !== undefined || shape.currency !== undefined
      ? {
          limits: {
            ...(shape.amount !== undefined ? { amount: shape.amount } : {}),
            ...(shape.perDay !== undefined ? { perDay: shape.perDay } : {}),
            ...(shape.currency !== undefined ? { currency: shape.currency } : {}),
          },
        }
      : {}),
    delegationDepth: shape.depth,
  };
  return {
    did,
    authority,
    validFrom: shape.validFrom,
    validUntil: shape.validFrom + shape.validUntilOffset,
  };
}

function toShape(party: DelegationParty): ParentShape {
  const limits = party.authority.limits ?? {};
  return {
    actions: party.authority.actions,
    resources: party.authority.resources,
    audience: party.authority.audience,
    amount: limits.amount,
    perDay: limits.perDay,
    currency: limits.currency,
    depth: party.authority.delegationDepth,
    validFrom: party.validFrom,
    validUntilOffset: (party.validUntil ?? party.validFrom + 3_600) - party.validFrom,
  };
}

/**
 * Derive a strictly attenuated child: every dimension is a subset, every
 * limit is ≤, the time window is nested, and depth strictly decreases
 * (unless minDepth forces the floor — the caller guarantees feasibility).
 */
function attenuate(shape: ParentShape, did: string, rnd: () => number, minDepth = 0): DelegationParty {
  const keepAtLeastOne = <T>(arr: T[]): T[] => {
    const kept = arr.filter(() => rnd() < 0.7);
    return kept.length > 0 ? kept : [pick(arr, rnd)];
  };

  const offset = shape.validUntilOffset;
  const fromShift = offset >= 2 ? Math.floor(rnd() * Math.min(offset - 1, 50)) : 0;
  const untilShift = Math.floor(rnd() * Math.min(offset - 1, 100));

  // Limits: every parent-constrained dimension MUST reappear in the child
  // with a value ≤ the parent's; the child may additionally constrain
  // dimensions the parent left open (that is narrowing, never escalation).
  const limits: { amount?: number; perDay?: number; currency?: string } = {};
  if (shape.amount !== undefined) {
    limits.amount = 1 + Math.floor(rnd() * shape.amount);
  } else if (rnd() < 0.3) {
    limits.amount = 1 + Math.floor(rnd() * 100);
  }
  if (shape.perDay !== undefined) {
    limits.perDay = 1 + Math.floor(rnd() * shape.perDay);
  } else if (rnd() < 0.2) {
    limits.perDay = 1 + Math.floor(rnd() * 50);
  }
  if (shape.currency !== undefined) {
    limits.currency = shape.currency;
  } else if (rnd() < 0.5) {
    limits.currency = pick(CURRENCIES, rnd);
  }

  return {
    did,
    authority: {
      actions: keepAtLeastOne(shape.actions),
      resources: keepAtLeastOne(shape.resources),
      ...(shape.audience !== undefined
        ? { audience: keepAtLeastOne(shape.audience) }
        : rnd() < 0.3
          ? { audience: [pick(DIDS, rnd)] }
          : {}),
      ...(Object.keys(limits).length > 0 ? { limits } : {}),
      delegationDepth: Math.max(
        minDepth,
        Math.min(shape.depth - 1, minDepth + Math.floor(rnd() * (shape.depth - minDepth))),
      ),
    },
    validFrom: shape.validFrom + fromShift,
    validUntil: shape.validFrom + offset - untilShift,
  };
}

/** Applies exactly ONE authority expansion; returns the expected denial code. */
function escalate(shape: ParentShape, did: string, rnd: () => number): {
  child: DelegationParty;
  expectedCode: ReasonCode;
} {
  const child = attenuate(shape, did, rnd);
  const mutations: { code: ReasonCode; apply: () => void }[] = [];

  const foreignAction = ACTIONS.find((a) => !shape.actions.includes(a));
  if (foreignAction !== undefined) {
    mutations.push({
      code: 'DELEGATION_ACTION_ESCALATION',
      apply: () => child.authority.actions.push(foreignAction),
    });
  }
  const foreignResource = RESOURCES.find((r) => !shape.resources.includes(r));
  if (foreignResource !== undefined) {
    mutations.push({
      code: 'DELEGATION_RESOURCE_ESCALATION',
      apply: () => child.authority.resources.push(foreignResource),
    });
  }
  if (shape.audience !== undefined) {
    mutations.push({
      code: 'DELEGATION_AUDIENCE_ESCALATION',
      apply: () => {
        delete child.authority.audience; // drop a set constraint = broaden to "any"
      },
    });
  }
  const limits = child.authority.limits;
  if (shape.amount !== undefined) {
    const maxAmount = shape.amount;
    mutations.push({
      code: 'DELEGATION_LIMIT_ESCALATION',
      apply: () => {
        if (limits === undefined) throw new Error('unreachable');
        limits.amount = maxAmount + 1 + Math.floor(rnd() * 1000);
      },
    });
  }
  if (shape.perDay !== undefined) {
    const maxPerDay = shape.perDay;
    mutations.push({
      code: 'DELEGATION_LIMIT_ESCALATION',
      apply: () => {
        if (limits === undefined) throw new Error('unreachable');
        limits.perDay = maxPerDay + 1 + Math.floor(rnd() * 100);
      },
    });
  }
  if (shape.currency !== undefined) {
    // Post-attenuation the child carries the parent's currency; switching
    // it to any other value loosens the constraint.
    const parentCurrency = shape.currency;
    mutations.push({
      code: 'DELEGATION_LIMIT_ESCALATION',
      apply: () => {
        if (limits === undefined) throw new Error('unreachable');
        limits.currency = CURRENCIES.find((c) => c !== parentCurrency) ?? CURRENCIES[0]!;
      },
    });
  }
  mutations.push({
    code: 'DELEGATION_TIME_ESCALATION',
    apply: () => {
      child.validUntil = (shape.validFrom + shape.validUntilOffset) + 1 + Math.floor(rnd() * 1000);
    },
  });
  mutations.push({
    code: 'DELEGATION_DEPTH_EXCEEDED',
    apply: () => {
      child.authority.delegationDepth = shape.depth; // must be strictly less
    },
  });

  const mutation = mutations[Math.floor(rnd() * mutations.length)]!;
  mutation.apply();
  return { child, expectedCode: mutation.code };
}

describe('property: attenuated children are always accepted', () => {
  it('validateDelegation(parent, attenuate(parent)) === ALLOW for any valid parent', () => {
    fc.assert(
      fc.property(
        parentShapeArb(1, 6),
        fc.integer({ min: 0, max: 2 ** 31 - 1 }),
        (shape, seed) => {
          const parent = toParty(shape, ROOT_DID);
          const child = attenuate(shape, CHILD_DID, mulberry32(seed));
          const result = validateDelegation({ parent, child });
          expect(result.ok).toBe(true);
        },
      ),
      { numRuns: 300 },
    );
  });

  it('amount and sets never increase across a full two-level chain', () => {
    fc.assert(
      fc.property(
        parentShapeArb(2, 6),
        fc.integer({ min: 0, max: 2 ** 31 - 1 }),
        fc.integer({ min: 0, max: 2 ** 31 - 1 }),
        (shape, seed1, seed2) => {
          const root = toParty(shape, ROOT_DID);
          const c1 = attenuate(shape, CHILD_DID, mulberry32(seed1), 1);
          const c2 = attenuate(toShape(c1), GRANDCHILD_DID, mulberry32(seed2));
          const result = validateDelegationChain([root, c1, c2]);
          expect(result.ok).toBe(true);

          // Direct invariants across the chain.
          for (const action of c2.authority.actions) {
            expect(root.authority.actions).toContain(action);
          }
          for (const resource of c2.authority.resources) {
            expect(root.authority.resources).toContain(resource);
          }
          const rootAmount = root.authority.limits?.amount;
          const c2Amount = c2.authority.limits?.amount;
          if (rootAmount !== undefined && c2Amount !== undefined) {
            expect(c2Amount).toBeLessThanOrEqual(rootAmount);
          }
          expect(c2.authority.delegationDepth).toBeLessThan(c1.authority.delegationDepth);
          expect(c2.validUntil ?? Infinity).toBeLessThanOrEqual(
            root.validUntil ?? Infinity,
          );
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe('property: every single-dimension expansion is denied', () => {
  it('expanding any constrained dimension yields exactly its escalation code', () => {
    fc.assert(
      fc.property(
        parentShapeArb(1, 6),
        fc.integer({ min: 0, max: 2 ** 31 - 1 }),
        (shape, seed) => {
          const parent = toParty(shape, ROOT_DID);
          const { child, expectedCode } = escalate(shape, CHILD_DID, mulberry32(seed));
          const result = validateDelegation({ parent, child });
          expect(result.ok).toBe(false);
          if (!result.ok) {
            expect(result.reasonCodes).toContain(expectedCode);
            expect(result.failedConstraints.length).toBeGreaterThan(0);
          }
        },
      ),
      { numRuns: 300 },
    );
  });
});
