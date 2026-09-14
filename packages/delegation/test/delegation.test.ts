import { describe, expect, it } from 'vitest';

import type { Authority } from '@agent-trust/schemas';

import type { DelegationParty } from '../src/attenuate.js';
import { validateDelegation } from '../src/attenuate.js';
import { validateDelegationChain } from '../src/chain.js';

const T0 = 1_757_800_000;

function party(did: string, authority: Authority, validFrom = T0, validUntil?: number): DelegationParty {
  return { did, authority, validFrom, validUntil };
}

const PARENT_AUTHORITY: Authority = {
  actions: ['refund:create', 'order:read'],
  resources: ['tenant:acme'],
  audience: ['did:web:payments.example:agent'],
  limits: { amount: 500, currency: 'SAR', perDay: 20 },
  delegationDepth: 1,
};

const ROOT = 'did:web:acme.example:org';
const CHILD = 'did:key:zChildAgent';
const GRANDCHILD = 'did:key:zGrandChildAgent';

describe('attenuation — valid narrowing', () => {
  it('accepts a strictly narrower child (spec example)', () => {
    const result = validateDelegation({
      parent: party(ROOT, PARENT_AUTHORITY),
      child: party(CHILD, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        audience: ['did:web:payments.example:agent'],
        limits: { amount: 100, currency: 'SAR', perDay: 5 },
        delegationDepth: 0,
      }, T0 + 10, T0 + 1000),
    });
    expect(result).toEqual({ ok: true, reasonCodes: ['ATTENUATION_VERIFIED'] });
  });

  it('accepts a child adding a constraint the parent never had', () => {
    const result = validateDelegation({
      parent: party(ROOT, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        delegationDepth: 1,
      }),
      child: party(CHILD, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        audience: ['did:web:payments.example:agent'],
        limits: { amount: 50, currency: 'SAR' },
        delegationDepth: 0,
      }, T0, T0 + 100),
    });
    expect(result.ok).toBe(true);
  });
});

describe('attenuation — escalations', () => {
  it('rejects amount escalation 500 → 1000 (spec example)', () => {
    const result = validateDelegation({
      parent: party(ROOT, PARENT_AUTHORITY),
      child: party(CHILD, { ...PARENT_AUTHORITY, limits: { amount: 1000, currency: 'SAR' }, delegationDepth: 0 }),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reasonCodes).toContain('DELEGATION_LIMIT_ESCALATION');
    const amount = result.failedConstraints.find((c) => c.field === 'authority.limits.amount');
    expect(amount).toMatchObject({ actual: 1000, operator: '<=', expected: 500 });
  });

  it('rejects a child limit removed under a set parent limit (unlimited = broader)', () => {
    const result = validateDelegation({
      parent: party(ROOT, PARENT_AUTHORITY),
      child: party(CHILD, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        delegationDepth: 0,
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reasonCodes).toContain('DELEGATION_LIMIT_ESCALATION');
      expect(result.reasonCodes).toContain('DELEGATION_AUDIENCE_ESCALATION');
    }
  });

  it('rejects action escalation (spec example: order:read → refund:create)', () => {
    const result = validateDelegation({
      parent: party(ROOT, { actions: ['order:read'], resources: ['tenant:acme'], delegationDepth: 1 }),
      child: party(CHILD, { actions: ['refund:create'], resources: ['tenant:acme'], delegationDepth: 0 }),
    });
    expect(result).toMatchObject({
      ok: false,
      reasonCodes: ['DELEGATION_ACTION_ESCALATION'],
    });
  });

  it('rejects resource escalation', () => {
    const result = validateDelegation({
      parent: party(ROOT, { actions: ['refund:create'], resources: ['tenant:acme'], delegationDepth: 1 }),
      child: party(CHILD, { actions: ['refund:create'], resources: ['tenant:beta'], delegationDepth: 0 }),
    });
    expect(result).toMatchObject({ ok: false, reasonCodes: ['DELEGATION_RESOURCE_ESCALATION'] });
  });

  it('rejects audience escalation (added counterparty and dropped constraint)', () => {
    const base = { actions: ['refund:create'], resources: ['tenant:acme'] };
    const parent = party(ROOT, { ...base, audience: ['did:web:payments.example:agent'], delegationDepth: 1 });
    const added = validateDelegation({
      parent,
      child: party(CHILD, { ...base, audience: ['did:web:payments.example:agent', 'did:web:evil.example'], delegationDepth: 0 }),
    });
    expect(added.ok).toBe(false);
    if (!added.ok) expect(added.reasonCodes).toContain('DELEGATION_AUDIENCE_ESCALATION');

    const dropped = validateDelegation({
      parent,
      child: party(CHILD, { ...base, delegationDepth: 0 }),
    });
    expect(dropped.ok).toBe(false);
    if (!dropped.ok) expect(dropped.reasonCodes).toContain('DELEGATION_AUDIENCE_ESCALATION');
  });

  it('rejects currency loosening (SAR → USD)', () => {
    const result = validateDelegation({
      parent: party(ROOT, PARENT_AUTHORITY),
      child: party(CHILD, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        audience: ['did:web:payments.example:agent'],
        limits: { amount: 100, currency: 'USD' },
        delegationDepth: 0,
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasonCodes).toContain('DELEGATION_LIMIT_ESCALATION');
  });

  it('rejects perDay escalation', () => {
    const result = validateDelegation({
      parent: party(ROOT, PARENT_AUTHORITY),
      child: party(CHILD, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        audience: ['did:web:payments.example:agent'],
        limits: { amount: 100, currency: 'SAR', perDay: 200 },
        delegationDepth: 0,
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasonCodes).toContain('DELEGATION_LIMIT_ESCALATION');
  });

  it('rejects credential-window time escalation (earlier start, later expiry, dropped expiry)', () => {
    const parent = party(ROOT, PARENT_AUTHORITY, T0 + 100, T0 + 1000);
    const base = {
      actions: ['refund:create'],
      resources: ['tenant:acme'],
      audience: ['did:web:payments.example:agent'],
      limits: { amount: 100, currency: 'SAR' },
      delegationDepth: 0,
    };
    const earlier = validateDelegation({
      parent,
      child: party(CHILD, base, T0 + 99, T0 + 1000),
    });
    expect(earlier.ok).toBe(false);
    if (!earlier.ok) expect(earlier.reasonCodes).toContain('DELEGATION_TIME_ESCALATION');

    const later = validateDelegation({
      parent,
      child: party(CHILD, base, T0 + 100, T0 + 1001),
    });
    expect(later.ok).toBe(false);
    if (!later.ok) expect(later.reasonCodes).toContain('DELEGATION_TIME_ESCALATION');

    const eternal = validateDelegation({
      parent,
      child: party(CHILD, base, T0 + 100),
    });
    expect(eternal.ok).toBe(false);
    if (!eternal.ok) expect(eternal.reasonCodes).toContain('DELEGATION_TIME_ESCALATION');
  });

  it('rejects authority-level ISO time escalation (spec example: 2026-10-01 → 2026-11-01)', () => {
    const result = validateDelegation({
      parent: party(ROOT, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        delegationDepth: 1,
        validUntil: '2026-10-01T00:00:00Z',
      }),
      child: party(CHILD, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        delegationDepth: 0,
        validUntil: '2026-11-01T00:00:00Z',
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasonCodes).toContain('DELEGATION_TIME_ESCALATION');
  });

  it('fails closed on an unparseable authority-level date', () => {
    const result = validateDelegation({
      parent: party(ROOT, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        delegationDepth: 1,
        validUntil: 'not-a-date',
      }),
      child: party(CHILD, {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        delegationDepth: 0,
        validUntil: '2026-11-01T00:00:00Z',
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasonCodes).toContain('DELEGATION_TIME_ESCALATION');
  });

  it('rejects depth violations (spec example: depth 1 → no further level)', () => {
    const childDepth1 = validateDelegation({
      parent: party(ROOT, { ...PARENT_AUTHORITY, delegationDepth: 1 }),
      child: party(CHILD, { ...PARENT_AUTHORITY, delegationDepth: 1 }),
    });
    expect(childDepth1.ok).toBe(false);
    if (!childDepth1.ok) expect(childDepth1.reasonCodes).toContain('DELEGATION_DEPTH_EXCEEDED');

    const exhausted = validateDelegation({
      parent: party(ROOT, { ...PARENT_AUTHORITY, delegationDepth: 0 }),
      child: party(CHILD, { ...PARENT_AUTHORITY, delegationDepth: 0 }),
    });
    expect(exhausted.ok).toBe(false);
    if (!exhausted.ok) expect(exhausted.reasonCodes).toContain('DELEGATION_DEPTH_EXCEEDED');
  });

  it('rejects self-delegation as a cycle', () => {
    const result = validateDelegation({
      parent: party(ROOT, PARENT_AUTHORITY),
      child: party(ROOT, { ...PARENT_AUTHORITY, delegationDepth: 0 }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasonCodes).toContain('DELEGATION_CYCLE');
  });

  it('collects every escalated dimension in one denial', () => {
    const result = validateDelegation({
      parent: party(ROOT, PARENT_AUTHORITY, T0, T0 + 1000),
      child: party(CHILD, {
        actions: ['refund:create', 'payment:create'],
        resources: ['tenant:acme', 'tenant:beta'],
        audience: ['did:web:payments.example:agent', 'did:web:evil.example'],
        limits: { amount: 900, currency: 'USD', perDay: 50 },
        delegationDepth: 1,
      }, T0 - 10, T0 + 2000),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reasonCodes).toEqual([
        'DELEGATION_ACTION_ESCALATION',
        'DELEGATION_RESOURCE_ESCALATION',
        'DELEGATION_AUDIENCE_ESCALATION',
        'DELEGATION_LIMIT_ESCALATION',
        'DELEGATION_LIMIT_ESCALATION',
        'DELEGATION_LIMIT_ESCALATION',
        'DELEGATION_TIME_ESCALATION',
        'DELEGATION_TIME_ESCALATION',
        'DELEGATION_DEPTH_EXCEEDED',
      ]);
    }
  });
});

describe('chain validation', () => {
  const rootAuth: Authority = {
    actions: ['refund:create', 'order:read'],
    resources: ['tenant:acme'],
    limits: { amount: 500, currency: 'SAR' },
    delegationDepth: 2,
  };

  it('accepts a valid two-level attenuation chain', () => {
    const c1: DelegationParty = {
      did: CHILD,
      authority: {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        limits: { amount: 200, currency: 'SAR' },
        delegationDepth: 1,
      },
      validFrom: T0 + 1,
      validUntil: T0 + 900,
    };
    const c2: DelegationParty = {
      did: GRANDCHILD,
      authority: {
        actions: ['refund:create'],
        resources: ['tenant:acme'],
        limits: { amount: 50, currency: 'SAR' },
        delegationDepth: 0,
      },
      validFrom: T0 + 2,
      validUntil: T0 + 800,
    };
    expect(validateDelegationChain([party(ROOT, rootAuth), c1, c2]).ok).toBe(true);
  });

  it('rejects a chain with a repeated DID (cycle)', () => {
    const c1: DelegationParty = {
      did: CHILD,
      authority: { actions: ['refund:create'], resources: ['tenant:acme'], delegationDepth: 1 },
      validFrom: T0,
      validUntil: T0 + 900,
    };
    const cycleBack: DelegationParty = {
      did: ROOT,
      authority: { actions: ['refund:create'], resources: ['tenant:acme'], delegationDepth: 0 },
      validFrom: T0,
      validUntil: T0 + 800,
    };
    const result = validateDelegationChain([party(ROOT, rootAuth), c1, cycleBack]);
    expect(result).toMatchObject({ ok: false, reasonCodes: ['DELEGATION_CYCLE'] });
  });

  it('propagates the failing link\'s reason codes', () => {
    const badMiddle: DelegationParty = {
      did: CHILD,
      authority: {
        actions: ['payment:create'],
        resources: ['tenant:acme'],
        delegationDepth: 1,
      },
      validFrom: T0,
      validUntil: T0 + 900,
    };
    const result = validateDelegationChain([party(ROOT, rootAuth), badMiddle]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasonCodes).toContain('DELEGATION_ACTION_ESCALATION');
  });
});
