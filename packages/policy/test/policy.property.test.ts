import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { join } from 'node:path';

import {
  loadOpaWasmPolicyEngine,
  type OpaWasmPolicyEngine,
} from '../src/index.js';
import {
  CASE_A_ALLOW,
  CASE_B_DENY,
  canonicalPolicyInput,
  REFUND_AGENT_DID,
} from './fixture.js';
import { AMOUNT_MAX, requestFactsArb } from './generators.js';

const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');

describe('property-based policy tests (8N)', () => {
  let engine: OpaWasmPolicyEngine;

  beforeAll(async () => {
    const result = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
    if (!result.ok) throw new Error(`engine failed to load: ${result.detail}`);
    engine = result.engine as OpaWasmPolicyEngine;
  });

  it('amount monotonicity: amount ≤ max never denies on the limit; amount > max always does', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: AMOUNT_MAX }),
        fc.integer({ min: AMOUNT_MAX + 1, max: 100_000 }),
        async (under, over) => {
          const underDecision = await engine.evaluate(
            canonicalPolicyInput({ amount: under, currency: 'SAR' }),
          );
          expect(underDecision.effect).toBe('ALLOW');

          const overDecision = await engine.evaluate(
            canonicalPolicyInput({ amount: over, currency: 'SAR' }),
          );
          expect(overDecision.effect).toBe('DENY');
          expect(overDecision.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('action containment: any action outside the delegation denies', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('refund:approve', 'order:read', 'payment:create', 'data:export'),
        async (action) => {
          const decision = await engine.evaluate(canonicalPolicyInput({ action, amount: 100 }));
          expect(decision.effect).toBe('DENY');
          expect(decision.reasonCodes).toEqual(['ACTION_NOT_IN_SCOPE']);
        },
      ),
      { numRuns: 50 },
    );
  });

  it('resource containment: resources outside order:* deny', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('tenant:acme', 'customer:pooled', 'invoice:INV-1', 'payment:PP-1'),
        async (resource) => {
          const decision = await engine.evaluate(
            canonicalPolicyInput({ resource, amount: 100 }),
          );
          expect(decision.effect).toBe('DENY');
          expect(decision.reasonCodes).toEqual(['RESOURCE_NOT_IN_SCOPE']);
        },
      ),
      { numRuns: 50 },
    );
  });

  it('audience containment: targets outside the delegated audience deny', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('did:web:evil.example:agent', 'did:web:other.example:agent'),
        async (audience) => {
          const decision = await engine.evaluate(
            canonicalPolicyInput({ audience, amount: 100 }),
          );
          expect(decision.effect).toBe('DENY');
          expect(decision.reasonCodes).toEqual(['AUDIENCE_MISMATCH']);
        },
      ),
      { numRuns: 30 },
    );
  });

  it('determinism: identical inputs produce byte-identical decisions, always', async () => {
    await fc.assert(
      fc.asyncProperty(requestFactsArb, fc.integer({ min: 2, max: 6 }), async (facts, runs) => {
        const reference = await engine.evaluate(facts);
        for (let i = 0; i < runs; i++) {
          const again = await engine.evaluate(facts);
          expect(again).toEqual(reference);
        }
      }),
      { numRuns: 60 },
    );
  });

  it('boundary: amount exactly at the limit allows; limit+1 denies', async () => {
    const at = await engine.evaluate(canonicalPolicyInput({ amount: AMOUNT_MAX, currency: 'SAR' }));
    expect(at.effect).toBe('ALLOW');
    const over = await engine.evaluate(
      canonicalPolicyInput({ amount: AMOUNT_MAX + 1, currency: 'SAR' }),
    );
    expect(over.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
  });

  it('authority time window: validUntil in the past denies AUTHORITY_EXPIRED regardless of amount', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 100 }),
        async (amount) => {
          const decision = await engine.evaluate(
            canonicalPolicyInput({
              amount,
              currency: 'SAR',
              authority: { validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-09-01T00:00:00Z' },
            }),
          );
          expect(decision.effect).toBe('DENY');
          expect(decision.reasonCodes).toEqual(['AUTHORITY_EXPIRED']);
        },
      ),
      { numRuns: 40 },
    );
  });

  it('canonical scenario pinned: 120 SAR allows, 5000 SAR denies with the exact code', async () => {
    const a = await engine.evaluate(canonicalPolicyInput(CASE_A_ALLOW));
    expect(a.effect).toBe('ALLOW');
    const b = await engine.evaluate(canonicalPolicyInput(CASE_B_DENY));
    expect(b.effect).toBe('DENY');
    expect(b.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    expect(REFUND_AGENT_DID).toBeDefined();
  });
});
