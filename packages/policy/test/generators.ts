import fc from 'fast-check';

import {
  canonicalPolicyInput,
  REFUND_AGENT_DID,
  type VerifiedFactsFixture,
} from './fixture.js';
import type { PolicyDecision } from '../src/index.js';

/**
 * fast-check generators for VerifiedFacts with a FIXED delegation
 * (refund:create / order:* / RefundAgent / 500 SAR) and varied requests.
 */

const AMOUNT_MAX = 500;

const actionArb = fc.constantFrom('refund:create', 'refund:approve', 'order:read', 'payment:create');
const resourceArb = fc.constantFrom('order:ORD-918', 'order:ORD-42', 'tenant:acme', 'order:ORD-1');
const currencyArb = fc.constantFrom('SAR', 'USD', 'EUR');
const amountArb = fc.integer({ min: 1, max: 100_000 });

/** Input whose authority is exactly the canonical delegation. */
export const requestFactsArb: fc.Arbitrary<VerifiedFactsFixture> = fc.record(
  {
    action: actionArb,
    resource: resourceArb,
    audience: fc.constantFrom(REFUND_AGENT_DID, 'did:web:evil.example:agent'),
    amount: amountArb,
    currency: currencyArb,
  },
  { noNullPrototype: true },
).map(({ action, resource, audience, amount, currency }) =>
  canonicalPolicyInput({ action, resource, audience, amount, currency }),
);

/** A decision that must equal the reference (full determinism incl. codes). */
export function expectSameDecision(a: PolicyDecision, b: PolicyDecision): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export { AMOUNT_MAX };
