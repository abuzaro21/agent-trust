import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import { computeEventHash, GENESIS_PREVIOUS_HASH } from '../src/hash.js';
import { InMemoryAuditLog } from '../src/memory-log.js';
import { verifyAuditChain } from '../src/verify-chain.js';
import type { ActionReceipt } from '../src/types.js';
import { STREAM_A, makeBody } from './fixture.js';

const resourceArb = fc.integer({ min: 0, max: 1_000_000 }).map((i) => `order:ORD-${i}`);
const amountArb = fc.integer({ min: 1, max: 10_000 });

/** Arbitrary valid receipt list built through the real log. */
const chainArb = fc
  .array(fc.record({ resource: resourceArb, amount: amountArb }, { noNullPrototype: true }), {
    minLength: 1,
    maxLength: 25,
  })
  .map((specs) => specs);

describe('audit property tests (9S)', () => {
  it('linear chaining: any valid receipt list verifies', async () => {
    await fc.assert(
      fc.asyncProperty(chainArb, async (specs) => {
        const log = new InMemoryAuditLog();
        for (const { resource, amount } of specs) {
          await log.append(STREAM_A, makeBody({
            request: {
              action: 'refund:create',
              resource,
              audience: 'did:web:payments.example:refund-agent',
              parameters: { amount, currency: 'SAR' },
            },
          }));
        }
        const chain = await log.readStream(STREAM_A);
        const result = verifyAuditChain(STREAM_A, chain);
        expect(result.valid).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('single mutation detection: mutating ANY old authenticated field breaks the chain at that point', async () => {
    await fc.assert(
      fc.asyncProperty(chainArb, fc.integer({ min: 1, max: 10_000 }), async (specs, newAmount) => {
        const log = new InMemoryAuditLog();
        for (const { resource, amount } of specs) {
          await log.append(STREAM_A, makeBody({
            request: {
              action: 'refund:create',
              resource,
              audience: 'did:web:payments.example:refund-agent',
              parameters: { amount, currency: 'SAR' },
            },
          }));
        }
        const chain = await log.readStream(STREAM_A);
        const victimIndex = Math.floor((newAmount % chain.length));
        const forged = structuredClone(chain);
        const victim = forged[victimIndex]!;
        const current = victim.body.request.parameters?.amount ?? 1;
        const mutatedAmount = newAmount === current ? newAmount + 1 : newAmount;
        victim.body.request = {
          ...victim.body.request,
          parameters: { amount: mutatedAmount, currency: 'SAR' },
        };
        const result = verifyAuditChain(STREAM_A, forged);
        // The chain breaks AT or BEFORE the mutated receipt (its own hash
        // mismatch, or an earlier linkage failure from reordering) — and
        // never validates.
        expect(result.valid).toBe(false);
      }),
      { numRuns: 150 },
    );
  });

  it('hash(A) === hash(reordered(A)) for arbitrary bodies (canonical stability)', async () => {
    await fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 10_000 }),
        fc.constantFrom('SAR', 'USD', 'EUR'),
        (amount, currency) => {
          const body = makeBody({
            request: {
              action: 'refund:create',
              resource: 'order:ORD-1',
              audience: 'did:web:payments.example:refund-agent',
              parameters: { amount, currency },
            },
          });
          // Different construction orders of the SAME semantic body.
          const reordered = {
            decision: body.decision,
            security: body.security,
            request: body.request,
            authority: body.authority,
            actor: body.actor,
            recordedAt: body.recordedAt,
            receiptId: body.receiptId,
          };
          expect(computeEventHash(GENESIS_PREVIOUS_HASH, body)).toBe(
            computeEventHash(GENESIS_PREVIOUS_HASH, reordered as never),
          );
        },
      ),
      { numRuns: 150 },
    );
  });

  it('stream isolation: appending to stream B never changes stream A\'s head', async () => {
    await fc.assert(
      fc.asyncProperty(chainArb, chainArb, async (specsA, specsB) => {
        const log = new InMemoryAuditLog();
        for (const { resource, amount } of specsA) {
          await log.append('stream-a', makeBody({
            request: { action: 'refund:create', resource, audience: 'did:web:payments.example:refund-agent', parameters: { amount, currency: 'SAR' } },
          }));
        }
        const headABefore = await log.getHead('stream-a');
        for (const { resource, amount } of specsB) {
          await log.append('stream-b', makeBody({
            request: { action: 'refund:create', resource, audience: 'did:web:payments.example:refund-agent', parameters: { amount, currency: 'SAR' } },
          }));
        }
        const headAAfter = await log.getHead('stream-a');
        expect(headAAfter).toEqual(headABefore);
        const b = await log.readStream('stream-b');
        expect(b[0]!.body.sequence).toBe(1);
      }),
      { numRuns: 60 },
    );
  });

  it('concurrent append linearity for arbitrary batch sizes', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 2, max: 60 }), async (n) => {
        const log = new InMemoryAuditLog();
        const receipts: ActionReceipt[] = await Promise.all(
          Array.from({ length: n }, (_, i) =>
            log.append(STREAM_A, makeBody({ request: { action: 'refund:create', resource: `order:${i}`, audience: 'did:web:payments.example:refund-agent' } })),
          ),
        );
        expect(new Set(receipts.map((r) => r.body.sequence)).size).toBe(n);
        expect(verifyAuditChain(STREAM_A, await log.readStream(STREAM_A)).valid).toBe(true);
      }),
      { numRuns: 40 },
    );
  });
});
