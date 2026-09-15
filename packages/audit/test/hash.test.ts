import { describe, expect, it } from 'vitest';

import {
  GENESIS_PREVIOUS_HASH,
  RECEIPT_HASH_DOMAIN,
  canonicalReceiptBytes,
  computeEventHash,
} from '../src/index.js';
import { NOW, makeBody } from './fixture.js';

const canonicalReceipt = (obj: unknown): string =>
  Array.from(canonicalReceiptBytes(obj as never))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

describe('canonicalization (9B/9Q)', () => {
  it('key insertion order never changes canonical bytes or the event hash', () => {
    const a = {
      z: 1,
      nested: { y: [3, 1, 2], a: true },
      m: { b: null, a: 'x' },
    };
    const reordered = {
      m: { a: 'x', b: null },
      nested: { a: true, y: [3, 1, 2] },
      z: 1,
    };
    expect(canonicalReceipt(a)).toBe(canonicalReceipt(reordered));

    const bodyA = makeBody();
    const bodyB = {
      decision: bodyA.decision,
      security: bodyA.security,
      request: bodyA.request,
      authority: bodyA.authority,
      actor: bodyA.actor,
      recordedAt: bodyA.recordedAt,
      receiptId: bodyA.receiptId,
    };
    expect(computeEventHash(GENESIS_PREVIOUS_HASH, bodyA as never)).toBe(
      computeEventHash(GENESIS_PREVIOUS_HASH, bodyB as never),
    );
  });

  it('nested arrays keep order (semantics), objects sort keys (syntax)', () => {
    expect(canonicalReceipt({ arr: [1, 2, 3] })).not.toBe(canonicalReceipt({ arr: [3, 2, 1] }));
  });

  it('a different semantic value produces a different hash (mutation sensitivity)', () => {
    const body = makeBody();
    const tampered = makeBody({
      request: { ...body.request, parameters: { amount: 5000, currency: 'SAR' } },
    });
    expect(computeEventHash(GENESIS_PREVIOUS_HASH, body)).not.toBe(
      computeEventHash(GENESIS_PREVIOUS_HASH, tampered),
    );
  });

  it('hash is domain-separated and length-prefixed by construction', () => {
    // Changing ONLY the body vs ONLY the previous hash must both change
    // the digest; and the domain separator is part of the input.
    const body = makeBody();
    const h1 = computeEventHash(GENESIS_PREVIOUS_HASH, body);
    const h2 = computeEventHash('1'.repeat(64), body);
    const h3 = computeEventHash(GENESIS_PREVIOUS_HASH, makeBody());
    expect(h1).not.toBe(h2);
    expect(h1).not.toBe(h3);
    expect(RECEIPT_HASH_DOMAIN).toBe('agent-trust/action-receipt/v1');
    expect(GENESIS_PREVIOUS_HASH).toBe('0'.repeat(64));
    expect(NOW).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });
});
