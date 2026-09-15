import { describe, expect, it } from 'vitest';

import { InMemoryAuditLog } from '../src/memory-log.js';
import { verifyAuditChain } from '../src/verify-chain.js';
import { STREAM_A, STREAM_B, makeBody, makeDenyBody } from './fixture.js';

describe('InMemoryAuditLog — append/chain semantics', () => {
  it('appends ALLOW and DENY receipts into one linear chain (9T)', async () => {
    const log = new InMemoryAuditLog();
    const allow = await log.append(STREAM_A, makeBody());
    const deny = await log.append(STREAM_A, makeDenyBody());
    expect(allow.body.sequence).toBe(1);
    expect(allow.previousHash).toBe('0'.repeat(64));
    expect(deny.body.sequence).toBe(2);
    expect(deny.previousHash).toBe(allow.eventHash);
    const head = await log.getHead(STREAM_A);
    expect(head).toEqual({ streamId: STREAM_A, sequence: 2, headHash: deny.eventHash });
    expect(verifyAuditChain(STREAM_A, await log.readStream(STREAM_A)).valid).toBe(true);
  });

  it('stamps streamId itself — callers cannot omit or spoof it', async () => {
    const log = new InMemoryAuditLog();
    const receipt = await log.append(STREAM_A, makeBody());
    expect(receipt.body.streamId).toBe(STREAM_A);
  });

  it('streams are isolated (9E): separate sequence and head per stream', async () => {
    const log = new InMemoryAuditLog();
    await log.append(STREAM_A, makeBody());
    await log.append(STREAM_A, makeBody());
    const b1 = await log.append(STREAM_B, makeBody());
    expect(b1.body.sequence).toBe(1); // stream B is untouched by stream A
    expect(b1.previousHash).toBe('0'.repeat(64));
    const headA = await log.getHead(STREAM_A);
    const headB = await log.getHead(STREAM_B);
    expect(headA!.sequence).toBe(2);
    expect(headB!.sequence).toBe(1);
    expect(headA!.headHash).not.toBe(headB!.headHash);
  });

  it('100-way concurrent append → exactly 100 receipts, contiguous 1..100, one chain, zero forks (9G/9R)', async () => {
    const log = new InMemoryAuditLog();
    const receipts = await Promise.all(
      Array.from({ length: 100 }, (_, i) =>
        log.append(STREAM_A, makeBody({
          request: {
            action: 'refund:create',
            resource: `order:ORD-${i}`,
            audience: 'did:web:payments.example:refund-agent',
          },
        })),
      ),
    );
    expect(receipts.length).toBe(100);
    const sequences = receipts.map((r) => r.body.sequence).sort((a, b) => a - b);
    expect(sequences).toEqual(Array.from({ length: 100 }, (_, i) => i + 1));
    // One linear chain: every receipt's previousHash is the prior eventHash.
    const sorted = [...receipts].sort((a, b) => a.body.sequence - b.body.sequence);
    expect(sorted[0]!.previousHash).toBe('0'.repeat(64));
    for (let i = 1; i < sorted.length; i++) {
      expect(sorted[i]!.previousHash).toBe(sorted[i - 1]!.eventHash);
    }
    // The stored chain verifies and the head is the LAST event's hash.
    const verification = verifyAuditChain(STREAM_A, await log.readStream(STREAM_A));
    expect(verification.valid).toBe(true);
    expect(verification).toMatchObject({ receipts: 100, headHash: sorted[99]!.eventHash });
    const heads = await Promise.all([log.getHead(STREAM_A), log.getHead(STREAM_A)]);
    expect(heads[0]).toEqual(heads[1]);
  });

  it('1000-way concurrent stress append stays linear', async () => {
    const log = new InMemoryAuditLog();
    const receipts = await Promise.all(
      Array.from({ length: 1000 }, (_, i) => log.append(STREAM_A, makeBody({ receiptId: `rcpt_stress_${i}` }))),
    );
    expect(new Set(receipts.map((r) => r.body.sequence)).size).toBe(1000);
    expect(verifyAuditChain(STREAM_A, await log.readStream(STREAM_A)).valid).toBe(true);
  }, 30_000);

  it('empty stream head is null and empty chain verifies with genesis head', async () => {
    const log = new InMemoryAuditLog();
    expect(await log.getHead('nothing')).toBeNull();
    expect(verifyAuditChain('nothing', [])).toEqual({
      valid: true,
      receipts: 0,
      headHash: '0'.repeat(64),
    });
  });
});
