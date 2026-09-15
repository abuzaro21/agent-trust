import { describe, expect, it } from 'vitest';

import { InMemoryAuditLog } from '../src/memory-log.js';
import { verifyAuditChain, chainHeadHash } from '../src/verify-chain.js';
import type { ActionReceipt } from '../src/types.js';
import { STREAM_A, makeBody } from './fixture.js';

async function buildChain(n = 6): Promise<ActionReceipt[]> {
  const log = new InMemoryAuditLog();
  for (let i = 0; i < n; i++) {
    await log.append(STREAM_A, makeBody({
      request: {
        action: 'refund:create',
        resource: `order:ORD-${i}`,
        audience: 'did:web:payments.example:refund-agent',
        parameters: { amount: 120, currency: 'SAR' },
      },
    }));
  }
  return log.readStream(STREAM_A);
}

const expectFail = (result: ReturnType<typeof verifyAuditChain>, atSequence?: number) => {
  expect(result.valid).toBe(false);
  if (!result.valid) {
    expect(result.reasonCodes.length).toBeGreaterThan(0);
    if (atSequence !== undefined) {
      expect(result.firstBrokenSequence).toBe(atSequence);
    }
  }
};

describe('tampering detection (9M) — every attack fails', () => {
  it('payload mutation (amount 120 → 5000)', async () => {
    const chain = await buildChain();
    const forged = structuredClone(chain);
    (forged[2]!.body.request.parameters as { amount: number }).amount = 5000;
    expectFail(verifyAuditChain(STREAM_A, forged), 3);
  });

  it('decision mutation (ALLOW ↔ DENY)', async () => {
    const chain = await buildChain();
    const forged = structuredClone(chain);
    forged[0]!.body.decision.effect = 'DENY';
    expectFail(verifyAuditChain(STREAM_A, forged), 1);
  });

  it('reason-code mutation', async () => {
    const chain = await buildChain();
    const forged = structuredClone(chain);
    forged[3]!.body.decision.reasonCodes = ['IDENTITY_PROOF_INVALID'];
    expectFail(verifyAuditChain(STREAM_A, forged), 4);
  });

  it('policy hash mutation', async () => {
    const chain = await buildChain();
    const forged = structuredClone(chain);
    forged[1]!.body.decision.policy.hash = `sha256:${'f'.repeat(64)}`;
    expectFail(verifyAuditChain(STREAM_A, forged), 2);
  });

  it('receipt deletion → sequence gap', async () => {
    const chain = await buildChain();
    const forged = chain.filter((r) => r.body.sequence !== 3);
    expectFail(verifyAuditChain(STREAM_A, forged), 3);
  });

  it('receipt insertion (fabricated event)', async () => {
    const chain = await buildChain();
    const forged = [...chain];
    forged.splice(2, 0, { ...chain[2]!, body: { ...chain[2]!.body, receiptId: 'rcpt_forged_01' } });
    expectFail(verifyAuditChain(STREAM_A, forged), 3);
  });

  it('receipt reorder (swap two receipts)', async () => {
    const chain = await buildChain();
    const forged = [...chain];
    const tmp = forged[1]!;
    forged[1] = forged[2]!;
    forged[2] = tmp;
    expectFail(verifyAuditChain(STREAM_A, forged), 2);
  });

  it('previousHash mutation', async () => {
    const chain = await buildChain();
    const forged = structuredClone(chain);
    forged[4] = { ...forged[4]!, previousHash: 'a'.repeat(64) };
    expectFail(verifyAuditChain(STREAM_A, forged), 5);
  });

  it('eventHash mutation', async () => {
    const chain = await buildChain();
    const forged = structuredClone(chain);
    forged[2] = { ...forged[2]!, eventHash: 'b'.repeat(64) };
    expectFail(verifyAuditChain(STREAM_A, forged), 3);
  });

  it('cross-stream substitution (receipt of stream B in stream A)', async () => {
    const log = new InMemoryAuditLog();
    await log.append('acme-demo', makeBody());
    const streamB = await log.append('beta-demo', makeBody());
    const chainA = await log.readStream('acme-demo');
    // A receipt that genuinely belongs to stream B placed into stream A's
    // history: the streamId stamp makes the substitution detectable.
    const substituted = [...chainA];
    substituted.splice(1, 0, { ...streamB, previousHash: chainA[0]!.eventHash });
    const result = verifyAuditChain('acme-demo', substituted);
    expect(result.valid).toBe(false);
  });

  it('untouched chain verifies clean (control)', async () => {
    const chain = await buildChain();
    const result = verifyAuditChain(STREAM_A, chain);
    expect(result.valid).toBe(true);
    expect(chainHeadHash(chain)).toBe(chain[chain.length - 1]!.eventHash);
  });

  it('an unanchored FUTURE event beyond a checkpoint is detectable (chain longer than checkpoint)', async () => {
    const chain = await buildChain(4);
    // Simulate checkpoint at sequence 2 vs a chain of 4: the composition
    // test covers the full flow; here we pin the head-hash semantics.
    const headAt2 = chain[1]!.eventHash;
    expect(chainHeadHash(chain.slice(0, 2))).toBe(headAt2);
    expect(chainHeadHash(chain)).not.toBe(headAt2);
  });
});
