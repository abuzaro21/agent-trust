import { beforeAll, describe, expect, it } from 'vitest';

import { AuditCheckpointService, verifyAuditAgainstCheckpoint, verifyCheckpointSignature } from '../src/checkpoint.js';
import { InMemoryAuditLog } from '../src/memory-log.js';
import { verifyAuditChain } from '../src/verify-chain.js';
import type { ActionReceipt, SignedAuditCheckpoint } from '../src/types.js';
import { AUDITOR_DID, NOW, NOW_UNIX, STREAM_A, auditWorld, makeBody } from './fixture.js';

describe('signed checkpoints (9I/9K/9N/9O/9P)', () => {
  let world: Awaited<ReturnType<typeof auditWorld>>;
  let service: AuditCheckpointService;
  let receipts: ActionReceipt[];
  let checkpoint: SignedAuditCheckpoint;

  beforeAll(async () => {
    world = await auditWorld();
    service = new AuditCheckpointService(world.anchorSigner);
    const log = new InMemoryAuditLog();
    for (let i = 0; i < 5; i++) {
      await log.append(STREAM_A, makeBody({ receiptId: `rcpt_ckpt_${String(i).padStart(4, '0')}` }));
    }
    receipts = await log.readStream(STREAM_A);
    checkpoint = await service.issue({
      checkpointId: 'ckpt_test_0001',
      streamId: STREAM_A,
      receipts,
      issuedAt: NOW,
    });
  });

  it('issues a checkpoint signed by the anchor DID and verifies it', async () => {
    expect(checkpoint.signerDid).toBe(AUDITOR_DID);
    expect(checkpoint.payload.sequence).toBe(5);
    expect(checkpoint.payload.headHash).toBe(receipts[4]!.eventHash);
    const verified = await verifyCheckpointSignature({
      checkpoint,
      didResolver: world.resolver,
      opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX },
    });
    expect(verified).toEqual({
      valid: true,
      streamId: STREAM_A,
      sequence: 5,
      headHash: checkpoint.payload.headHash,
    });
    // The trusted chain agrees with the checkpoint (control).
    expect(
      verifyAuditAgainstCheckpoint({ streamId: STREAM_A, receipts, checkpoint, checkpointVerified: verified }).valid,
    ).toBe(true);
  });

  it('9N — full-chain rewrite: internally coherent forged chain FAILS against the trusted checkpoint', async () => {
    // 1. Attacker edits an OLD receipt (5000 instead of 120)…
    const forged = structuredClone(receipts);
    (forged[1]!.body.request.parameters as { amount: number }).amount = 5000;
    // 2. …and recomputes EVERY eventHash after it, producing a perfectly
    //    self-consistent replacement chain.
    for (let i = 1; i < forged.length; i++) {
      const { computeEventHash } = await import('../src/hash.js');
      forged[i] = {
        body: forged[i]!.body,
        previousHash: i === 1 ? forged[0]!.eventHash : forged[i - 1]!.eventHash,
        eventHash: computeEventHash(i === 1 ? forged[0]!.eventHash : forged[i - 1]!.eventHash, forged[i]!.body),
      };
    }
    // 3. The rewritten chain passes its OWN internal verification…
    expect(verifyAuditChain(STREAM_A, forged).valid).toBe(true);
    // 4. …but FAILS against the checkpoint issued before the attack:
    //    this is exactly why signed checkpoints exist.
    const verified = await verifyCheckpointSignature({
      checkpoint,
      didResolver: world.resolver,
      opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX },
    });
    const against = verifyAuditAgainstCheckpoint({ streamId: STREAM_A, receipts: forged, checkpoint, checkpointVerified: verified });
    expect(against).toEqual({
      valid: false,
      reasonCodes: ['AUDIT_CHECKPOINT_MISMATCH'],
      detail: 'recomputed head does not match the checkpoint',
    });
  });

  it('9P — truncation: 100-event chain cut to 80 FAILS against a checkpoint at 100', async () => {
    const log = new InMemoryAuditLog();
    for (let i = 0; i < 100; i++) {
      await log.append(STREAM_A, makeBody({ receiptId: `rcpt_trunc_${String(i).padStart(4, '0')}` }));
    }
    const full = await log.readStream(STREAM_A);
    const cp = await service.issue({ checkpointId: 'ckpt_trunc_0001', streamId: STREAM_A, receipts: full, issuedAt: NOW });
    const verified = await verifyCheckpointSignature({ checkpoint: cp, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(verified.valid).toBe(true);

    const truncated = full.slice(0, 80);
    // The surviving prefix IS internally valid…
    expect(verifyAuditChain(STREAM_A, truncated).valid).toBe(true);
    // …but cannot be hidden from the checkpoint.
    const against = verifyAuditAgainstCheckpoint({ streamId: STREAM_A, receipts: truncated, checkpoint: cp, checkpointVerified: verified });
    expect(against.valid).toBe(false);
    if (!against.valid) {
      expect(against.reasonCodes).toEqual(['AUDIT_SEQUENCE_INVALID']);
      expect(against.detail).toContain('truncation');
    }
  });

  it('9O — checkpoint forgery: all eight attack shapes are rejected', async () => {
    const baseVerified = await verifyCheckpointSignature({ checkpoint, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(baseVerified.valid).toBe(true);

    // 1. wrong signing key (evil anchor, correct DID label is impossible —
    //    its key differs, so signature fails)
    const evil = await new AuditCheckpointService(world.evilSigner).issue({
      checkpointId: 'ckpt_evil_0001',
      streamId: STREAM_A,
      receipts,
      issuedAt: NOW,
    });
    // Evil signed with a DIFFERENT DID: signer trust rejects it.
    const evilVerified = await verifyCheckpointSignature({ checkpoint: evil, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(evilVerified).toMatchObject({ valid: false, reasonCodes: ['AUDIT_SIGNER_UNTRUSTED'] });

    // 2. modified checkpoint payload (headHash claim) with copied signature
    const tamperedPayload: SignedAuditCheckpoint = {
      ...checkpoint,
      payload: { ...checkpoint.payload, headHash: 'a'.repeat(64) },
    };
    const tamperedVerified = await verifyCheckpointSignature({ checkpoint: tamperedPayload, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(tamperedVerified).toMatchObject({ valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'] });

    // 3. modified head hash INSIDE the signed payload (re-signed is covered
    //    by 1; here the jws/payload divergence is detected)
    const divergent: SignedAuditCheckpoint = {
      payload: { ...checkpoint.payload, sequence: 99 },
      signerDid: checkpoint.signerDid,
      kid: checkpoint.kid,
      jws: checkpoint.jws,
    };
    const divergentVerified = await verifyCheckpointSignature({ checkpoint: divergent, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(divergentVerified).toMatchObject({ valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'] });

    // 4. wrong stream claim
    const wrongStreamVerified = await verifyCheckpointSignature({
      checkpoint,
      didResolver: world.resolver,
      opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX },
    });
    expect(wrongStreamVerified.valid).toBe(true);
    const streamMismatch = verifyAuditAgainstCheckpoint({
      streamId: 'another-stream',
      receipts,
      checkpoint,
      checkpointVerified: wrongStreamVerified,
    });
    expect(streamMismatch).toMatchObject({ valid: false, reasonCodes: ['AUDIT_CHECKPOINT_MISMATCH'] });

    // 5. wrong sequence claim vs actual chain
    const shortChain = receipts.slice(0, 3);
    const againstShort = verifyAuditAgainstCheckpoint({ streamId: STREAM_A, receipts: shortChain, checkpoint, checkpointVerified: baseVerified });
    expect(againstShort).toMatchObject({ valid: false, reasonCodes: ['AUDIT_SEQUENCE_INVALID'] });

    // 6. wrong signer DID expectation
    const wrongSigner = await verifyCheckpointSignature({ checkpoint, didResolver: world.resolver, opts: { expectedSignerDid: 'did:web:someone-else.example', now: NOW_UNIX } });
    expect(wrongSigner).toMatchObject({ valid: false, reasonCodes: ['AUDIT_SIGNER_UNTRUSTED'] });

    // 7. invalid kid (points at a method that does not exist)
    const badKid: SignedAuditCheckpoint = {
      payload: checkpoint.payload,
      signerDid: checkpoint.signerDid,
      kid: `${AUDITOR_DID}#does-not-exist`,
      jws: checkpoint.jws,
    };
    const badKidVerified = await verifyCheckpointSignature({ checkpoint: badKid, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(badKidVerified.valid).toBe(false);
    if (!badKidVerified.valid) {
      expect(['AUDIT_CHECKPOINT_INVALID', 'AUDIT_SIGNER_UNTRUSTED']).toContain(badKidVerified.reasonCodes[0]);
    }

    // 8. malformed signature bytes
    const [h, p] = checkpoint.jws.split('.') as [string, string, string];
    const malformed: SignedAuditCheckpoint = { ...checkpoint, jws: `${h}.${p}.!!!not-base64url!!!` };
    const malformedVerified = await verifyCheckpointSignature({ checkpoint: malformed, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(malformedVerified).toMatchObject({ valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'] });
  });

  it('checkpoint of an empty stream anchors sequence 0 / genesis head', async () => {
    const empty = await service.issue({ checkpointId: 'ckpt_empty_0001', streamId: STREAM_A, receipts: [], issuedAt: NOW });
    expect(empty.payload.sequence).toBe(0);
    expect(empty.payload.headHash).toBe('0'.repeat(64));
    const verified = await verifyCheckpointSignature({ checkpoint: empty, didResolver: world.resolver, opts: { expectedSignerDid: AUDITOR_DID, now: NOW_UNIX } });
    expect(verified.valid).toBe(true);
  });
});
