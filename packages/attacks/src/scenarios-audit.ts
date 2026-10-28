import type { AttackScenario } from './types.js';
import { STREAM, NOW, buildAttackWorld, anchorCheckpoint } from './world.js';
import { verifyAuditChain, verifyAuditAgainstCheckpoint, verifyCheckpointSignature } from '@agent-trust/audit';
import { TrustProfileService } from '@agent-trust/trust-profile';

/**
 * Step 13J — Audit attacks. The full-database attacker can rewrite the
 * chain coherently; only the SIGNED CHECKPOINT (trust root) catches it.
 */

/**
 * The production CONSUMER of audit history (TrustProfileService) must fail closed on whatever the verifiers reject.
 * `verifyAuditAgainstCheckpoint` anchors the head hash + sequence; interior-receipt tampering is the chain verifier's
 * job, and the consumer runs BOTH. Returning the consumer's own verdict proves the combination, not a single function.
 */
async function consumerHistoryVerified(
  w: Awaited<ReturnType<typeof buildAttackWorld>>,
  cp: Awaited<ReturnType<typeof anchorCheckpoint>>,
  receipts: Awaited<ReturnType<typeof w.auditLog.readStream>>,
): Promise<boolean> {
  const service = new TrustProfileService({
    didResolver: w.gatewayDeps.didResolver,
    verifier: w.gatewayDeps.verifier,
    attestationStore: w.attestationStore,
    agentCredentialStore: w.agentCredentialStore,
    attestationTrust: w.attestationTrust,
    auditLog: {
      append: (streamId, body) => w.auditLog.append(streamId, body),
      getHead: (streamId) => w.auditLog.getHead(streamId),
      readStream: async () => [...receipts],
    },
    auditCheckpoint: cp,
    auditStreamId: STREAM,
    checkpointSignerDid: 'did:web:trust.example.com:audit',
  });
  const profile = await service.build('did:web:trust.example.com:agents:support', { now: NOW });
  return profile.history.integrity.verified;
}

async function prepare() {
  const w = await buildAttackWorld();
  // Produce a small legitimate history: 1 ALLOW, 1 DENY.
  await w.gateway.handleTask(await w.task({ amount: 120, taskId: 'au_ok' }));
  await w.gateway.handleTask(await w.task({ amount: 5000, taskId: 'au_over' }));
  const cp = await anchorCheckpoint(w, 'ckpt_audit_tamper');
  const receipts = await w.auditLog.readStream(STREAM);
  // Control: the UNTOUCHED history verifies end to end (chain + signed checkpoint). Every scenario below must
  // therefore be detecting its mutation, not a pre-existing breakage.
  const checkpointVerified = await verifyCheckpointSignature({ checkpoint: cp, didResolver: w.gatewayDeps.didResolver });
  const controlIntact =
    verifyAuditChain(STREAM, receipts).valid &&
    verifyAuditAgainstCheckpoint({ streamId: STREAM, receipts, checkpoint: cp, checkpointVerified }).valid;
  const controlConsumerHistoryVerified = await consumerHistoryVerified(w, cp, receipts);
  return { w, cp, receipts, controlIntact, controlConsumerHistoryVerified };
}

export const AUDIT_001: AttackScenario = {
  id: 'AUDIT-001',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Receipt mutation: amount edited in a stored receipt',
  expected: { verdict: 'DETECTED', outcome: 'chain verification fails at the mutated sequence and the history consumer fails closed', reasonCode: 'AUDIT_CHAIN_INVALID' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    const tampered = structuredClone(receipts);
    (tampered[0]!.body.request as { parameters?: { amount?: number } }).parameters = { amount: 1 };
    const chain = verifyAuditChain(STREAM, tampered);
    const consumerOk = await consumerHistoryVerified(w, cp, tampered);
    return {
      outcome: !chain.valid && !consumerOk ? `chain invalid at seq ${chain.firstBrokenSequence}; history consumer fails closed` : 'UNDETECTED',
      verdict: !chain.valid && !consumerOk ? 'DETECTED' : 'BREACHED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, chainValid: chain.valid, consumerHistoryVerified: consumerOk },
    };
  },
};

export const AUDIT_002: AttackScenario = {
  id: 'AUDIT-002',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Decision mutation: ALLOW flipped to DENY in a stored receipt',
  expected: { verdict: 'DETECTED', outcome: 'chain verification fails and the history consumer fails closed', reasonCode: 'AUDIT_CHAIN_INVALID' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    const tampered = structuredClone(receipts);
    const allow = tampered.find((r) => r.body.decision.effect === 'ALLOW');
    if (allow === undefined) throw new Error('fixture: no ALLOW receipt');
    allow.body.decision.effect = 'DENY';
    const chain = verifyAuditChain(STREAM, tampered);
    const consumerOk = await consumerHistoryVerified(w, cp, tampered);
    return {
      outcome: !chain.valid && !consumerOk ? 'mutation detected (chain verifier; history consumer fails closed)' : 'UNDETECTED',
      verdict: !chain.valid && !consumerOk ? 'DETECTED' : 'BREACHED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, chainValid: chain.valid, consumerHistoryVerified: consumerOk },
    };
  },
};

export const AUDIT_003: AttackScenario = {
  id: 'AUDIT-003',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Receipt deletion (middle of the chain)',
  expected: { verdict: 'DETECTED', outcome: 'sequence/hash discontinuity detected', reasonCode: 'AUDIT_SEQUENCE_INVALID' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    const tampered = receipts.filter((_, i) => i !== 1); // drop seq 2
    const chain = verifyAuditChain(STREAM, tampered);
    const consumerOk = await consumerHistoryVerified(w, cp, tampered);
    return {
      outcome: !chain.valid && !consumerOk ? `deletion detected at seq ${chain.firstBrokenSequence}; history consumer fails closed` : 'UNDETECTED',
      verdict: !chain.valid && !consumerOk ? 'DETECTED' : 'BREACHED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, chainValid: chain.valid, consumerHistoryVerified: consumerOk },
    };
  },
};

export const AUDIT_004: AttackScenario = {
  id: 'AUDIT-004',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Receipt reorder',
  expected: { verdict: 'DETECTED', outcome: 'sequence discontinuity detected', reasonCode: 'AUDIT_SEQUENCE_INVALID' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    const tampered = [...receipts];
    const tmp = tampered[0]!;
    tampered[0] = tampered[1]!;
    tampered[1] = tmp;
    const chain = verifyAuditChain(STREAM, tampered);
    const consumerOk = await consumerHistoryVerified(w, cp, tampered);
    return {
      outcome: !chain.valid && !consumerOk ? `reorder detected at seq ${chain.firstBrokenSequence}; history consumer fails closed` : 'UNDETECTED',
      verdict: !chain.valid && !consumerOk ? 'DETECTED' : 'BREACHED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, chainValid: chain.valid, consumerHistoryVerified: consumerOk },
    };
  },
};

export const AUDIT_005: AttackScenario = {
  id: 'AUDIT-005',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Forged receipt inserted into the chain',
  expected: { verdict: 'DETECTED', outcome: 'hash linkage breaks at the forgery (its own hash is self-consistent; only the previousHash link is wrong)', reasonCode: 'AUDIT_CHAIN_INVALID' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    const forged = structuredClone(receipts[0]!);
    forged.body = {
      ...forged.body,
      receiptId: 'rcpt_forged',
      sequence: receipts.length + 1,
      decision: { ...forged.body.decision, effect: 'ALLOW' },
    };
    // The forger appends an event whose own hash IS recomputed correctly (hashes are public SHA-256, there is no
    // chain secret) but whose previousHash points at the wrong predecessor: only the linkage check can catch it.
    const { computeEventHash, GENESIS_PREVIOUS_HASH } = await import('@agent-trust/audit');
    forged.previousHash = GENESIS_PREVIOUS_HASH;
    forged.eventHash = computeEventHash(forged.previousHash, forged.body);
    const tampered = [...receipts, forged];
    const chain = verifyAuditChain(STREAM, tampered);
    const consumerOk = await consumerHistoryVerified(w, cp, tampered);
    return {
      outcome: !chain.valid && !consumerOk ? `forgery detected at seq ${chain.firstBrokenSequence}; history consumer fails closed` : 'UNDETECTED',
      verdict: !chain.valid && !consumerOk ? 'DETECTED' : 'BREACHED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, chainValid: chain.valid, consumerHistoryVerified: consumerOk },
    };
  },
};

export const AUDIT_006: AttackScenario = {
  id: 'AUDIT-006',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Cross-stream substitution: receipts from another stream spliced in',
  expected: { verdict: 'DETECTED', outcome: 'foreign-stream receipts detected', reasonCode: 'AUDIT_CHAIN_INVALID' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    // Build a foreign stream receipt via a second world is heavy; simulate
    // by changing the streamId on a copy — the verifier binds streamId.
    const foreign = structuredClone(receipts[0]!);
    foreign.body.streamId = 'other-stream';
    const tampered = [...receipts];
    tampered[1] = foreign;
    const chain = verifyAuditChain(STREAM, tampered);
    const consumerOk = await consumerHistoryVerified(w, cp, tampered);
    return {
      outcome: !chain.valid && !consumerOk ? `foreign stream detected at seq ${chain.firstBrokenSequence}; history consumer fails closed` : 'UNDETECTED',
      verdict: !chain.valid && !consumerOk ? 'DETECTED' : 'BREACHED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, chainValid: chain.valid, consumerHistoryVerified: consumerOk },
    };
  },
};

export const AUDIT_007: AttackScenario = {
  id: 'AUDIT-007',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Full-chain rewrite: old receipt modified, all later hashes recomputed',
  expected: { verdict: 'DETECTED', outcome: 'rewritten chain is internally coherent BUT the signed checkpoint rejects it', reasonCode: 'AUDIT_CHECKPOINT_MISMATCH' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    // The powerful attacker: mutate an old receipt AND recompute every
    // subsequent event hash so the chain is internally coherent.
    const { computeEventHash, GENESIS_PREVIOUS_HASH } = await import('@agent-trust/audit');
    const rewritten = structuredClone(receipts);
    (rewritten[0]!.body.request as { parameters?: { amount?: number } }).parameters = { amount: 1 };
    let prev = GENESIS_PREVIOUS_HASH;
    for (const r of rewritten) {
      r.previousHash = prev;
      r.eventHash = computeEventHash(prev, r.body);
      prev = r.eventHash;
    }
    const chain = verifyAuditChain(STREAM, rewritten);
    if (!chain.valid) throw new Error('fixture: rewrite should be internally coherent');
    const anchored = verifyAuditAgainstCheckpoint({
      streamId: STREAM,
      receipts: rewritten,
      checkpoint: cp,
      checkpointVerified: await verifyCheckpointSignature({ checkpoint: cp, didResolver: w.gatewayDeps.didResolver }),
    });
    return {
      outcome: !anchored.valid
        ? `coherent rewrite (${rewritten.length} receipts, chain valid) REJECTED by signed checkpoint`
        : 'UNDETECTED — checkpoint accepted the rewrite',
      verdict: !anchored.valid ? 'DETECTED' : 'BREACHED',
      reasonCodes: anchored.valid ? [] : anchored.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, rewrittenChainCoherent: chain.valid, checkpointRejected: !anchored.valid, consumerHistoryVerified: await consumerHistoryVerified(w, cp, rewritten) },
    };
  },
};

export const AUDIT_008: AttackScenario = {
  id: 'AUDIT-008',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Truncation: tail receipts deleted after the checkpoint anchored them',
  expected: { verdict: 'DETECTED', outcome: 'sequence below checkpoint anchor detected', reasonCode: 'AUDIT_SEQUENCE_INVALID' },
  async run() {
    const { w, cp, receipts, controlIntact, controlConsumerHistoryVerified } = await prepare();
    const truncated = receipts.slice(0, -1);
    const anchored = verifyAuditAgainstCheckpoint({
      streamId: STREAM,
      receipts: truncated,
      checkpoint: cp,
      checkpointVerified: await verifyCheckpointSignature({ checkpoint: cp, didResolver: w.gatewayDeps.didResolver }),
    });
    return {
      outcome: !anchored.valid ? `truncation detected (checkpoint at ${cp.payload.sequence}, chain ends at ${truncated.length})` : 'UNDETECTED',
      verdict: !anchored.valid ? 'DETECTED' : 'BREACHED',
      reasonCodes: anchored.valid ? [] : anchored.reasonCodes,
      invariants: { controlIntact, controlConsumerHistoryVerified, anchoredValid: anchored.valid, consumerHistoryVerified: await consumerHistoryVerified(w, cp, truncated) },
    };
  },
};

export const AUDIT_009: AttackScenario = {
  id: 'AUDIT-009',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Forged checkpoint: wrong signer, forged signature, edited payload, or another stream',
  expected: { verdict: 'DETECTED', outcome: 'every checkpoint forgery is rejected by its own gate; the genuine checkpoint verifies under the same pin', reasonCode: 'AUDIT_SIGNER_UNTRUSTED' },
  async run() {
    const { w, cp, receipts, controlIntact } = await prepare();
    const opts = { expectedSignerDid: 'did:web:trust.example.com:audit', now: NOW };
    const verify = (checkpoint: typeof cp) => verifyCheckpointSignature({ checkpoint, didResolver: w.gatewayDeps.didResolver, opts });
    // Control: the genuine checkpoint verifies under the SAME pinned-signer options used against every forgery.
    const genuine = await verify(cp);

    // (a) An attacker checkpoints the SAME chain with their OWN key.
    const { AuditCheckpointService } = await import('@agent-trust/audit');
    const evilService = new AuditCheckpointService(w.evilSigner);
    const wrongSigner = await verify(await evilService.issue({ checkpointId: 'ckpt_evil', streamId: STREAM, receipts, issuedAt: '2026-09-15T12:00:00Z' }));

    // (b) Genuine signer DID and kid, but the signature bytes are corrupted.
    const [h, p, sig] = cp.jws.split('.') as [string, string, string];
    const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const badSignature = await verify({ ...cp, jws: `${h}.${p}.${flipped}` });

    // (c) Genuine signature, but the claimed payload was edited afterwards (valid shape, different head hash).
    const editedPayload = await verify({ ...cp, payload: { ...cp.payload, headHash: '0'.repeat(64) } });

    // (d) A genuine checkpoint presented for a DIFFERENT stream.
    const genuineVerified = await verifyCheckpointSignature({ checkpoint: cp, didResolver: w.gatewayDeps.didResolver, opts });
    const otherStream = verifyAuditAgainstCheckpoint({ streamId: 'other-stream', receipts, checkpoint: cp, checkpointVerified: genuineVerified });

    const codes = (v: { valid: boolean; reasonCodes?: string[] }) => (v.valid ? ['ACCEPTED'] : (v.reasonCodes ?? []));
    const rejected = !wrongSigner.valid && !badSignature.valid && !editedPayload.valid && !otherStream.valid;
    return {
      outcome: rejected ? 'all four checkpoint forgeries rejected; genuine checkpoint verifies' : 'UNDETECTED',
      verdict: rejected && genuine.valid ? 'DETECTED' : 'BREACHED',
      reasonCodes: wrongSigner.valid ? [] : wrongSigner.reasonCodes,
      invariants: {
        controlIntact,
        controlPinnedGenuineVerifies: genuine.valid,
        wrongSignerReasons: codes(wrongSigner),
        badSignatureReasons: codes(badSignature),
        editedPayloadReasons: codes(editedPayload),
        otherStreamReasons: codes(otherStream),
      },
    };
  },
};

export const AUDIT_SCENARIOS = [AUDIT_001, AUDIT_002, AUDIT_003, AUDIT_004, AUDIT_005, AUDIT_006, AUDIT_007, AUDIT_008, AUDIT_009];
