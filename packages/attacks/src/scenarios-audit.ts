import type { AttackScenario } from './types.js';
import { STREAM, NOW, buildAttackWorld, anchorCheckpoint } from './world.js';
import { verifyAuditChain, verifyAuditAgainstCheckpoint, verifyCheckpointSignature } from '@agent-trust/audit';

/**
 * Step 13J — Audit attacks. The full-database attacker can rewrite the
 * chain coherently; only the SIGNED CHECKPOINT (trust root) catches it.
 */

async function prepare() {
  const w = await buildAttackWorld();
  // Produce a small legitimate history: 1 ALLOW, 1 DENY.
  await w.gateway.handleTask(await w.task({ amount: 120, taskId: 'au_ok' }));
  await w.gateway.handleTask(await w.task({ amount: 5000, taskId: 'au_over' }));
  const cp = await anchorCheckpoint(w, 'ckpt_au');
  const receipts = await w.auditLog.readStream(STREAM);
  return { w, cp, receipts };
}

export const AUDIT_001: AttackScenario = {
  id: 'AUDIT-001',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Receipt mutation: amount edited in a stored receipt',
  expected: { outcome: 'chain verification fails at the mutated sequence' },
  async run() {
    const { w, cp, receipts } = await prepare();
    const tampered = structuredClone(receipts);
    (tampered[0]!.body.request as { parameters?: { amount?: number } }).parameters = { amount: 1 };
    const chain = verifyAuditChain(STREAM, tampered);
    const anchored = verifyAuditAgainstCheckpoint({ streamId: STREAM, receipts: tampered, checkpoint: cp, checkpointVerified: await verifyCheckpointSignature({ checkpoint: cp, didResolver: w.gatewayDeps.didResolver }) });
    return {
      outcome: !chain.valid && !anchored.valid ? `chain invalid at seq ${chain.firstBrokenSequence}; checkpoint rejects` : 'UNDETECTED',
      reasonCodes: [...(chain.valid ? [] : chain.reasonCodes), ...(anchored.valid ? [] : anchored.reasonCodes)],
      invariants: { chainValid: chain.valid, anchoredValid: anchored.valid },
    };
  },
};

export const AUDIT_002: AttackScenario = {
  id: 'AUDIT-002',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Decision mutation: ALLOW flipped to DENY in a stored receipt',
  expected: { outcome: 'chain verification fails' },
  async run() {
    const { w, cp, receipts } = await prepare();
    const tampered = structuredClone(receipts);
    const allow = tampered.find((r) => r.body.decision.effect === 'ALLOW');
    if (allow === undefined) throw new Error('fixture: no ALLOW receipt');
    allow.body.decision.effect = 'DENY';
    const chain = verifyAuditChain(STREAM, tampered);
    const anchored = verifyAuditAgainstCheckpoint({ streamId: STREAM, receipts: tampered, checkpoint: cp, checkpointVerified: await verifyCheckpointSignature({ checkpoint: cp, didResolver: w.gatewayDeps.didResolver }) });
    return {
      outcome: !chain.valid && !anchored.valid ? 'mutation detected (chain + checkpoint)' : 'UNDETECTED',
      reasonCodes: [...(chain.valid ? [] : chain.reasonCodes), ...(anchored.valid ? [] : anchored.reasonCodes)],
      invariants: { chainValid: chain.valid, anchoredValid: anchored.valid },
    };
  },
};

export const AUDIT_003: AttackScenario = {
  id: 'AUDIT-003',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Receipt deletion (middle of the chain)',
  expected: { outcome: 'sequence/hash discontinuity detected' },
  async run() {
    const { w, cp, receipts } = await prepare();
    const tampered = receipts.filter((_, i) => i !== 1); // drop seq 2
    const chain = verifyAuditChain(STREAM, tampered);
    return {
      outcome: !chain.valid ? `deletion detected at seq ${chain.firstBrokenSequence}` : 'UNDETECTED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { chainValid: chain.valid },
    };
  },
};

export const AUDIT_004: AttackScenario = {
  id: 'AUDIT-004',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Receipt reorder',
  expected: { outcome: 'sequence discontinuity detected' },
  async run() {
    const { w, cp, receipts } = await prepare();
    const tampered = [...receipts];
    const tmp = tampered[0]!;
    tampered[0] = tampered[1]!;
    tampered[1] = tmp;
    const chain = verifyAuditChain(STREAM, tampered);
    return {
      outcome: !chain.valid ? `reorder detected at seq ${chain.firstBrokenSequence}` : 'UNDETECTED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { chainValid: chain.valid },
    };
  },
};

export const AUDIT_005: AttackScenario = {
  id: 'AUDIT-005',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Forged receipt inserted into the chain',
  expected: { outcome: 'hash linkage breaks at the forgery' },
  async run() {
    const { w, cp, receipts } = await prepare();
    const forged = structuredClone(receipts[0]!);
    forged.body = {
      ...forged.body,
      receiptId: 'rcpt_forged',
      sequence: receipts.length + 1,
      decision: { ...forged.body.decision, effect: 'ALLOW' },
    };
    // Recompute NOTHING else — the forger appends a self-consistent-looking
    // event without the chain secret (the previous hash is stale).
    const tampered = [...receipts, forged];
    const chain = verifyAuditChain(STREAM, tampered);
    return {
      outcome: !chain.valid ? `forgery detected at seq ${chain.firstBrokenSequence}` : 'UNDETECTED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { chainValid: chain.valid },
    };
  },
};

export const AUDIT_006: AttackScenario = {
  id: 'AUDIT-006',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Cross-stream substitution: receipts from another stream spliced in',
  expected: { outcome: 'foreign-stream receipts detected' },
  async run() {
    const { w, cp, receipts } = await prepare();
    // Build a foreign stream receipt via a second world is heavy; simulate
    // by changing the streamId on a copy — the verifier binds streamId.
    const foreign = structuredClone(receipts[0]!);
    foreign.body.streamId = 'other-stream';
    const tampered = [...receipts];
    tampered[1] = foreign;
    const chain = verifyAuditChain(STREAM, tampered);
    return {
      outcome: !chain.valid ? `foreign stream detected at seq ${chain.firstBrokenSequence}` : 'UNDETECTED',
      reasonCodes: chain.valid ? [] : chain.reasonCodes,
      invariants: { chainValid: chain.valid },
    };
  },
};

export const AUDIT_007: AttackScenario = {
  id: 'AUDIT-007',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Full-chain rewrite: old receipt modified, all later hashes recomputed',
  expected: { outcome: 'rewritten chain is internally coherent BUT the signed checkpoint rejects it' },
  async run() {
    const { w, cp, receipts } = await prepare();
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
      reasonCodes: anchored.valid ? [] : anchored.reasonCodes,
      invariants: { rewrittenChainCoherent: chain.valid, checkpointRejected: !anchored.valid },
    };
  },
};

export const AUDIT_008: AttackScenario = {
  id: 'AUDIT-008',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Truncation: tail receipts deleted after the checkpoint anchored them',
  expected: { outcome: 'sequence below checkpoint anchor detected' },
  async run() {
    const { w, cp, receipts } = await prepare();
    const truncated = receipts.slice(0, -1);
    const anchored = verifyAuditAgainstCheckpoint({
      streamId: STREAM,
      receipts: truncated,
      checkpoint: cp,
      checkpointVerified: await verifyCheckpointSignature({ checkpoint: cp, didResolver: w.gatewayDeps.didResolver }),
    });
    return {
      outcome: !anchored.valid ? `truncation detected (checkpoint at ${cp.payload.sequence}, chain ends at ${truncated.length})` : 'UNDETECTED',
      reasonCodes: anchored.valid ? [] : anchored.reasonCodes,
      invariants: { anchoredValid: anchored.valid },
    };
  },
};

export const AUDIT_009: AttackScenario = {
  id: 'AUDIT-009',
  category: 'AUDIT',
  kind: 'ATTACK',
  title: 'Forged checkpoint signed by the wrong key',
  expected: { outcome: 'signer verification fails' },
  async run() {
    const { w, cp } = await prepare();
    // An attacker checkpoints the SAME chain with their OWN key.
    const { AuditCheckpointService } = await import('@agent-trust/audit');
    const evilService = new AuditCheckpointService(w.evilSigner);
    const forgedCp = await evilService.issue({
      checkpointId: 'ckpt_evil',
      streamId: STREAM,
      receipts: await w.auditLog.readStream(STREAM),
      issuedAt: '2026-09-15T12:00:00Z',
    });
    const verified = await verifyCheckpointSignature({
      checkpoint: forgedCp,
      didResolver: w.gatewayDeps.didResolver,
      opts: { expectedSignerDid: 'did:web:trust.example.com:audit', now: NOW },
    });
    void cp;
    return {
      outcome: !verified.valid ? 'checkpoint signer not the trusted anchor — rejected' : 'UNDETECTED',
      reasonCodes: verified.valid ? [] : verified.reasonCodes,
      invariants: { checkpointValid: verified.valid },
    };
  },
};

export const AUDIT_SCENARIOS = [AUDIT_001, AUDIT_002, AUDIT_003, AUDIT_004, AUDIT_005, AUDIT_006, AUDIT_007, AUDIT_008, AUDIT_009];
