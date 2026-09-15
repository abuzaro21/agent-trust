import {
  SCHEMA_ID_ACTION_RECEIPT_ENVELOPE,
  type ReasonCode,
  type Validator,
  createValidator,
} from '@agent-trust/schemas';

import { computeEventHash, GENESIS_PREVIOUS_HASH } from './hash.js';
import type { ActionReceipt, ChainVerification } from './types.js';

/**
 * Independent chain verifier (Step 9K/X). Checks, in order, per receipt:
 * schema → stream/sequence continuity → previousHash linkage → recomputed
 * eventHash. Returns the FIRST broken sequence so a denial is actionable.
 * A chain that is internally coherent still proves nothing against a
 * full-database attacker — that is what signed checkpoints add
 * (verifyAuditAgainstCheckpoint).
 */
export function verifyAuditChain(
  streamId: string,
  receipts: readonly ActionReceipt[],
  validator: Validator = createValidator(),
): ChainVerification {
  if (receipts.length === 0) {
    return { valid: true, receipts: 0, headHash: GENESIS_PREVIOUS_HASH };
  }

  let expectedPrevious = GENESIS_PREVIOUS_HASH;
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i]!;
    const sequence = i + 1;

    if (!validator.validate(SCHEMA_ID_ACTION_RECEIPT_ENVELOPE, receipt).valid) {
      return {
        valid: false,
        reasonCodes: ['AUDIT_CHAIN_INVALID'],
        firstBrokenSequence: sequence,
        detail: 'receipt fails the envelope schema',
      };
    }
    if (receipt.body.streamId !== streamId) {
      return {
        valid: false,
        reasonCodes: ['AUDIT_CHAIN_INVALID'],
        firstBrokenSequence: sequence,
        detail: `foreign stream: expected ${streamId}, got ${receipt.body.streamId}`,
      };
    }
    if (receipt.body.sequence !== sequence) {
      return {
        valid: false,
        reasonCodes: ['AUDIT_SEQUENCE_INVALID'],
        firstBrokenSequence: sequence,
        detail: `expected sequence ${sequence}, got ${receipt.body.sequence}`,
      };
    }
    if (receipt.previousHash !== expectedPrevious) {
      return {
        valid: false,
        reasonCodes: ['AUDIT_CHAIN_INVALID'],
        firstBrokenSequence: sequence,
        detail: `previousHash linkage broken at sequence ${sequence}`,
      };
    }
    const recomputed = computeEventHash(receipt.previousHash, receipt.body);
    if (recomputed !== receipt.eventHash) {
      return {
        valid: false,
        reasonCodes: ['AUDIT_CHAIN_INVALID'],
        firstBrokenSequence: sequence,
        detail: `eventHash mismatch at sequence ${sequence}`,
      };
    }
    expectedPrevious = receipt.eventHash;
  }

  return {
    valid: true,
    receipts: receipts.length,
    headHash: receipts[receipts.length - 1]!.eventHash,
  };
}

/** Compute the chain head hash WITHOUT verifying (checkpoint comparison). */
export function chainHeadHash(receipts: readonly ActionReceipt[]): string {
  return receipts.length === 0 ? GENESIS_PREVIOUS_HASH : receipts[receipts.length - 1]!.eventHash;
}

export type { ReasonCode };
