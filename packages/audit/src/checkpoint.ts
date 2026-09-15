import { canonicalJson } from '@agent-trust/crypto';
import type { PublicJwk, Signer } from '@agent-trust/crypto';
import { parseDidUrl } from '@agent-trust/did';
import {
  SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD,
  type Validator,
  createValidator,
} from '@agent-trust/schemas';
import {
  decodeJwsPayload,
  parseCompactJws,
  signCompactJws,
  verifyCompactJwsSignature,
} from '@agent-trust/vc';
import type { DidResolver } from '@agent-trust/did';

import { chainHeadHash } from './verify-chain.js';
import type {
  ActionReceipt,
  AuditCheckpointPayload,
  CheckpointVerification,
  SignedAuditCheckpoint,
} from './types.js';

/**
 * Checkpoint service (Steps 9I/9J): signs a stream head through the
 * EXISTING Signer + compact-JWS stack — no second signature system, and
 * no audit code ever touches private key material.
 */
export class AuditCheckpointService {
  readonly #signer: Signer;

  constructor(signer: Signer) {
    this.#signer = signer;
  }

  async issue(input: {
    checkpointId: string;
    streamId: string;
    receipts: readonly ActionReceipt[];
    issuedAt: string;
  }): Promise<SignedAuditCheckpoint> {
    const head = input.receipts.length === 0 ? null : input.receipts[input.receipts.length - 1];
    const payload: AuditCheckpointPayload = {
      checkpointId: input.checkpointId,
      streamId: input.streamId,
      sequence: head?.body.sequence ?? 0,
      headHash: chainHeadHash(input.receipts),
      issuedAt: input.issuedAt,
      algorithm: 'sha256',
      chainFormat: 'agent-trust/action-receipt/v1',
    };
    const jws = await signCompactJws(this.#signer, payload as unknown as Record<string, unknown>);
    return {
      payload,
      signerDid: parseDidUrl(await this.#signer.keyId()).did,
      kid: await this.#signer.keyId(),
      jws,
    };
  }
}

export interface CheckpointVerifyOptions {
  /**
   * The exact signer DID the checkpoint must come from. Omitting it makes
   * any resolvable signer acceptable — production callers should pin it.
   */
  expectedSignerDid?: string;
  /** Frozen clock (unix seconds) — determinism for tests. */
  now?: number;
}

/**
 * Independent checkpoint verification (Step 9K). Validates the JWS
 * structure, resolves the signer's key via the DidResolver (kid
 * ownership), verifies the signature over the received bytes, checks the
 * payload schema, signer trust binding, and stream binding. Comparing the
 * headHash against a RECEIPT CHAIN is verifyAuditAgainstCheckpoint below.
 */
export async function verifyCheckpointSignature(input: {
  checkpoint: SignedAuditCheckpoint;
  didResolver: DidResolver;
  validator?: Validator;
  opts?: CheckpointVerifyOptions;
}): Promise<CheckpointVerification> {
  const validator = input.validator ?? createValidator();
  const { checkpoint, didResolver } = input;

  if (!validator.validate(SCHEMA_ID_AUDIT_CHECKPOINT_PAYLOAD, checkpoint.payload).valid) {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'], detail: 'payload schema invalid' };
  }
  if (
    input.opts?.expectedSignerDid !== undefined &&
    checkpoint.signerDid !== input.opts.expectedSignerDid
  ) {
    return { valid: false, reasonCodes: ['AUDIT_SIGNER_UNTRUSTED'], detail: 'unexpected signer DID' };
  }

  let parsed;
  try {
    parsed = parseCompactJws(checkpoint.jws);
  } catch {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'], detail: 'malformed JWS' };
  }
  const kid = parsed.protectedHeader.kid;
  if (typeof kid !== 'string' || kid !== checkpoint.kid) {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'], detail: 'kid mismatch' };
  }
  if (parseDidUrl(kid).did !== checkpoint.signerDid) {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'], detail: 'kid does not belong to the signer' };
  }

  const resolution = await didResolver.resolve(checkpoint.signerDid);
  const method = resolution.didDocument?.verificationMethod?.find((m) => m.id === kid);
  if (!method?.publicKeyJwk) {
    return { valid: false, reasonCodes: ['AUDIT_SIGNER_UNTRUSTED'], detail: 'signer key not resolvable' };
  }
  if (!verifyCompactJwsSignature(parsed, method.publicKeyJwk as PublicJwk)) {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'], detail: 'signature invalid' };
  }

  // The signed payload must match what the checkpoint claims (a tampered
  // payload field with a copied signature cannot survive this).
  let signedPayload: Record<string, unknown>;
  try {
    signedPayload = decodeJwsPayload(parsed);
  } catch {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'], detail: 'payload decode failed' };
  }
  if (canonicalJson(signedPayload) !== canonicalJson(checkpoint.payload)) {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_INVALID'], detail: 'payload does not match the signed JWS' };
  }

  return {
    valid: true,
    streamId: checkpoint.payload.streamId,
    sequence: checkpoint.payload.sequence,
    headHash: checkpoint.payload.headHash,
  };
}

export type ChainVsCheckpointVerification =
  | { valid: true; streamId: string; sequence: number; headHash: string }
  | { valid: false; reasonCodes: import('@agent-trust/schemas').ReasonCode[]; detail?: string };

/**
 * The Step 9N/9P guarantee: an internally coherent REWRITTEN chain fails
 * against a trusted checkpoint — CHECKPOINT_HEAD_MISMATCH — and a
 * TRUNCATED chain fails on sequence. A bare hash chain alone cannot
 * provide this; the checkpoint signing key is the trust root.
 */
export function verifyAuditAgainstCheckpoint(input: {
  streamId: string;
  receipts: readonly ActionReceipt[];
  checkpoint: SignedAuditCheckpoint;
  checkpointVerified: CheckpointVerification;
}): ChainVsCheckpointVerification {
  if (!input.checkpointVerified.valid) {
    return { valid: false, reasonCodes: input.checkpointVerified.reasonCodes, detail: input.checkpointVerified.detail };
  }
  if (input.checkpointVerified.streamId !== input.streamId) {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_MISMATCH'], detail: 'checkpoint is for a different stream' };
  }
  const last = input.receipts[input.receipts.length - 1];
  const actualSequence = last?.body.sequence ?? 0;
  if (actualSequence < input.checkpointVerified.sequence) {
    return {
      valid: false,
      reasonCodes: ['AUDIT_SEQUENCE_INVALID'],
      detail: `truncation: checkpoint anchors sequence ${input.checkpointVerified.sequence} but chain ends at ${actualSequence}`,
    };
  }
  if (actualSequence > input.checkpointVerified.sequence) {
    return {
      valid: false,
      reasonCodes: ['AUDIT_CHECKPOINT_MISMATCH'],
      detail: `chain is longer than the checkpoint (ends at ${actualSequence}, checkpoint at ${input.checkpointVerified.sequence}) — events after the checkpoint are unanchored`,
    };
  }
  const actualHead = chainHeadHash(input.receipts);
  if (actualHead !== input.checkpointVerified.headHash) {
    return { valid: false, reasonCodes: ['AUDIT_CHECKPOINT_MISMATCH'], detail: 'recomputed head does not match the checkpoint' };
  }
  return {
    valid: true,
    streamId: input.streamId,
    sequence: input.checkpointVerified.sequence,
    headHash: input.checkpointVerified.headHash,
  };
}
