import type { ReasonCode } from '@agent-trust/schemas';

/**
 * Audit domain types (Step 9). The receipt body is the canonical HASHED
 * payload; hash fields live outside it in the envelope. See
 * schemas/action-receipt.schema.ts for the wire contract.
 */

export type PolicyEffect = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

export type ExecutionState = 'NOT_EXECUTED' | 'SUCCEEDED' | 'FAILED';

export interface ActionReceiptBody {
  receiptId: string;
  /** Events in stream A never affect stream B (Step 9E). */
  streamId: string;
  sequence: number;
  /** Canonical UTC seconds — lexicographic-time safe. */
  recordedAt: string;
  actor: { did: string; controller?: string };
  request: {
    action: string;
    resource: string;
    audience: string;
    parameters?: { amount?: number; currency?: string };
  };
  /** Evidence as identifiers/digests — never raw credentials or tokens. */
  authority?: {
    credentialId?: string;
    issuer?: string;
    /** sha256 hex of the canonical authority object. */
    authorityDigest?: string;
  };
  security: {
    proofVerified: true;
    credentialVerified: true;
    issuerTrusted: true;
    credentialActive: true;
    quarantined: false;
    replayChecked: true;
  };
  decision: {
    effect: PolicyEffect;
    reasonCodes: ReasonCode[];
    policy: { id: string; version: string; hash: string };
  };
  /** Decision ≠ execution (Step 9U): ALLOW does not imply success. */
  execution?: {
    state: ExecutionState;
    resultDigest?: string;
  };
}

export interface ActionReceipt {
  body: ActionReceiptBody;
  /** Fixed-size 64-char lowercase hex; all-zeros for the stream's first event. */
  previousHash: string;
  eventHash: string;
}

export interface AuditHead {
  streamId: string;
  sequence: number;
  headHash: string;
}

export interface AuditCheckpointPayload {
  checkpointId: string;
  streamId: string;
  sequence: number;
  headHash: string;
  issuedAt: string;
  algorithm: 'sha256';
  chainFormat: 'agent-trust/action-receipt/v1';
}

/** Compact JWS over the canonical checkpoint payload (existing JWS stack). */
export interface SignedAuditCheckpoint {
  payload: AuditCheckpointPayload;
  signerDid: string;
  kid: string;
  jws: string;
}

/**
 * CLAIM-ONCE append: the log OWNS chain advancement (Step 9F) — callers
 * never compute sequence/previousHash themselves. Implementations must
 * make read-head → assign-sequence → hash → persist → advance-head atomic
 * from the caller's perspective. Failure to persist a required receipt is
 * AUDIT_LOG_UNAVAILABLE and future orchestration treats it as fail-closed
 * for state-changing actions (Step 9Z).
 */
export interface AuditLog {
  append(streamId: string, body: Omit<ActionReceiptBody, 'streamId' | 'sequence'>): Promise<ActionReceipt>;
  readStream(streamId: string): Promise<ActionReceipt[]>;
  getHead(streamId: string): Promise<AuditHead | null>;
}

export type ChainVerification =
  | { valid: true; receipts: number; headHash: string }
  | {
      valid: false;
      reasonCodes: ReasonCode[];
      /** Sequence of the first receipt that failed verification, when known. */
      firstBrokenSequence?: number;
      detail?: string;
    };

export type CheckpointVerification =
  | { valid: true; streamId: string; sequence: number; headHash: string }
  | { valid: false; reasonCodes: ReasonCode[]; detail?: string };
