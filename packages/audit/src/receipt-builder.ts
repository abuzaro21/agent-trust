import { canonicalJson, sha256Hex } from '@agent-trust/crypto';
import type { ReasonCode } from '@agent-trust/schemas';

import type { ActionReceiptBody, ExecutionState, PolicyEffect } from './types.js';

/**
 * Receipt builder (Step 9C) — a strict FIELD ALLOWLIST. Even if the caller
 * passes richer objects (full VCs, tokens, conversations), only the
 * contracted evidence identifiers/digests below can enter a receipt body.
 * The builder never receives private key material by construction (it
 * takes a PolicyDecision, which carries hashes, not secrets).
 */
export interface ReceiptDecisionInput {
  effect: PolicyEffect;
  reasonCodes: ReasonCode[];
  policy: { id: string; version: string; hash: string };
}

export interface ReceiptSecurityInput {
  proofVerified: true;
  credentialVerified: true;
  issuerTrusted: true;
  credentialActive: true;
  quarantined: false;
  replayChecked: true;
}

export interface BuildReceiptBodyInput {
  receiptId: string;
  recordedAt: string;
  actor: { did: string; controller?: string };
  request: {
    action: string;
    resource: string;
    audience: string;
    parameters?: { amount?: number; currency?: string };
  };
  authority?: {
    credentialId?: string;
    issuer?: string;
    /** Canonical authority object — stored only as its sha256 digest. */
    authority?: unknown;
  };
  security: ReceiptSecurityInput;
  decision: ReceiptDecisionInput;
  execution?: { state: ExecutionState; result?: unknown };
}

/** sha256 hex of the canonical authority object (evidence digest). */
export function authorityDigestOf(authority: unknown): string {
  return sha256Hex(canonicalJson(authority));
}

/** sha256 hex of the canonical execution result (never the raw result). */
export function resultDigestOf(result: unknown): string {
  return sha256Hex(canonicalJson(result));
}

export function buildReceiptBody(input: BuildReceiptBodyInput): Omit<ActionReceiptBody, 'streamId' | 'sequence'> {
  return {
    receiptId: input.receiptId,
    recordedAt: input.recordedAt,
    actor: {
      did: input.actor.did,
      ...(input.actor.controller !== undefined ? { controller: input.actor.controller } : {}),
    },
    request: {
      action: input.request.action,
      resource: input.request.resource,
      audience: input.request.audience,
      ...(input.request.parameters !== undefined ? { parameters: input.request.parameters } : {}),
    },
    ...(input.authority !== undefined
      ? {
          authority: {
            ...(input.authority.credentialId !== undefined ? { credentialId: input.authority.credentialId } : {}),
            ...(input.authority.issuer !== undefined ? { issuer: input.authority.issuer } : {}),
            ...(input.authority.authority !== undefined
              ? { authorityDigest: authorityDigestOf(input.authority.authority) }
              : {}),
          },
        }
      : {}),
    security: { ...input.security },
    decision: {
      effect: input.decision.effect,
      reasonCodes: [...input.decision.reasonCodes],
      policy: { ...input.decision.policy },
    },
    ...(input.execution !== undefined
      ? {
          execution: {
            state: input.execution.state,
            ...(input.execution.result !== undefined
              ? { resultDigest: resultDigestOf(input.execution.result) }
              : {}),
          },
        }
      : {}),
  };
}
