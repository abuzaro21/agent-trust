/**
 * Deterministic reason codes emitted by the verification plane and the
 * policy engine. These are the machine-readable source of truth for every
 * decision — no LLM ever generates a security rationale (docs/trust-model.md).
 *
 * Codes are split into EVIDENCE_* (facts that justify an ALLOW),
 * DENIAL_* (verification-plane rejections), and POLICY_* (policy-plane
 * judgments). Grouping is documentation only — codes are used uniformly.
 */
export const REASON_CODES = [
  // --- evidence (verification plane, positive) ---
  'IDENTITY_VERIFIED',
  'TRUSTED_ISSUER',
  'DELEGATION_VALID',
  'ATTENUATION_VERIFIED',
  'WITHIN_AMOUNT_LIMIT',
  'WITHIN_RATE_LIMIT',
  'WITHIN_SCOPE',
  'NO_ACTIVE_REVOCATION',
  'REVOCATION_CHECKED',
  'VC_VALID',
  'REPLAY_SAFE',
  'APPROVAL_VALID',

  // --- denial (verification plane, negative) ---
  'IDENTITY_PROOF_INVALID',
  'DID_RESOLUTION_FAILED',
  'DID_METHOD_UNSUPPORTED',
  'VC_SIGNATURE_INVALID',
  'VC_SCHEMA_INVALID',
  'UNTRUSTED_ISSUER',
  'VC_EXPIRED',
  'VC_NOT_YET_VALID',
  'CREDENTIAL_REVOKED',
  'CREDENTIAL_SUSPENDED',
  'WRONG_SUBJECT',
  'AUDIENCE_MISMATCH',
  'NON_ATTENUATED_DELEGATION',
  'DELEGATION_CYCLE',
  'DELEGATION_DEPTH_EXCEEDED',
  'PARENT_DELEGATION_REVOKED',
  'AUTHORITY_LIMIT_EXCEEDED',
  'ACTION_NOT_IN_SCOPE',
  'RESOURCE_NOT_IN_SCOPE',
  'RATE_LIMIT_EXCEEDED',
  'REPLAY_DETECTED',
  'REPLAY_PROTECTION_UNAVAILABLE',
  'AGENT_QUARANTINED',
  'APPROVAL_INVALID',
  'REQUEST_MALFORMED',

  // --- denial / escalation (policy plane or dependency failures) ---
  'POLICY_ENGINE_UNAVAILABLE',
  'POLICY_BUNDLE_INVALID',
  'POLICY_EVALUATION_ERROR',
  'AUDIT_LOG_UNAVAILABLE',
  'REPUTATION_INSUFFICIENT',
  'APPROVAL_REQUIRED',
] as const;

export type ReasonCode = (typeof REASON_CODES)[number];

/** Narrow an arbitrary string to a ReasonCode; returns undefined if unknown. */
export function asReasonCode(value: string): ReasonCode | undefined {
  return (REASON_CODES as readonly string[]).includes(value)
    ? (value as ReasonCode)
    : undefined;
}
