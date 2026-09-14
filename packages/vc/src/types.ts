import type { Authority, ReasonCode } from '@agent-trust/schemas';

/**
 * Credential types this fabric can issue and verify. Anything else is
 * VC_TYPE_UNSUPPORTED — a closed set, by design.
 */
export const SUPPORTED_CREDENTIAL_TYPES = [
  'AgentMembershipCredential',
  'AgentDelegationCredential',
] as const;

export type CredentialType = (typeof SUPPORTED_CREDENTIAL_TYPES)[number];

/**
 * W3C VC 2.0 claims in the JOSE (JWT) profile: issuer=iss, subject=sub,
 * credential id=jti, validFrom=nbf, validUntil=exp, and the `vc` object
 * carrying type + credentialSubject.
 */
export interface CredentialClaims {
  iss: string;
  sub: string;
  jti: string;
  nbf: number;
  exp?: number;
  vc: {
    type: string[];
    credentialSubject: { id: string } & Record<string, unknown>;
    credentialStatus?: Record<string, unknown>;
  };
}

/**
 * The credential in W3C document form (for display/API responses).
 * Derived deterministically from verified claims — never parsed from
 * untrusted input directly.
 */
export interface CredentialDocument {
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown> & { id: string };
}

/** Verified facts for downstream consumers (the future policy layer). */
export interface VerifiedFacts {
  credentialValid: true;
  issuerTrusted: true;
  credentialId: string;
  credentialType: CredentialType;
  issuerDid: string;
  subjectDid: string;
  /** Unix seconds. */
  validFrom: number;
  /** Unix seconds, when the credential carries an expiry. */
  validUntil?: number;
  /** Present only for AgentDelegationCredential. */
  authority?: Authority;
  /** Present only for AgentMembershipCredential. */
  membership?: {
    controller?: string;
    organization?: string;
    runtimeBinding?: string;
  };
}

/**
 * Deterministic verification outcome. Exactly one reason code per failure —
 * the first failing stage of the pipeline — so results are reproducible.
 */
export type VcVerification =
  | { valid: true; facts: VerifiedFacts; claims: CredentialClaims }
  | { valid: false; reasonCodes: [ReasonCode] };

/** Unix seconds or a Date — issuance input convenience. */
export type TimeInput = number | Date;

export function toUnixSeconds(value: TimeInput): number {
  return typeof value === 'number' ? Math.floor(value) : Math.floor(value.getTime() / 1000);
}

export function toIso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}
