import type { ReasonCode } from '@agent-trust/schemas';

/**
 * Status / quarantine seams. The VC verifier depends ONLY on these
 * interfaces — never on a concrete status store, bitstring encoding, or
 * quarantine implementation (those live in packages/status, which depends
 * on vc; this direction is what keeps the dependency graph acyclic).
 */

export type CredentialStatusState = 'ACTIVE' | 'REVOKED' | 'SUSPENDED' | 'UNKNOWN';

/**
 * The `credentialStatus` entry a credential may carry (W3C Bitstring
 * Status List profile). Parsed from verified claims, so its shape is
 * attacker-controlled content — the checker must validate it before use.
 */
export interface CredentialStatusEntry {
  id: string;
  type: string;
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
}

export interface CredentialStatusCheckInput {
  credentialId: string;
  issuerDid: string;
  /** The raw credentialStatus object from verified claims. */
  status: Record<string, unknown>;
  /** Frozen verification clock (unix seconds) — callers inject for determinism. */
  now: number;
}

export interface CredentialStatusResult {
  state: CredentialStatusState;
  /** ISO-8601, derived from the injected verification clock. */
  checkedAt: string;
  source?: string;
  /** Diagnostic detail for logs — never a substitute for reason codes. */
  detail?: string;
}

/**
 * Status is an independent security gate: cryptographic validity never
 * implies current authorization validity. UNKNOWN means the checker could
 * not PROVE the credential is active — the verifier fails closed on it.
 */
export interface CredentialStatusChecker {
  check(input: CredentialStatusCheckInput): Promise<CredentialStatusResult>;
}

/**
 * Emergency kill switch for an AGENT IDENTITY — distinct from credential
 * status: quarantine blocks the agent regardless of any credential state,
 * and is reversible by the operator (release).
 */
export interface AgentQuarantineStore {
  isQuarantined(agentDid: string): Promise<boolean>;
}

/** Verifier's status-gate outcomes, kept next to the seam for cohesion. */
export type StatusGateDenial = Extract<
  ReasonCode,
  'CREDENTIAL_REVOKED' | 'CREDENTIAL_SUSPENDED' | 'CREDENTIAL_STATUS_UNAVAILABLE' | 'AGENT_QUARANTINED'
>;
