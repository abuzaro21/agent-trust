import type { CredentialStatusEntry } from '@agent-trust/vc';

export type StatusPurpose = 'revocation' | 'suspension';

/**
 * One status list. `controllerDid` binds the list to its owner — the
 * checker refuses lists whose controller is not the credential's issuer
 * (or an explicitly trusted status authority, once such a registry exists).
 */
export interface StatusList {
  id: string;
  purpose: StatusPurpose;
  controllerDid: string;
  sizeBits: number;
  /** Canonical base64url of the W3C-ordered bitstring. */
  encodedList: string;
  /** Bumped on every mutation so stale snapshots are detectable later. */
  version: number;
  /** Unix seconds, from the injected clock. */
  updatedAt: number;
}

/** Semantic mutation errors — callers never read-modify-write bitstrings. */
export type StatusListErrorCode =
  | 'LIST_NOT_FOUND'
  | 'PURPOSE_MISMATCH'
  | 'INDEX_OUT_OF_RANGE'
  | 'SIZE_INVALID'
  | 'MALFORMED_ENCODING';

export class StatusListError extends Error {
  readonly code: StatusListErrorCode;
  constructor(code: StatusListErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

export interface StatusListStore {
  get(listId: string): Promise<StatusList | null>;
  put(list: StatusList): Promise<void>;
}

/**
 * Store of SIGNED status-list credentials (compact JWS produced via the
 * existing VC primitives). The checker verifies these instead of trusting
 * raw stored lists — unsigned attacker-controlled data can never flip a
 * credential back to active.
 */
export interface SignedStatusListStore {
  /** The compact JWS of the status-list credential for this reference. */
  get(statusListCredential: string): Promise<string | null>;
}

export type { CredentialStatusEntry };
