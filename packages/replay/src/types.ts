/**
 * Replay-protection domain types (Step 7, ADR-0003).
 *
 * The store answers exactly one question atomically: has THIS authorization
 * been claimed before, in THIS namespace? It never does get-then-set.
 */

/** Unix seconds — project-wide time convention. */
export interface ReplayClaim {
  /** Canonical namespace (audience + key binding), hashed into the key. */
  namespace: string;
  /** Validated unique-per-request token from the proof. */
  jti: string;
  /** Claim retention deadline: after this the entry may be evicted. */
  expiresAt: number;
}

export type ReplayClaimResult =
  | { claimed: true }
  | { claimed: false; reason: 'already_claimed' };

/**
 * CLAIM-ONCE semantics. Implementations must be atomic under concurrency:
 * for a given (namespace, jti), at most ONE claim succeeds. Infrastructure
 * failures are thrown as ReplayStoreUnavailableError — the orchestration
 * layer decides fail-closed behavior (P0: always deny writes).
 */
export interface ReplayStore {
  claim(claim: ReplayClaim): Promise<ReplayClaimResult>;
}

/** Thrown when the backing store cannot complete the atomic claim. */
export class ReplayStoreUnavailableError extends Error {
  override readonly cause?: unknown;
  constructor(cause?: unknown) {
    super('replay store unavailable');
    this.name = 'ReplayStoreUnavailableError';
    this.cause = cause;
  }
}
