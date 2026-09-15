import { isValidJti, canonicalReplayNamespace, replayKey } from './key.js';
import { ReplayStoreUnavailableError } from './types.js';
import type { ReplayStore } from './types.js';

/**
 * Replay protector (Step 7F). SECURITY-CRITICAL ORDERING: this service
 * consumes a proof that has ALREADY passed cryptographic + temporal
 * verification. An invalid signature must never be able to claim
 * (poison) a legitimate jti — crypto first, claim second, always.
 */
export interface VerifiedProofContext {
  /** The exact htu the proof was verified against (namespace binding). */
  audience: string;
  /** Verification-method id from the verified proof header. */
  kid: string;
  /** Unique-per-request token from the verified proof. */
  jti: string;
  /** Verified proof window (unix seconds). */
  iat: number;
  exp: number;
  /** Verification clock (unix seconds) — injected for determinism. */
  now: number;
}

export type ReplayDecision =
  | {
      outcome: 'claimed';
      key: string;
      /** Seconds the claim is retained past the verification clock. */
      retentionSeconds: number;
      replayChecked: true;
      replayClaimed: true;
    }
  | {
      outcome: 'denied';
      reasonCode:
        | 'REPLAY_DETECTED'
        | 'REPLAY_PROTECTION_UNAVAILABLE'
        | 'REQUEST_MALFORMED'
        | 'VC_EXPIRED';
      replayChecked: boolean;
      replayClaimed: false;
    };

export interface ReplayProtectorOptions {
  /**
   * Clock skew (seconds) tolerated in TTL derivation — mirrors ADR-0003:
   * ttl = proof.exp − now + allowedClockSkew. Default 0 (the PoP verifier
   * itself applies no skew).
   */
  clockSkew?: number;
  /** Upper bound on retention; anything larger is rejected. Default 1h. */
  maxRetentionSeconds?: number;
}

export class ReplayProtector {
  readonly #store: ReplayStore;
  readonly #clockSkew: number;
  readonly #maxRetentionSeconds: number;

  constructor(store: ReplayStore, opts: ReplayProtectorOptions = {}) {
    this.#store = store;
    this.#clockSkew = opts.clockSkew ?? 0;
    this.#maxRetentionSeconds = opts.maxRetentionSeconds ?? 3_600;
  }

  async verifyAndClaim(ctx: VerifiedProofContext): Promise<ReplayDecision> {
    // jti validation happens BEFORE the store is touched (Step 7N).
    if (!isValidJti(ctx.jti)) {
      return { outcome: 'denied', reasonCode: 'REQUEST_MALFORMED', replayChecked: false, replayClaimed: false };
    }

    // TTL from the proof's own lifetime (Step 7E) — never a hardcoded
    // constant. The PoP verifier has already rejected expired proofs;
    // ttl <= 0 here is defense-in-depth, not the primary temporal gate.
    const ttl = ctx.exp - ctx.now + this.#clockSkew;
    if (ttl <= 0) {
      return { outcome: 'denied', reasonCode: 'VC_EXPIRED', replayChecked: false, replayClaimed: false };
    }
    if (ttl > this.#maxRetentionSeconds) {
      return { outcome: 'denied', reasonCode: 'REQUEST_MALFORMED', replayChecked: false, replayClaimed: false };
    }

    const namespace = canonicalReplayNamespace({ audience: ctx.audience, kid: ctx.kid });
    let claimResult;
    try {
      claimResult = await this.#store.claim({
        namespace,
        jti: ctx.jti,
        expiresAt: ctx.now + ttl,
      });
    } catch (e) {
      if (e instanceof ReplayStoreUnavailableError) {
        return {
          outcome: 'denied',
          reasonCode: 'REPLAY_PROTECTION_UNAVAILABLE',
          replayChecked: true,
          replayClaimed: false,
        };
      }
      throw e;
    }
    if (!claimResult.claimed) {
      return { outcome: 'denied', reasonCode: 'REPLAY_DETECTED', replayChecked: true, replayClaimed: false };
    }
    return {
      outcome: 'claimed',
      key: replayKey(namespace, ctx.jti),
      retentionSeconds: ttl,
      replayChecked: true,
      replayClaimed: true,
    };
  }
}
