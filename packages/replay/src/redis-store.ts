import { replayKey } from './key.js';
import { ReplayStoreUnavailableError } from './types.js';
import type { ReplayClaim, ReplayClaimResult, ReplayStore } from './types.js';

/**
 * Minimal structural view of a Redis client — the adapter needs exactly
 * one command shape (SET key value NX PX <ms>). Keeping the type
 * structural isolates `redis` to this file and avoids coupling the
 * package to a specific client major version.
 */
export interface RedisSetNxClient {
  set(
    key: string,
    value: string,
    options: { NX: true; PX: number },
  ): Promise<'OK' | null | unknown>;
}

/**
 * Production/live-demo adapter (Step 7C). Redis is the concurrency
 * authority: the claim is ONE atomic command —
 *
 *     SET replay:v1:<sha256(ns)>:<jti> 1 NX PX <ttlMs>
 *
 *   OK   → first claim → ACCEPT
 *   null → already exists → REPLAY_DETECTED (by the caller)
 *
 * Never EXISTS-then-SET, never application-side locks.
 */
export class RedisReplayStore implements ReplayStore {
  readonly #client: RedisSetNxClient;
  readonly #clock: () => number;

  constructor(client: RedisSetNxClient, opts: { clock?: () => number } = {}) {
    this.#client = client;
    this.#clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  async claim(claim: ReplayClaim): Promise<ReplayClaimResult> {
    const key = replayKey(claim.namespace, claim.jti);
    const ttlMs = Math.max(1, Math.round((claim.expiresAt - this.#clock()) * 1000));
    let result: unknown;
    try {
      result = await this.#client.set(key, '1', { NX: true, PX: ttlMs });
    } catch (cause) {
      // Infrastructure failure is REPORTED, never silently tolerated —
      // the orchestration layer maps it to REPLAY_PROTECTION_UNAVAILABLE.
      throw new ReplayStoreUnavailableError(cause);
    }
    return result === 'OK'
      ? { claimed: true }
      : { claimed: false, reason: 'already_claimed' };
  }
}
