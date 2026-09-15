import { replayKey } from './key.js';
import type { ReplayClaim, ReplayClaimResult, ReplayStore } from './types.js';

/**
 * Deterministic in-memory CLAIM-ONCE store (Step 7B).
 *
 * Atomicity: the check-and-set runs synchronously inside one call with no
 * await between read and write, so within a single JS event-loop tick no
 * interleaving is possible — Promise.all of N concurrent claims yields
 * exactly one success (proven by test). The interface maps 1:1 onto
 * Redis SET NX for the distributed case.
 *
 * Expired entries are purged opportunistically; an expired claim's jti may
 * be reused only after its security validity window is over — that is
 * safe because the proof itself is temporally dead by then (the PoP
 * verifier rejects proofs whose window has closed).
 */
export class InMemoryReplayStore implements ReplayStore {
  readonly #entries = new Map<string, number>();
  readonly #clock: () => number;
  readonly #maxEntries: number;

  constructor(opts: { clock?: () => number; maxEntries?: number } = {}) {
    this.#clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
    this.#maxEntries = opts.maxEntries ?? 100_000;
  }

  get size(): number {
    return this.#entries.size;
  }

  async claim(claim: ReplayClaim): Promise<ReplayClaimResult> {
    const now = this.#clock();
    const key = replayKey(claim.namespace, claim.jti);
    const expiresAt = this.#entries.get(key);
    if (expiresAt !== undefined) {
      if (expiresAt > now) {
        return { claimed: false, reason: 'already_claimed' };
      }
      this.#entries.delete(key); // expired: safe to reclaim
    }
    this.#entries.set(key, claim.expiresAt);
    if (this.#entries.size > this.#maxEntries) {
      this.#purgeExpired(now);
    }
    return { claimed: true };
  }

  #purgeExpired(now: number): void {
    for (const [key, expiresAt] of this.#entries) {
      if (expiresAt <= now) this.#entries.delete(key);
      if (this.#entries.size <= this.#maxEntries) break;
    }
  }
}
