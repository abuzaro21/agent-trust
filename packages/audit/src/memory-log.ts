import { randomUUID } from 'node:crypto';

import { computeEventHash, GENESIS_PREVIOUS_HASH } from './hash.js';
import type {
  ActionReceipt,
  ActionReceiptBody,
  AuditHead,
  AuditLog,
} from './types.js';

interface StreamState {
  readonly receipts: ActionReceipt[];
  sequence: number;
  headHash: string;
}

/**
 * Deterministic in-memory AuditLog (Step 9G).
 *
 * Atomicity (Step 9F): append() performs read-head → assign-sequence →
 * previousHash → eventHash → persist → advance-head SYNCHRONOUSLY within
 * one event-loop turn — no await separates the head read from the head
 * write, so concurrent append() calls (Promise.all of 100+) serialize into
 * one linear chain: unique contiguous sequences, zero forks (proven by
 * test). This mirrors the future Postgres adapter, where the same five
 * steps become one transaction with row-level locking on the head.
 *
 * The streamId is stamped into the body here (callers cannot forget it),
 * and callers NEVER compute sequence/previousHash themselves.
 */
export class InMemoryAuditLog implements AuditLog {
  readonly #streams = new Map<string, StreamState>();
  readonly #idFactory: () => string;

  constructor(opts: { idFactory?: () => string } = {}) {
    this.#idFactory = opts.idFactory ?? (() => `rcpt_${randomUUID()}`);
  }

  async append(
    streamId: string,
    body: Omit<ActionReceiptBody, 'streamId' | 'sequence'>,
  ): Promise<ActionReceipt> {
    let state = this.#streams.get(streamId);
    if (state === undefined) {
      state = { receipts: [], sequence: 0, headHash: GENESIS_PREVIOUS_HASH };
      this.#streams.set(streamId, state);
    }
    const fullBody: ActionReceiptBody = {
      ...body,
      streamId,
      sequence: state.sequence + 1,
    };
    const previousHash = state.headHash;
    const eventHash = computeEventHash(previousHash, fullBody);
    const receipt: ActionReceipt = { body: fullBody, previousHash, eventHash };
    state.receipts.push(receipt);
    state.sequence = fullBody.sequence;
    state.headHash = eventHash;
    return receipt;
  }

  async readStream(streamId: string): Promise<ActionReceipt[]> {
    return this.#streams.get(streamId)?.receipts.map((r) => structuredClone(r)) ?? [];
  }

  async getHead(streamId: string): Promise<AuditHead | null> {
    const state = this.#streams.get(streamId);
    if (!state || state.receipts.length === 0) return null;
    return { streamId, sequence: state.sequence, headHash: state.headHash };
  }
}
