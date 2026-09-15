import type { AuthorizedAction, ExecutionResult } from './types.js';

/**
 * Demo enterprise side effect (Step 10I/10J): an in-memory refund ledger.
 * Real code, not a UI simulation — but deliberately NOT reachable except
 * through gateway authorization in production/demo wiring.
 *
 * Idempotency (Step 10J): taskId is the idempotency key. The SAME key
 * always returns the SAME logical result and never creates a second
 * refund — protecting against network retry, gateway crash after
 * execution, or client retry with a fresh transport request. The honest
 * guarantee is at-most-once replay proof + idempotent side effect, not
 * distributed exactly-once.
 */
export interface RefundRecord {
  taskId: string;
  actorDid: string;
  amount?: number;
  currency?: string;
  refundId: string;
}

export class DemoRefundExecutor {
  readonly #ledger = new Map<string, RefundRecord>();
  readonly #callCount = { total: 0, succeeded: 0, failed: 0 };
  readonly #refundCounter = { n: 0 };
  /** When set, the executor simulates a business failure for matching taskIds. */
  readonly #failTaskIds: Set<string>;

  constructor(opts: { failTaskIds?: string[] } = {}) {
    this.#failTaskIds = new Set(opts.failTaskIds ?? []);
  }

  get callCount(): { total: number; succeeded: number; failed: number } {
    return { ...this.#callCount };
  }

  get ledger(): RefundRecord[] {
    return [...this.#ledger.values()];
  }

  /** Count of DISTINCT logical refunds (idempotent repeats excluded). */
  get successfulRefundCount(): number {
    return this.#refundCounter.n;
  }

  async execute(action: AuthorizedAction): Promise<ExecutionResult> {
    this.#callCount.total += 1;
    const existing = this.#ledger.get(action.taskId);
    if (existing !== undefined) {
      // Idempotent repeat: same logical result, NO duplicate refund.
      return { state: 'SUCCEEDED', result: existing, detail: 'idempotent-replay' };
    }

    if (this.#failTaskIds.has(action.taskId)) {
      this.#callCount.failed += 1;
      return { state: 'FAILED', detail: 'refund provider rejected the operation' };
    }

    this.#refundCounter.n += 1;
    const record: RefundRecord = {
      taskId: action.taskId,
      actorDid: action.actorDid,
      amount: action.parameters?.amount,
      currency: action.parameters?.currency,
      refundId: `refund_${String(this.#refundCounter.n).padStart(6, '0')}`,
    };
    this.#ledger.set(action.taskId, record);
    this.#callCount.succeeded += 1;
    return { state: 'SUCCEEDED', result: record };
  }
}
