import { StatusBitstring } from './bitstring.js';
import type { StatusList, StatusListStore, StatusPurpose } from './types.js';
import { StatusListError } from './types.js';

function defaultClock(): number {
  return Math.floor(Date.now() / 1000);
}

export interface CreateListInput {
  id: string;
  purpose: StatusPurpose;
  controllerDid: string;
  sizeBits: number;
}

/**
 * Semantic mutation API over status lists. Callers NEVER read-modify-write
 * bitstrings — every state change is a named operation (revoke / suspend /
 * unsuspend), which later maps onto atomic persistent operations.
 *
 * Lifecycle enforced structurally:
 *  - revocation lists have NO unset operation: `unsuspend` is rejected on
 *    them, so a revoked credential cannot be restored through this API;
 *  - suspension lists accept suspend/unsuspend only;
 *  - `revoke` exists only for revocation lists.
 *
 * Indexes are leased by `assignIndex` and tracked in-memory so two
 * credentials cannot silently share an index before revocation.
 */
export class StatusListManager {
  readonly #store: StatusListStore;
  readonly #clock: () => number;
  readonly #assigned = new Map<string, Set<number>>();

  constructor(store: StatusListStore, opts: { clock?: () => number } = {}) {
    this.#store = store;
    this.#clock = opts.clock ?? defaultClock;
  }

  async createList(input: CreateListInput): Promise<StatusList> {
    if (!Number.isInteger(input.sizeBits) || input.sizeBits <= 0 || input.sizeBits % 8 !== 0) {
      throw new StatusListError('SIZE_INVALID', 'sizeBits must be a positive multiple of 8');
    }
    const list: StatusList = {
      id: input.id,
      purpose: input.purpose,
      controllerDid: input.controllerDid,
      sizeBits: input.sizeBits,
      encodedList: new StatusBitstring(input.sizeBits).toBase64Url(),
      version: 1,
      updatedAt: this.#clock(),
    };
    await this.#store.put(list);
    this.#assigned.set(input.id, new Set());
    return list;
  }

  /** Lease the first unassigned index (credential stays ACTIVE at issuance). */
  async assignIndex(listId: string): Promise<number> {
    const list = await this.#requireList(listId);
    const assigned = this.#assigned.get(listId) ?? new Set<number>();
    const bits = StatusBitstring.fromBase64Url(list.encodedList, list.sizeBits);
    for (let i = 0; i < list.sizeBits; i++) {
      if (!assigned.has(i) && !bits.get(i)) {
        assigned.add(i);
        this.#assigned.set(listId, assigned);
        return i;
      }
    }
    throw new StatusListError('INDEX_OUT_OF_RANGE', `status list ${listId} is full`);
  }

  /** Permanent invalidation. Only exists for revocation lists. */
  async revoke(listId: string, index: number): Promise<StatusList> {
    return this.#setBit(listId, index, 'revocation', true, 'revoke');
  }

  /** Temporary invalidation. Only exists for suspension lists. */
  async suspend(listId: string, index: number): Promise<StatusList> {
    return this.#setBit(listId, index, 'suspension', true, 'suspend');
  }

  /** Restore a suspended credential. Rejected on revocation lists. */
  async unsuspend(listId: string, index: number): Promise<StatusList> {
    return this.#setBit(listId, index, 'suspension', false, 'unsuspend');
  }

  /** Read one credential's bit plus the list snapshot it was read from. */
  async readStatus(
    listId: string,
    index: number,
  ): Promise<{ set: boolean; list: StatusList }> {
    const list = await this.#requireList(listId);
    const bits = this.#decode(list);
    this.#checkIndex(bits, index);
    return { set: bits.get(index), list };
  }

  async #requireList(listId: string): Promise<StatusList> {
    const list = await this.#store.get(listId);
    if (!list) throw new StatusListError('LIST_NOT_FOUND', `status list ${listId} does not exist`);
    return list;
  }

  #decode(list: StatusList): StatusBitstring {
    try {
      return StatusBitstring.fromBase64Url(list.encodedList, list.sizeBits);
    } catch {
      throw new StatusListError('MALFORMED_ENCODING', `status list ${list.id} has a corrupt bitstring`);
    }
  }

  #checkIndex(bits: StatusBitstring, index: number): void {
    if (!Number.isInteger(index) || index < 0 || index >= bits.sizeBits) {
      throw new StatusListError('INDEX_OUT_OF_RANGE', `index ${index} outside [0, ${bits.sizeBits})`);
    }
  }

  async #setBit(
    listId: string,
    index: number,
    requiredPurpose: StatusPurpose,
    value: boolean,
    operation: 'revoke' | 'suspend' | 'unsuspend',
  ): Promise<StatusList> {
    const list = await this.#requireList(listId);
    if (list.purpose !== requiredPurpose) {
      throw new StatusListError(
        'PURPOSE_MISMATCH',
        `${operation} requires a ${requiredPurpose} list, but ${listId} is a ${list.purpose} list`,
      );
    }
    const bits = this.#decode(list);
    this.#checkIndex(bits, index);
    bits.set(index, value);
    const updated: StatusList = {
      ...list,
      encodedList: bits.toBase64Url(),
      version: list.version + 1,
      updatedAt: this.#clock(),
    };
    await this.#store.put(updated);
    return updated;
  }
}
