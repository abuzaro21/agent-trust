import type { StatusList } from './types.js';

/**
 * Deterministic in-memory status-list store for tests and development.
 * Deliberately dumb: the manager owns all semantics, the store only
 * persists whole StatusList snapshots keyed by id.
 */
export class InMemoryStatusListStore {
  readonly #lists = new Map<string, StatusList>();

  async get(listId: string): Promise<StatusList | null> {
    return this.#lists.get(listId) ?? null;
  }

  async put(list: StatusList): Promise<void> {
    this.#lists.set(list.id, { ...list });
  }
}
