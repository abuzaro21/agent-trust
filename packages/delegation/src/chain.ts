import type { AttenuationResult, DelegationParty } from './attenuate.js';
import { validateDelegation } from './attenuate.js';

/**
 * Validates a whole delegation chain: root authority first, then each
 * successive attenuation. Duplicate DIDs anywhere in the chain are cycles.
 * The first failing link (in order) decides the returned reason codes.
 */
export function validateDelegationChain(chain: readonly DelegationParty[]): AttenuationResult {
  if (chain.length < 2) {
    return { ok: true, reasonCodes: ['ATTENUATION_VERIFIED'] };
  }

  const seen = new Set<string>();
  for (const party of chain) {
    if (seen.has(party.did)) {
      return {
        ok: false,
        reasonCodes: ['DELEGATION_CYCLE'],
        failedConstraints: [
          { field: 'chain.did', actual: party.did, operator: 'unique', expected: 'no repeated DIDs' },
        ],
      };
    }
    seen.add(party.did);
  }

  for (let i = 0; i < chain.length - 1; i++) {
    const parent = chain[i];
    const child = chain[i + 1];
    if (parent === undefined || child === undefined) {
      break; // unreachable given length check; satisfies noUncheckedIndexedAccess
    }
    const result = validateDelegation({ parent, child });
    if (!result.ok) return result;
  }
  return { ok: true, reasonCodes: ['ATTENUATION_VERIFIED'] };
}
