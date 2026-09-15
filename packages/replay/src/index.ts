export type {
  ReplayClaim,
  ReplayClaimResult,
  ReplayStore,
} from './types.js';
export { ReplayStoreUnavailableError } from './types.js';

export {
  JTI_PATTERN,
  canonicalReplayNamespace,
  isValidJti,
  replayKey,
  type ReplayNamespaceParts,
} from './key.js';

export { InMemoryReplayStore } from './memory-store.js';

export { RedisReplayStore, type RedisSetNxClient } from './redis-store.js';

export {
  ReplayProtector,
  type ReplayDecision,
  type ReplayProtectorOptions,
  type VerifiedProofContext,
} from './protector.js';

export {
  verifyProofWithReplay,
  type ProofWithReplayInput,
  type ProofWithReplayResult,
} from './verify-with-replay.js';
