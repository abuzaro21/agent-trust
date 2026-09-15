export {
  InMemoryAttestationStore,
  InMemoryAgentCredentialStore,
  InMemoryAttestationTrustPolicy,
  asCredentialType,
} from './types.js';
export type {
  AgentCredentialStore,
  AttestationStore,
  AttestationTrustPolicy,
  ProfileContext,
  TrustProfile,
} from './types.js';

export { TrustProfileService, type BuildProfileOptions, type TrustProfileDeps } from './service.js';
