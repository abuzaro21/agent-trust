export {
  SUPPORTED_CREDENTIAL_TYPES,
  type CredentialClaims,
  type CredentialDocument,
  type CredentialType,
  type TimeInput,
  type VcVerification,
  type VerifiedFacts,
  toIso,
  toUnixSeconds,
} from './types.js';

export {
  JwsFormatError,
  decodeJwsPayload,
  parseCompactJws,
  signCompactJws,
  verifyCompactJwsSignature,
  type ParsedJws,
} from './jws.js';

export { InMemoryIssuerTrustStore, type IssuerTrustStore } from './trust.js';

export {
  CredentialIssuer,
  type DelegationInput,
  type MembershipInput,
} from './issue.js';

export {
  CredentialVerifier,
  type VerifyOptions,
  type VerifierDeps,
} from './verify.js';

export type {
  AgentQuarantineStore,
  CredentialStatusCheckInput,
  CredentialStatusChecker,
  CredentialStatusEntry,
  CredentialStatusResult,
  CredentialStatusState,
  StatusGateDenial,
} from './status-seam.js';
