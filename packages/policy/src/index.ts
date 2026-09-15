export type {
  PolicyDecision,
  PolicyEffect,
  PolicyEngine,
  PolicyInfrastructureDenial,
  PolicyLoadFailure,
  PolicyLoadResult,
  PolicyLoadSuccess,
  PolicyManifest,
} from './types.js';

export {
  loadBundle,
  normalizeSha256,
  sha256OfBytes,
  validateManifestShape,
  type BundleLoadFailure,
  type LoadedBundle,
} from './manifest.js';

export {
  OpaWasmPolicyEngine,
  loadOpaWasmPolicyEngine,
  type OpaWasmEngineOptions,
} from './opa-wasm-engine.js';

/**
 * Human-readable mapping for tests/demo display ONLY (Step 8
 * explainability). This text NEVER feeds back into any decision — the
 * reason codes are the security truth.
 */
export const REASON_CODE_EXPLANATIONS: Record<string, string> = {
  ACTION_NOT_IN_SCOPE: 'Requested action is not in the delegated authority.',
  RESOURCE_NOT_IN_SCOPE: 'Requested resource is outside the delegated resources.',
  AUDIENCE_MISMATCH: 'Request target is not in the delegated audience.',
  AUTHORITY_NOT_YET_VALID: 'Delegated authority window is not open yet.',
  AUTHORITY_EXPIRED: 'Delegated authority window has closed.',
  CURRENCY_MISMATCH: 'Requested currency differs from the delegated currency.',
  AUTHORITY_LIMIT_EXCEEDED: 'Requested amount exceeds delegated authority.',
  REQUEST_MALFORMED: 'Request facts are malformed or incomplete.',
  POLICY_EVALUATION_ERROR: 'Policy evaluation failed — denied fail-closed.',
  POLICY_BUNDLE_INVALID: 'Policy bundle failed integrity checks — denied fail-closed.',
  POLICY_ENGINE_UNAVAILABLE: 'Policy engine unavailable — denied fail-closed.',
};
