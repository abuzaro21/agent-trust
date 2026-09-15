import type { ReasonCode } from '@agent-trust/schemas';

/**
 * PolicyEngine seam (ADR-0002). The ONLY input is VerifiedFacts — facts
 * already proven by trusted code. The ONLY output is a PolicyDecision.
 * Implementations: OpaWasmPolicyEngine (P0). Remote/Cedar engines slot in
 * behind this interface without touching the trust pipeline.
 */
export interface PolicyEngine {
  evaluate(input: unknown): Promise<PolicyDecision>;
}

/** PolicyEffect: REQUIRE_APPROVAL is contract-supported, HITL is P1. */
export type PolicyEffect = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

export interface PolicyDecision {
  effect: PolicyEffect;
  reasonCodes: ReasonCode[];
  policy: {
    id: string;
    version: string;
    /** 'sha256:<64 hex>' of policy.wasm, verified at load time. */
    hash: string;
  };
}

/**
 * policy.wasm + manifest.json artifacts (Step 8I). The loader computes the
 * SHA-256 of the wasm bytes and compares against manifest.sha256 — a
 * mismatch fails closed (POLICY_BUNDLE_INVALID).
 */
export interface PolicyManifest {
  id: string;
  version: string;
  entrypoint: string;
  sha256: string;
  compiledBy: string;
}

/** Deterministic policy-infrastructure denial (Step 8J/8Q). */
export type PolicyInfrastructureDenial = Extract<
  ReasonCode,
  'POLICY_BUNDLE_INVALID' | 'POLICY_ENGINE_UNAVAILABLE' | 'POLICY_EVALUATION_ERROR' | 'REQUEST_MALFORMED'
>;

export type PolicyLoadSuccess = {
  ok: true;
  engine: PolicyEngine;
  manifest: PolicyManifest;
  hash: string;
};

export type PolicyLoadFailure = {
  ok: false;
  reasonCode: PolicyInfrastructureDenial;
  detail: string;
};

export type PolicyLoadResult = PolicyLoadSuccess | PolicyLoadFailure;
