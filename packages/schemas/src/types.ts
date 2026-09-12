/**
 * Core contract types. The JSON Schema modules in ./schemas are the
 * wire-format contracts; these interfaces are their TypeScript mirror.
 * If the two ever disagree, the schema validation tests must fail.
 */
import type { ReasonCode } from './reason-codes.js';

/** Policy decision effects. REQUIRE_APPROVAL escalates to human-in-the-loop. */
export type Effect = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

/** DID string, any supported method (did:web, did:key in P0). */
export type Did = string;

/** Scoped authority granted by a DelegationCredential. */
export interface AuthorityLimits {
  /** Maximum single-action amount. */
  amount?: number;
  currency?: string;
  /** Maximum operations per day. */
  perDay?: number;
}

export interface Authority {
  /** Permitted actions, e.g. ["refund:create"]. Child ⊆ parent (attenuation). */
  actions: string[];
  /** Permitted resources, e.g. ["tenant:acme"]. Child ⊆ parent. */
  resources: string[];
  /** DIDs of services this authority may be used against. */
  audience?: Did[];
  limits?: AuthorityLimits;
  /**
   * Remaining sub-delegation budget. 0 = leaf agent, cannot delegate further.
   * child.depth < parent.remainingDepth is enforced structurally.
   */
  delegationDepth: number;
}

/**
 * Proof-of-possession bound to one request. `signature` is base64url(ES256)
 * over canonicalJson({ htu, requestBodyDigest, jti, iat, exp, nonce? }) —
 * see packages/crypto proof.ts. Replay key: replay:<aud>:<kid>:<jti>.
 */
export interface AgentProof {
  /** DID URL of the verification method, e.g. did:key:z6Mk...#<thumbprint> */
  kid: string;
  /** Unique per request — the replay-protection token (ADR-0003). */
  jti: string;
  /** Unix seconds. */
  iat: number;
  /** Unix seconds. Short-lived by design. */
  exp: number;
  /** Optional server-issued challenge. */
  nonce?: string;
  signature: string;
}

export interface FailedConstraint {
  field: string;
  actual: unknown;
  operator: string;
  expected: unknown;
}

export interface PolicyDecision {
  decisionId: string;
  effect: Effect;
  reasonCodes: ReasonCode[];
  failedConstraints?: FailedConstraint[];
  matchedPolicies?: string[];
  evidenceRefs?: string[];
  /** SHA-256 of the policy bundle that produced this decision. */
  policyBundleHash: string;
  expiresAt?: string;
}

/** Pre-verified facts handed to the policy engine — never raw crypto input. */
export interface PolicyActor {
  did: Did;
  controller?: Did;
  quarantined: boolean;
}

export interface PolicyRequest {
  action: string;
  amount?: number;
  currency?: string;
  resource: string;
}

/** Effective authority derived from the verified delegation chain, or null. */
export interface PolicyAuthority {
  actions: string[];
  maxAmount?: number;
  currency?: string;
}

export interface PolicyEvidence {
  credentialsValid: boolean;
  revocationChecked: boolean;
  replaySafe: boolean;
  successfulSimilarActions30d?: number;
  unresolvedIncidents?: number;
}

export interface PolicyInput {
  actor: PolicyActor;
  request: PolicyRequest;
  authority: PolicyAuthority | null;
  evidence: PolicyEvidence;
}

/** POST /v1/trust/evaluate request body. */
export interface TrustEvaluateRequest {
  actor: Did;
  action: string;
  resource: string;
  parameters?: Record<string, unknown>;
  /** Target service agent DID. */
  audience?: Did;
  taskId: string;
  nonce?: string;
  /** Compact JWS Verifiable Credentials. */
  credentials: string[];
  proof: AgentProof;
}

export interface TrustEvaluateResponse extends PolicyDecision {}

/** One entry in the tamper-evident action hash chain. */
export interface ActionReceipt {
  eventId: string;
  actorDid: Did;
  action: string;
  resource: string;
  decisionId: string;
  effect: Effect;
  requestHash: string;
  /** 'genesis' for the first entry. */
  previousHash: string;
  eventHash: string;
  timestamp: string;
}
