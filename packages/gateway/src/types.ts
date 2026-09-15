import type { ReasonCode } from '@agent-trust/schemas';
import type { ActionReceipt } from '@agent-trust/audit';

/**
 * Mirror of the VerifiedFacts wire contract (schemas/verified-facts).
 * Constructed ONLY by the gateway's centralized builder from verified
 * stage outputs — never ad hoc.
 */
export interface VerifiedFacts {
  actor: { did: string; controller?: string };
  request: {
    action: string;
    resource: string;
    audience: string;
    parameters?: { amount?: number; currency?: string };
  };
  identity: { proofVerified: true };
  credential: { verified: true; issuer: string; issuerTrusted: true; types: string[] };
  authority: {
    actions: string[];
    resources: string[];
    audience?: string[];
    limits?: { amount?: number; currency?: string; perDay?: number };
  };
  status: { credentialActive: true; quarantined: false };
  replay: { checked: true; claimed: true };
  context: { now: string };
}

/**
 * Gateway result / executor contracts (Step 10). Stages report PASS / FAIL
 * / NOT_RUN so the demo (and later the dashboard) can show exactly which
 * trust layer decided what. Reason codes always come from the layer that
 * actually failed — never a generic blob.
 */

export type StageResult = 'PASS' | 'FAIL' | 'NOT_RUN';
export type PolicyStage = 'ALLOW' | 'DENY' | 'NOT_RUN';
export type ExecutionStage = 'SUCCEEDED' | 'FAILED' | 'NOT_RUN' | 'UNKNOWN';

export type GatewayOutcome =
  | 'AUTHORIZED'
  | 'DENIED'
  | 'EXECUTION_FAILED'
  | /** execution result known to the process but the outcome receipt could not be persisted */ 'EXECUTION_UNCERTAIN';

export interface GatewayStages {
  identity: StageResult;
  replay: StageResult;
  credential: StageResult;
  authority: StageResult;
  policy: PolicyStage;
  audit: StageResult;
  execution: ExecutionStage;
}

export interface GatewayResult {
  taskId: string;
  outcome: GatewayOutcome;
  effect?: 'ALLOW' | 'DENY';
  reasonCodes: ReasonCode[];
  stages: GatewayStages;
  decisionReceiptId?: string;
  executionReceiptId?: string;
}

/** The action handed to the executor ONLY after gateway authorization. */
export interface AuthorizedAction {
  taskId: string;
  actorDid: string;
  audienceDid: string;
  action: string;
  resource: string;
  parameters?: { amount?: number; currency?: string };
  decisionReceiptId: string;
}

export interface ExecutionResult {
  state: 'SUCCEEDED' | 'FAILED';
  /** Deterministic digest of the business result — receipts store the digest. */
  result?: unknown;
  detail?: string;
}

/**
 * Side-effect boundary (Step 10I). The gateway owns the ONLY production
 * call path; the executor exists independently for tests, but the demo
 * wiring never exposes it outside gateway authorization.
 */
export interface ActionExecutor {
  execute(action: AuthorizedAction): Promise<ExecutionResult>;
}
