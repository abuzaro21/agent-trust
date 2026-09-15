import type { ReasonCode } from '@agent-trust/schemas';

/**
 * Step 13A — AttackScenario abstraction. NOT a red-team framework: a
 * deterministic scenario registry the demo and CI both execute. Every
 * scenario builds its own isolated world (Step 13R) and judges success by
 * BOTH the denial reason AND the security invariants (Step 13N).
 */

export type AttackCategory =
  | 'IDENTITY'
  | 'CREDENTIAL'
  | 'AUTHORITY'
  | 'STATUS'
  | 'REPLAY'
  | 'POLICY'
  | 'AUDIT'
  | 'ATTESTATION'
  | 'DID_WEB'
  | 'INFRASTRUCTURE';

export type ScenarioKind = 'ATTACK' | 'FAILURE_DEMO';

export interface AttackExpected {
  /** Human summary of the required outcome, e.g. 'DENY before policy'. */
  outcome: string;
  /** The single reason code that must appear in the observed denial. */
  reasonCode?: ReasonCode;
  /** Predicate over observed reason codes (when more precision is needed). */
  reasonCodesMatch?: (codes: ReasonCode[]) => boolean;
}

export interface AttackInvariants {
  executorCalls?: number;
  /** Maximum receipts the attack may add for the VICTIM actor. */
  victimReceiptsAddedMax?: number;
  victimHistoryChanged?: false;
  /** Authority entries the victim profile must retain after the attack. */
  victimAuthorityCount?: number;
  /** Trusted attestations the victim profile must retain. */
  victimTrustedAttestations?: number;
  /** Exactly-one semantics for replay races. */
  successfulRefunds?: number;
  /** Generic assertion hook — throw on violation. */
  assert?: () => void | Promise<void>;
}

export interface AttackObserved {
  outcome: string;
  reasonCodes: ReasonCode[];
  invariants: {
    executorCalls?: number;
    victimReceiptsAdded?: number;
    [k: string]: unknown;
  };
}

export interface AttackResult {
  id: string;
  kind: ScenarioKind;
  category: AttackCategory;
  title: string;
  status: 'PASS' | 'FAIL';
  expected: { outcome: string; reasonCode?: ReasonCode };
  observed: AttackObserved;
  durationMs: number;
  detail?: string;
}

export interface AttackContext {
  /** Frozen wall clock (unix seconds) — 2026-09-15T12:00:00Z. */
  now: number;
}

export interface AttackScenario {
  id: string;
  category: AttackCategory;
  kind: ScenarioKind;
  title: string;
  expected: AttackExpected;
  /** Build an ISOLATED world and run the attack (Step 13R). */
  run(ctx: AttackContext): Promise<AttackObserved>;
}
