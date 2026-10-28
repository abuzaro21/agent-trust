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

/**
 * Machine-checked classification of what a scenario observed. The scenario
 * derives it from REAL objects (a gateway result, a loader result, a
 * verifier result) — never from prose — and the runner compares it for
 * equality with `expected.verdict`.
 *
 *  - DENIED       the gateway returned effect DENY (nothing executed)
 *  - REFUSED      a component refused the input (loader, resolver, walker, schema, attestation pipeline)
 *  - DETECTED     an integrity check flagged tampering
 *  - CONTAINED    the attack was processed but changed nothing it must not (replay race, Sybil vouches, cache poisoning, key rotation)
 *  - FAILED_SAFE  an infrastructure failure was handled fail-closed or reported honestly
 *  - BREACHED     the defence did not hold (only ever OBSERVED, never expected)
 */
export type Verdict = 'DENIED' | 'REFUSED' | 'DETECTED' | 'CONTAINED' | 'FAILED_SAFE' | 'BREACHED';
export type ExpectedVerdict = Exclude<Verdict, 'BREACHED'>;

export interface AttackExpected {
  /** Human description of the required outcome. DISPLAY ONLY — it is never evaluated. */
  outcome: string;
  /** The machine-checked outcome class the scenario must observe (see Verdict). */
  verdict: ExpectedVerdict;
  /**
   * Reason-code policy — EXACTLY ONE of the next three must be declared, so a
   * forgotten check can never pass silently:
   */
  /** The single reason code that must appear in the observed denial. */
  reasonCode?: ReasonCode;
  /** Predicate over observed reason codes (when more precision is needed). */
  reasonCodesMatch?: (codes: ReasonCode[]) => boolean;
  /** Justification when the scenario genuinely has no reason code to assert. */
  noReasonCode?: string;
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
  /** Human description of what happened. DISPLAY ONLY — never the oracle. */
  outcome: string;
  /** Typed classification derived from real objects (see Verdict). */
  verdict: Verdict;
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
  expected: { outcome: string; verdict: ExpectedVerdict; reasonCode?: ReasonCode; noReasonCode?: string };
  observed: AttackObserved;
  durationMs: number;
  /** Every reason this scenario FAILED (empty on PASS). */
  failures?: string[];
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
