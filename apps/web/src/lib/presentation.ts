/**
 * Pure presentation helpers shared by the UI and its tests. NOTHING here
 * computes authorization: these map already-decided backend data (the
 * gateway's stages, reason codes and the signed credential's limits) to
 * layout and plain-English text.
 */

import type { DecisionDto, ProfileDto } from './dto';

// --------------------------------------------------------------- pipeline

export type Tone = 'ok' | 'deny' | 'warn' | 'neutral';

export interface StageView {
  key: string;
  label: string;
  value: string;
  tone: Tone;
}

export type PipelineGroupId = 'verification' | 'policy' | 'provenance';

export interface PipelineStepView extends StageView {
  /** One sentence: what this step establishes. */
  detail: string;
  /** Position in the real gateway execution order (1-based). */
  order: number;
}

export interface PipelineGroupView {
  id: PipelineGroupId;
  title: string;
  subtitle: string;
  steps: PipelineStepView[];
}

/**
 * The REAL gateway order (packages/gateway/src/gateway.ts):
 *   request schema → identity/PoP → replay claim → credentials (+status,
 *   quarantine) → delegation chain → policy → decision receipt → executor →
 *   outcome receipt.
 * `source` names the GatewayResult stage the value is read from.
 */
export const PIPELINE_STEPS: {
  key: string;
  label: string;
  group: PipelineGroupId;
  source: keyof DecisionDto['stages'] | 'outcomeReceipt';
  detail: string;
}[] = [
  { key: 'identity', label: 'Identity', group: 'verification', source: 'identity', detail: 'The request is signed with the key published in the agent’s DID document (proof of possession).' },
  { key: 'replay', label: 'Replay claim', group: 'verification', source: 'replay', detail: 'These exact signed bytes have not been used before (claim-once).' },
  { key: 'credential', label: 'Credentials & status', group: 'verification', source: 'credential', detail: 'Signature, trusted issuer, expiry, revocation/suspension status, and quarantine.' },
  { key: 'delegation', label: 'Delegation chain verified', group: 'verification', source: 'authority', detail: 'The delegation credential is valid and bound to this agent. Passing here does not mean the amount is allowed — limits are enforced by the policy step.' },
  { key: 'policy', label: 'Policy decision', group: 'policy', source: 'policy', detail: 'Is this specific action acceptable now? Deterministic policy over verified facts only; it enforces the action, resource, audience, amount and time limits from the delegation.' },
  { key: 'decisionReceipt', label: 'Decision receipt', group: 'provenance', source: 'audit', detail: 'The decision is appended to the hash-chained audit log before anything executes.' },
  { key: 'execution', label: 'Execution (simulated)', group: 'provenance', source: 'execution', detail: 'Runs only after ALLOW and a durable decision receipt. The executor is a simulation.' },
  { key: 'outcomeReceipt', label: 'Outcome receipt', group: 'provenance', source: 'outcomeReceipt', detail: 'The execution outcome is recorded as a separate chained receipt.' },
];

export const PIPELINE_GROUPS: { id: PipelineGroupId; title: string; subtitle: string }[] = [
  { id: 'verification', title: 'Verification', subtitle: 'What is proven — identity, credentials, delegated authority' },
  { id: 'policy', title: 'Policy', subtitle: 'Is this action acceptable now?' },
  { id: 'provenance', title: 'Provenance & execution', subtitle: 'What is recorded and what runs' },
];

const PASS_VALUES = new Set(['PASS', 'ALLOW', 'SUCCEEDED']);
const FAIL_VALUES = new Set(['FAIL', 'DENY', 'FAILED']);
const WARN_VALUES = new Set(['EXECUTION_UNCERTAIN']);

function toneOf(raw: string): Tone {
  return PASS_VALUES.has(raw) ? 'ok' : FAIL_VALUES.has(raw) ? 'deny' : WARN_VALUES.has(raw) ? 'warn' : 'neutral';
}

/** Flat stage list in the real gateway order (kept for tests and simple callers). */
export function stagesToView(stages: Record<string, string>): StageView[] {
  const order = ['identity', 'replay', 'credential', 'authority', 'policy', 'audit', 'execution'];
  const labels: Record<string, string> = {
    identity: 'Identity',
    replay: 'Replay claim',
    credential: 'Credentials & status',
    authority: 'Delegation chain verified',
    policy: 'Policy decision',
    audit: 'Decision receipt',
    execution: 'Execution (simulated)',
  };
  return order
    .filter((key) => key in stages)
    .map((key) => {
      const raw = stages[key]!;
      return { key, label: labels[key] ?? key, value: raw === 'NOT_RUN' ? '—' : raw, tone: toneOf(raw) };
    });
}

/**
 * Eight-step, three-group pipeline view built ONLY from the GatewayResult.
 * The outcome-receipt step is read from `executionReceiptId` (the backend's
 * own record that the outcome receipt exists); it is never inferred.
 */
export function pipelineView(decision: DecisionDto): PipelineGroupView[] {
  const steps: PipelineStepView[] = PIPELINE_STEPS.map((def, i) => {
    let raw: string;
    if (def.source === 'outcomeReceipt') {
      raw = decision.executionReceiptId !== undefined
        ? 'RECORDED'
        : decision.outcome === 'EXECUTION_UNCERTAIN'
          ? 'EXECUTION_UNCERTAIN'
          : 'NOT_RUN';
    } else {
      raw = decision.stages[def.source];
      // When execution succeeded but its OUTCOME receipt could not be saved the gateway reports
      // stages.audit = FAIL while the decision receipt does exist (decisionReceiptId): the
      // decision receipt is fine; the outcome step carries the failure.
      if (def.key === 'decisionReceipt' && raw === 'FAIL' && decision.decisionReceiptId !== undefined) raw = 'RECORDED';
    }
    const value =
      raw === 'NOT_RUN'
        ? '—'
        : raw === 'EXECUTION_UNCERTAIN'
          ? 'UNRECORDED'
          : def.key === 'execution' && raw === 'SUCCEEDED'
            ? 'SUCCEEDED (simulated)'
            : raw;
    const tone: Tone = raw === 'RECORDED' ? 'ok' : toneOf(raw);
    return { key: def.key, label: def.label, detail: def.detail, value, tone, order: i + 1 };
  });
  return PIPELINE_GROUPS.map((g) => ({
    ...g,
    steps: steps.filter((s) => PIPELINE_STEPS.find((d) => d.key === s.key)!.group === g.id),
  }));
}

/** The first step the backend reports as failed/denied (for the "stopped at" line). */
export function stoppedAt(groups: PipelineGroupView[]): PipelineStepView | undefined {
  return groups.flatMap((g) => g.steps).find((s) => s.tone === 'deny');
}

// ---------------------------------------------------------------- verdict

export interface Verdict {
  kind: 'allow' | 'deny' | 'uncertain';
  tone: 'ok' | 'deny' | 'warn';
  headline: string;
  code: string;
  sentence: string;
}

export function verdictFor(decision: DecisionDto, ctx: { requested?: number; limit?: number; currency?: string } = {}): Verdict {
  if (decision.effect === 'ALLOW' && decision.outcome === 'AUTHORIZED') {
    return {
      kind: 'allow',
      tone: 'ok',
      headline: 'Authorized',
      code: 'WITHIN_AUTHORITY',
      sentence:
        'Every verification step passed and the policy found this action inside the delegated authority. The simulated refund ran and was recorded.',
    };
  }
  const primary = decision.reasonCodes[0];
  if (decision.outcome === 'EXECUTION_UNCERTAIN') {
    return { kind: 'uncertain', tone: 'warn', headline: 'Execution uncertain', code: primary ?? decision.outcome, sentence: explainReason(primary, ctx) };
  }
  return { kind: 'deny', tone: 'deny', headline: 'Denied', code: primary ?? decision.outcome, sentence: explainReason(primary, ctx) };
}

/**
 * Amount-vs-limit meter. Shown ONLY when the backend decision is about the
 * amount (an ALLOW, or AUTHORITY_LIMIT_EXCEEDED). Never for unrelated
 * denials such as a spoofed identity or a revoked credential.
 */
export function amountMeter(
  decision: DecisionDto,
  requested: number | undefined,
  limit: number | undefined,
): { percent: number; label: string; tone: 'ok' | 'deny' } | undefined {
  if (requested === undefined || limit === undefined || limit <= 0) return undefined;
  const allowed = decision.effect === 'ALLOW' && decision.outcome === 'AUTHORIZED';
  const limitDenial = decision.reasonCodes[0] === 'AUTHORITY_LIMIT_EXCEEDED';
  if (!allowed && !limitDenial) return undefined;
  return {
    percent: Math.min(100, Math.round((requested / limit) * 100)),
    label: allowed ? 'within the delegated limit' : 'above the delegated limit',
    tone: allowed ? 'ok' : 'deny',
  };
}

/** The delegated amount limit, as published by the backend's verified profile. */
export function limitFromProfile(profile: ProfileDto | null): { amount: number; currency: string } | undefined {
  const a = profile?.profile.authority.active[0];
  if (a?.limits?.amount === undefined) return undefined;
  return { amount: a.limits.amount, currency: a.limits.currency ?? 'SAR' };
}

// ------------------------------------------------------------ explanations

/** Static, human explanation. Never consulted for authorization. */
export function explainReason(code: string | undefined, details: { requested?: number; limit?: number; currency?: string } = {}): string {
  const cur = details.currency ?? 'SAR';
  switch (code) {
    case 'AUTHORITY_LIMIT_EXCEEDED':
      return details.requested !== undefined && details.limit !== undefined
        ? `Requested ${details.requested.toLocaleString('en-US')} ${cur} is above the ${details.limit.toLocaleString('en-US')} ${cur} limit in the signed delegation. The agent is trusted — but not for this action.`
        : 'The requested amount is above the limit in the signed delegation. The agent is trusted — but not for this action.';
    case 'CURRENCY_MISMATCH':
      return 'The requested currency differs from the currency the delegation is limited to.';
    case 'AUTHORITY_NOT_YET_VALID':
      return 'The delegated authority has not started yet (its validity window is in the future).';
    case 'AUTHORITY_EXPIRED':
      return 'The delegated authority has expired (its validity window has closed).';
    case 'ACTION_NOT_IN_SCOPE':
      return 'The requested action is not part of the delegated authority.';
    case 'RESOURCE_NOT_IN_SCOPE':
      return 'The resource is outside the delegated resource pattern.';
    case 'AUDIENCE_MISMATCH':
      return 'The delegation does not name this destination service.';
    case 'IDENTITY_PROOF_INVALID':
      return 'The signature did not verify against the key published for this identity, so the request is not authenticated. Nothing after identity ran.';
    case 'DID_RESOLUTION_FAILED':
      return 'The agent’s DID document could not be resolved, so its key cannot be checked.';
    case 'CREDENTIAL_REVOKED':
      return 'The credential was revoked on its status list. Revocation is permanent, and revoked credentials cannot authorize new actions.';
    case 'CREDENTIAL_SUSPENDED':
      return 'The credential is currently suspended (a reversible status).';
    case 'CREDENTIAL_STATUS_UNAVAILABLE':
      return 'The credential’s status could not be checked, so the fabric denies rather than guessing.';
    case 'AGENT_QUARANTINED':
      return 'This agent identity is quarantined (emergency kill switch), which stops it even though its own signed proof is valid.';
    case 'REPLAY_DETECTED':
      return 'These exact signed bytes were already used once. Replay protection is claim-once: one authorization, one execution.';
    case 'UNTRUSTED_ISSUER':
      return 'The signature is cryptographically valid, but the issuer is not trusted for this credential type. A valid signature is not permission.';
    case 'WRONG_SUBJECT':
      return 'The credential was issued to a different agent.';
    case 'VC_EXPIRED':
      return 'The credential has expired.';
    case 'VC_NOT_YET_VALID':
      return 'The credential is not valid yet.';
    case 'VC_SIGNATURE_INVALID':
      return 'The credential’s signature did not verify.';
    case 'REQUEST_MALFORMED':
      return 'The request failed input validation (for example an amount that is not a positive number, or a missing credential), so no authorization decision was made. Nothing was executed.';
    case 'POLICY_EVALUATION_ERROR':
      return 'The policy engine failed. The fabric denies rather than guessing; no receipt is written because the policy identity is unknown.';
    case 'AUDIT_LOG_UNAVAILABLE':
      return 'The audit store was unavailable; nothing runs without a durable decision receipt.';
    case 'AUDIT_OUTCOME_UNRECORDED':
      return 'The action ran, but its outcome receipt could not be saved. It is marked uncertain and never blindly retried.';
    case 'REPLAY_PROTECTION_UNAVAILABLE':
      return 'The replay store was unreachable; a protected write fails closed.';
    default:
      return code === undefined ? 'No denial reason reported.' : `Denied: ${code}.`;
  }
}

// ------------------------------------- authorization vs execution (two facts)

export interface FactView {
  tone: Tone;
  label: string;
  detail: string;
}

/**
 * Authorization (the policy decision) and execution (what the simulated
 * executor then did) are different facts and are reported separately. Both
 * are read from the GatewayResult; nothing here decides anything.
 */
export function decisionSplit(decision: DecisionDto): { authorization: FactView; execution: FactView } {
  const policy = decision.stages.policy;
  const authorization: FactView =
    decision.effect === 'ALLOW'
      ? { tone: 'ok', label: 'Allowed by policy', detail: 'The deterministic policy found the request inside the verified authority.' }
      : decision.effect === 'DENY' && policy === 'DENY'
        ? { tone: 'deny', label: 'Denied by policy', detail: 'Every verification step passed; the policy refused this specific request.' }
        : decision.effect === 'DENY'
          ? { tone: 'deny', label: 'Denied before policy', detail: 'A verification step failed, so policy never ran.' }
          : { tone: 'warn', label: 'No authorization decision', detail: 'The request did not reach a policy decision.' };

  const raw = decision.stages.execution;
  const recorded = decision.executionReceiptId !== undefined;
  let execution: FactView;
  if (decision.outcome === 'EXECUTION_UNCERTAIN') {
    execution = { tone: 'warn', label: 'Uncertain (simulated)', detail: 'The simulated action ran but its outcome receipt could not be saved.' };
  } else if (raw === 'SUCCEEDED') {
    execution = {
      tone: 'ok',
      label: 'Succeeded (simulated)',
      detail: recorded ? 'The simulated refund ran; its outcome receipt is recorded. No money moves.' : 'The simulated refund ran. No money moves.',
    };
  } else if (raw === 'FAILED') {
    execution = { tone: 'deny', label: 'Failed (simulated)', detail: 'The simulated executor reported a failure.' };
  } else if (raw === 'NOT_RUN') {
    execution = { tone: 'neutral', label: 'Not run', detail: decision.effect === 'DENY' ? 'Nothing was executed.' : 'The executor did not run.' };
  } else {
    execution = { tone: 'neutral', label: raw, detail: 'Reported by the gateway.' };
  }
  return { authorization, execution };
}

/** "n of 4 verification steps passed" — read from the stages, never inferred. */
export function verificationSummary(decision: DecisionDto): { passed: number; total: number } {
  const steps = pipelineView(decision).find((g) => g.id === 'verification')?.steps ?? [];
  return { passed: steps.filter((s) => s.tone === 'ok').length, total: steps.length };
}

/**
 * How two real responses relate: derived only from the two verdicts the
 * backend produced. 'pending' until both exist.
 */
export function comparisonOf(a: Verdict | undefined, b: Verdict | undefined): 'pending' | 'different' | 'same' {
  if (a === undefined || b === undefined) return 'pending';
  return a.kind === b.kind ? 'same' : 'different';
}

/** The three failure demonstrations shown first; the rest sit behind a disclosure. */
export const PRIMARY_FAILURE_IDS = ['spoof', 'revoked', 'replay'] as const;
/** Grant / scope / revoke: the compact lifecycle story (verify and quarantine live in the suite and failure cases). */
export const COMPACT_LIFECYCLE_KEYS = ['grant', 'scope', 'revoke'] as const;

export function shortHash(value: string | undefined): string {
  if (value === undefined) return '—';
  const hex = value.replace(/^sha256:/, '');
  return hex.length > 20 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex;
}

// ------------------------------------------------------- scenarios & story

export interface ScenarioMeta {
  id: string;
  title: string;
  tone: 'ok' | 'deny' | 'warn';
  proves: string;
  /** Honest caveat shown on the card. */
  note?: string;
  /** Attack-suite scenario that covers this case with side-effect invariants. */
  suite: string;
}

export const FAILURE_SCENARIOS: ScenarioMeta[] = [
  { id: 'spoof', title: 'Spoofed agent', tone: 'deny', suite: 'IDENTITY-001', proves: 'An impostor claims the SupportAgent’s DID but signs with its own key. Identity fails first; policy and execution never run.', note: 'No receipt is attributed to the victim.' },
  { id: 'revoked', title: 'Revoked credential', tone: 'deny', suite: 'STATUS-001', proves: 'Revoking a credential (one bit on a status list) blocks the next request that carries it, even from the legitimate agent.', note: 'Uses a separate isolated credential so the main one stays valid for other visitors.' },
  { id: 'replay', title: 'Replayed request', tone: 'deny', suite: 'REPLAY-001', proves: 'The identical signed request is accepted once and rejected the second time: one authorization, one execution.', note: 'The server sends the same request twice; this demonstrates the protection, it is not a live external attacker.' },
  { id: 'quarantine', title: 'Quarantined agent', tone: 'warn', suite: 'STATUS-003', proves: 'An emergency kill switch stops an identity even when its own signed proof is valid.' },
  { id: 'wrong-audience', title: 'Wrong audience', tone: 'warn', suite: 'IDENTITY-004', proves: 'A delegation only works for the service it names; the same request aimed at another service is denied.' },
  { id: 'tampered', title: 'Tampered request', tone: 'warn', suite: 'IDENTITY-003', proves: '120 SAR is signed but 5000 SAR is sent. The signature no longer matches the content, so identity fails before policy sees the amount.' },
];

export const PRIMARY_SCENARIOS: { id: 'valid-120' | 'over-5000'; amount: number; title: string }[] = [
  { id: 'valid-120', amount: 120, title: 'Request 120 SAR' },
  { id: 'over-5000', amount: 5000, title: 'Request 5,000 SAR' },
];

export interface LifecycleStep {
  key: 'grant' | 'scope' | 'verify' | 'revoke' | 'quarantine';
  title: string;
  text: string;
  /** Preset that exercises this step on real backend code. */
  preset?: string;
  /** Attack-suite scenario that proves it with invariants. */
  suite?: string;
}

/**
 * Grant → scope → verify → revoke/quarantine, as an explanation backed by
 * existing fixtures. No step mutates shared state from the public page.
 */
export const LIFECYCLE: LifecycleStep[] = [
  { key: 'grant', title: 'Grant', text: 'An issuer the verifier trusts signs a delegation credential to the agent (a W3C VC as a compact JWS). The credential below is that grant.' },
  { key: 'scope', title: 'Scope', text: 'The grant is narrow: one action, a resource pattern, one audience, an amount cap and a validity window. Requests outside it are denied.', preset: 'over-5000', suite: 'AUTHORITY-001' },
  { key: 'verify', title: 'Verify', text: 'Every request re-proves identity, freshness, credential signature, issuer trust and current status before policy decides.', preset: 'valid-120', suite: 'IDENTITY-001' },
  { key: 'revoke', title: 'Revoke', text: 'The issuer flips a bit on a status list. The next request with that credential is denied; revocation is permanent, suspension is reversible.', preset: 'revoked', suite: 'STATUS-001' },
  { key: 'quarantine', title: 'Quarantine', text: 'An operator can stop an identity outright, regardless of what its credentials say.', preset: 'quarantine', suite: 'STATUS-003' },
];

export const STANDARDS: { name: string; use: string }[] = [
  { name: 'W3C DID Core · did:web', use: 'Agent and issuer identities resolve over HTTPS' },
  { name: 'W3C VC Data Model 2.0 (compact JWS)', use: 'Signed delegation and attestation credentials' },
  { name: 'JOSE / ES256 (P-256)', use: 'Signatures on credentials, proofs and checkpoints' },
  { name: 'W3C Bitstring Status List', use: 'Revocation and suspension' },
  { name: 'RFC 8785 JSON canonicalization', use: 'Stable bytes for signing and hashing' },
  { name: 'OPA Rego → WebAssembly', use: 'Deterministic, hash-pinned policy' },
];
