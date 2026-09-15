/**
 * Pure presentation helpers shared by the UI and its tests. NOTHING here
 * computes authorization: these map already-decided backend data to text.
 */

export interface StageView {
  key: string;
  label: string;
  value: string;
  tone: 'ok' | 'deny' | 'warn' | 'neutral';
}

const STAGE_LABELS: [key: string, label: string][] = [
  ['identity', 'Identity'],
  ['replay', 'Replay'],
  ['credential', 'Credentials + Status'],
  ['authority', 'Authority'],
  ['policy', 'Policy'],
  ['audit', 'Audit'],
  ['execution', 'Execution'],
];

const PASS_VALUES = new Set(['PASS', 'ALLOW', 'SUCCEEDED']);
const FAIL_VALUES = new Set(['FAIL', 'DENY', 'FAILED']);
const WARN_VALUES = new Set(['EXECUTION_UNCERTAIN']);

export function stagesToView(stages: Record<string, string>): StageView[] {
  // Order the pipeline the way the trust chain reads: identity → … → audit.
  const order = ['identity', 'credential', 'authority', 'replay', 'policy', 'audit', 'execution'];
  return order
    .filter((key) => key in stages)
    .map((key) => {
      const raw = stages[key]!;
      const value = raw === 'NOT_RUN' ? '—' : raw;
      const tone: StageView['tone'] = PASS_VALUES.has(raw)
        ? 'ok'
        : FAIL_VALUES.has(raw)
          ? 'deny'
          : WARN_VALUES.has(raw)
            ? 'warn'
            : 'neutral';
      const label = STAGE_LABELS.find(([k]) => k === key)?.[1] ?? key;
      return { key, label, value, tone };
    });
}

/** Static, human explanation. Never consulted for authorization. */
export function explainReason(code: string | undefined, details: Record<string, unknown> = {}): string {
  switch (code) {
    case 'AUTHORITY_LIMIT_EXCEEDED':
      return `Requested ${String(details.amount ?? 'more')} ${String(details.currency ?? 'SAR')} exceeds the delegated ${String(details.limit ?? '500')} ${String(details.currency ?? 'SAR')} limit.`;
    case 'ACTION_NOT_IN_SCOPE':
      return 'The action is not part of the delegated authority.';
    case 'RESOURCE_NOT_IN_SCOPE':
      return 'The resource is outside the delegated resource pattern.';
    case 'AUDIENCE_MISMATCH':
      return 'The delegation does not name this destination service.';
    case 'IDENTITY_PROOF_INVALID':
      return 'The proof-of-possession did not verify against the resolved identity key — the request is not authenticated.';
    case 'CREDENTIAL_REVOKED':
      return 'The credential was revoked. Revocation is permanent.';
    case 'CREDENTIAL_SUSPENDED':
      return 'The credential is currently suspended.';
    case 'AGENT_QUARANTINED':
      return 'The agent identity is quarantined (emergency kill switch).';
    case 'REPLAY_DETECTED':
      return 'These exact signed bytes were already used once. Replay protection is claim-once.';
    case 'UNTRUSTED_ISSUER':
      return 'The signature is cryptographically valid, but the issuer is not trusted for this credential type.';
    case 'WRONG_SUBJECT':
      return 'The credential was issued to a different agent.';
    case 'REQUEST_MALFORMED':
      return 'The request is incomplete — at minimum a valid delegation credential is required.';
    case 'POLICY_EVALUATION_ERROR':
      return 'The policy engine failed; the fabric denies rather than guessing.';
    case 'AUDIT_LOG_UNAVAILABLE':
      return 'The audit store was unavailable; no side effect runs without a durable decision receipt.';
    case 'AUDIT_OUTCOME_UNRECORDED':
      return 'Execution happened but its outcome receipt could not be persisted — marked uncertain, never blindly retried.';
    case 'REPLAY_PROTECTION_UNAVAILABLE':
      return 'The replay store was unreachable; a protected write fails closed.';
    default:
      return code ?? 'No denial reason reported.';
  }
}

export function shortHash(value: string | undefined): string {
  if (value === undefined) return '—';
  const hex = value.replace(/^sha256:/, '');
  return hex.length > 20 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex;
}
