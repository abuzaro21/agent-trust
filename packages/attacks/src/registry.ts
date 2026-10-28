import type { AttackScenario } from './types.js';
import { allOf, requireAtLeast, requireInvariants, requireNonEmptyString, type InvariantCheck, type InvariantVerdict } from './oracle.js';
import { IDENTITY_SCENARIOS } from './scenarios-identity.js';
import { CREDENTIAL_SCENARIOS } from './scenarios-identity.js';
import { AUTHORITY_SCENARIOS } from './scenarios-authority.js';
import { STATUS_SCENARIOS } from './scenarios-status.js';
import { REPLAY_SCENARIOS, POLICY_SCENARIOS } from './scenarios-replay-policy.js';
import { AUDIT_SCENARIOS } from './scenarios-audit.js';
import { ATTEST_SCENARIOS } from './scenarios-attestation.js';
import { DIDWEB_SCENARIOS } from './scenarios-didweb.js';
import { INFRA_SCENARIOS } from './scenarios-infra.js';

/**
 * Step 13B — the deterministic attack registry. IDs are stable and
 * referenced by docs/threat-model.md and the README video shortlist.
 *
 * Every scenario's evidence requirements live in ONE declarative table
 * (EVIDENCE_SPEC). A checker is generated from it, and a registry test
 * independently violates EVERY asserted key (delete + corrupt) and fails if a
 * scenario records a key that is neither asserted nor explicitly listed as
 * `informational` — so evidence can no longer be recorded and then ignored.
 * Checkers use the strict helpers in ./oracle.ts: a missing key fails, and an
 * empty specification fails.
 */

export type { InvariantCheck };

export interface EvidenceSpec {
  /** Keys that must be present and strictly (structurally) equal to these values. */
  equals?: Record<string, unknown>;
  /** Numeric keys that must be present and >= the minimum. */
  atLeast?: Record<string, number>;
  /** String keys that must be present and non-empty (typed cause markers). */
  nonEmptyString?: string[];
  /** Recorded for the human report only; deliberately NOT asserted. Every entry is a reviewed decision. */
  informational?: string[];
}

const blockedBeforePolicy: EvidenceSpec = { equals: { executorCalls: 0, policyCalls: 0 } };
/** Policy RAN (and denied); the executor never did. */
const deniedByPolicy: EvidenceSpec = { equals: { executorCalls: 0 }, atLeast: { policyCalls: 1 } };
/** Credential/status gate stopped the request: neither policy nor executor ran, and the credential stage is the typed cause. */
const stoppedAtCredentialStage: EvidenceSpec = { equals: { executorCalls: 0, policyCalls: 0, credentialStage: 'FAIL' } };
/** Tampering is caught on a history that verified cleanly beforehand, and the consumer suppresses the tampered history. */
const auditTamper = (extra: Record<string, unknown>): EvidenceSpec => ({
  equals: { controlIntact: true, controlConsumerHistoryVerified: true, consumerHistoryVerified: false, consumerHistoryEmpty: true, ...extra },
});
/** Resolver refused a bad did:web response: good document resolves through the same transport, nothing cached, typed DID-Core error pinned. */
const didRefused = (error: string, extra: Record<string, unknown> = {}): EvidenceSpec => ({
  equals: { controlResolves: true, resolutionError: error, notCached: true, ...extra },
});
/** SSRF guard refused before any connect attempt, with the typed POLICY error, and the same transport DOES connect to a public address. */
const ssrfBlocked = (extra: Record<string, unknown> = {}): EvidenceSpec => ({
  equals: { blockedPreConnect: true, connectAttempts: 0, controlPublicAddressConnects: true, transportErrorCode: 'POLICY', ...extra },
});

export const EVIDENCE_SPEC: Record<string, EvidenceSpec> = {
  'IDENTITY-001': { equals: { policyCalls: 0, executorCalls: 0, victimReceiptsAdded: 0, victimHistoryDecisions: { allow: 0, deny: 0 } } },
  'IDENTITY-002': blockedBeforePolicy,
  'IDENTITY-003': blockedBeforePolicy,
  'IDENTITY-004': { equals: { positiveControlAuthorized: true, executorCalls: 0 } },
  'CREDENTIAL-001': blockedBeforePolicy,
  // The verifier's own kid/issuer binding is exercised with a permissive resolver whose issuer document wrongly lists the attacker's key.
  'CREDENTIAL-002': {
    equals: { executorCalls: 0, policyCalls: 0, permissiveResolverControl: ['ACCEPTED'], permissiveResolverForgedReasons: ['VC_ISSUER_KEY_MISMATCH'] },
  },
  'CREDENTIAL-003': blockedBeforePolicy,
  'CREDENTIAL-004': blockedBeforePolicy,
  'CREDENTIAL-005': blockedBeforePolicy,
  'CREDENTIAL-006': blockedBeforePolicy,
  'AUTHORITY-001': deniedByPolicy,
  'AUTHORITY-002': deniedByPolicy,
  'AUTHORITY-003': deniedByPolicy,
  'AUTHORITY-004': deniedByPolicy,
  // Delegation walker, exercised directly (the gateway accepts a single link): rejects the attack, accepts the control.
  'AUTHORITY-005': { equals: { walkerRejected: true, controlAttenuatedChainAccepted: true } },
  'AUTHORITY-006': { equals: { walkerRejected: true, notStrictlyLessRejected: true, controlWithinBudgetChainAccepted: true } },
  'STATUS-001': blockedBeforePolicy,
  'STATUS-002': blockedBeforePolicy,
  // Quarantine: the gateway denies before policy, AND each of the verifier's two quarantine stages is independently reached.
  'STATUS-003': {
    equals: {
      executorCalls: 0,
      policyCalls: 0,
      verifierControlBeforeQuarantine: ['ACCEPTED'],
      verifiedSubjectStageReasons: ['AGENT_QUARANTINED'],
      earlyActorStageReasons: ['AGENT_QUARANTINED'],
    },
  },
  'STATUS-004': stoppedAtCredentialStage,
  'STATUS-005': stoppedAtCredentialStage,
  'STATUS-006': stoppedAtCredentialStage,
  'REPLAY-001': { equals: { firstAuthorized: true, secondDenied: true, successfulRefunds: 1, executorCalls: 1 } },
  'REPLAY-002': { equals: { authorizedCount: 1, deniedCount: 99, replayDeniedCount: 99, successfulRefunds: 1, executorCalls: 1 } },
  'REPLAY-003': blockedBeforePolicy,
  'REPLAY-004': { equals: { attackerDenied: true, legitAuthorized: true, successfulRefunds: 1, executorCalls: 1 } },
  // Loader boundary: the genuine artifact loads (control), the corrupted ones never yield an engine.
  'POLICY-001': {
    equals: {
      controlLoadsEngine: true,
      flippedByteStage: 'hash_mismatch',
      flippedByteEngineObtainable: false,
      garbageWithMatchingDigestPassesDigestGate: true,
      garbageRefusedAtInstantiation: true,
      garbageEngineObtainable: false,
    },
  },
  'POLICY-002': { equals: { controlLoadsEngine: true, refusalStage: 'hash_mismatch', engineObtainable: false } },
  'POLICY-003': { equals: { executorCalls: 0 } },
  'POLICY-004': { equals: { schemaRejectedScore: true, controlValidWithoutScore: true, engineDecisionEffect: 'DENY' } },
  'AUDIT-001': auditTamper({ chainValid: false }),
  'AUDIT-002': auditTamper({ chainValid: false }),
  'AUDIT-003': auditTamper({ chainValid: false }),
  'AUDIT-004': auditTamper({ chainValid: false }),
  'AUDIT-005': auditTamper({ chainValid: false }),
  'AUDIT-006': auditTamper({ chainValid: false }),
  // A coherent rewrite passes the chain walk by construction; the signed checkpoint must still reject it.
  'AUDIT-007': auditTamper({ rewrittenChainCoherent: true, checkpointRejected: true }),
  'AUDIT-008': auditTamper({ anchoredValid: false }),
  // Four forgeries, each rejected at its own gate; the genuine checkpoint verifies under the same signer pin.
  'AUDIT-009': {
    equals: {
      controlIntact: true,
      controlPinnedGenuineVerifies: true,
      wrongSignerReasons: ['AUDIT_SIGNER_UNTRUSTED'],
      badSignatureReasons: ['AUDIT_CHECKPOINT_INVALID'],
      editedPayloadReasons: ['AUDIT_CHECKPOINT_INVALID'],
      otherStreamReasons: ['AUDIT_CHECKPOINT_MISMATCH'],
    },
  },
  'ATTEST-001': { equals: { victimAuthorityCount: 1, controlTrustedAttestations: 1, rejectedReasons: ['ATTESTATION_TYPE_UNSUPPORTED', 'UNTRUSTED_ISSUER'] } },
  'ATTEST-002': { equals: { policyDeniedOverLimit: true, victimTrustedAttestations: 0, sybilRejected: 100, victimAuthorityCount: 1 } },
  'ATTEST-003': { equals: { executorCalls: 0, victimTrustedAttestations: 2 } },
  'ATTEST-004': { equals: { trustedBefore: 1, victimTrustedAttestations: 0 } },
  'ATTEST-005': { equals: { controlTrustedAttestations: 1, wrongSubjectRejected: 1 } },
  'DIDWEB-001': didRefused('invalidDid'),
  'DIDWEB-002': ssrfBlocked(),
  'DIDWEB-003': ssrfBlocked(),
  'DIDWEB-004': ssrfBlocked(),
  // Rebinding: one lookup only, and the connection primitive receives the address that was VALIDATED (the first answer).
  'DIDWEB-005': ssrfBlocked({ lookupsForOneRequest: 1, connectedAddresses: ['93.184.216.34'] }),
  'DIDWEB-006': didRefused('internalError', { redirectRefusedByPolicy: true }),
  'DIDWEB-007': didRefused('internalError', { declaredLengthCap: 'TOO_LARGE', streamedBytesCap: 'TOO_LARGE', belowLimitControl: 'OK' }),
  'DIDWEB-008': didRefused('invalidDid'),
  'DIDWEB-009': didRefused('invalidDid', { foreignIdAndControllerRefused: true, foreignIdOwnControllerRefused: true, ownIdForeignControllerRefused: true }),
  'DIDWEB-010': { equals: { firstFailed: true, secondSucceeded: true, secondResolvedToExpectedDid: true } },
  'DIDWEB-011': { equals: { refetchedEveryResolve: true, keyRotated: true, keyAfterIsRotatedKey: true } },
  'INFRA-001': { equals: { executorCalls: 0, policyAllowedThenAuditVeto: true } },
  'INFRA-002': { equals: { decisionEffect: 'ALLOW', decisionReceiptEffect: 'ALLOW', outcomeState: 'FAILED', decisionAndOutcomeChained: true } },
  'INFRA-003': { equals: { outcome: 'EXECUTION_UNCERTAIN', executorCalls: 1, auditAppendAttempts: 2 } },
  'INFRA-004': { equals: { executorCalls: 0 } },
  'INFRA-005': { equals: { executorCalls: 0, policySkipped: true } },
};

/** Keys a spec asserts (equals + atLeast + nonEmptyString). */
export function assertedKeys(spec: EvidenceSpec): string[] {
  return [...Object.keys(spec.equals ?? {}), ...Object.keys(spec.atLeast ?? {}), ...(spec.nonEmptyString ?? [])];
}

export function checkerFor(spec: EvidenceSpec): InvariantCheck {
  return (o) => {
    const parts: InvariantVerdict[] = [];
    if (spec.equals !== undefined) parts.push(requireInvariants(o, spec.equals));
    for (const [k, min] of Object.entries(spec.atLeast ?? {})) parts.push(requireAtLeast(o, k, min));
    for (const k of spec.nonEmptyString ?? []) parts.push(requireNonEmptyString(o, k));
    return allOf(...parts); // an empty spec yields no parts, and allOf() of nothing FAILS
  };
}

export const INVARIANT_CHECKS: Record<string, InvariantCheck> = Object.fromEntries(
  Object.entries(EVIDENCE_SPEC).map(([id, spec]) => [id, checkerFor(spec)]),
);

export const ATTACK_REGISTRY: readonly AttackScenario[] = [
  ...IDENTITY_SCENARIOS,
  ...CREDENTIAL_SCENARIOS,
  ...AUTHORITY_SCENARIOS,
  ...STATUS_SCENARIOS,
  ...REPLAY_SCENARIOS,
  ...POLICY_SCENARIOS,
  ...AUDIT_SCENARIOS,
  ...ATTEST_SCENARIOS,
  ...DIDWEB_SCENARIOS,
  ...INFRA_SCENARIOS,
];
