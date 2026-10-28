import type { AttackScenario } from './types.js';
import { allOf, requireAtLeast, requireInvariants, type InvariantCheck } from './oracle.js';
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
 * Every scenario has an invariant checker beyond the reason code: a denial
 * alone proves nothing if the side effect happened anyway. The checkers use
 * the strict helpers in ./oracle.ts — a key the scenario forgot to record
 * FAILS the check (it can never pass by omission), and every checker
 * rejects an empty observation (asserted by test/registry-integrity.test.ts).
 */

export type { InvariantCheck };

/** Gateway rejected the request before policy or executor could act. */
const blockedBeforePolicy: InvariantCheck = (o) => requireInvariants(o, { executorCalls: 0, policyCalls: 0 });

/** Policy RAN (and denied); the executor never did. */
const deniedByPolicy: InvariantCheck = (o) => allOf(requireInvariants(o, { executorCalls: 0 }), requireAtLeast(o, 'policyCalls', 1));

/** Credential/status gate stopped the request: neither policy nor executor ran, and the credential stage is the typed cause. */
const stoppedAtCredentialStage: InvariantCheck = (o) =>
  requireInvariants(o, { executorCalls: 0, policyCalls: 0, credentialStage: 'FAIL' });

/** Resolver refused a bad did:web response: nothing was cached and the same transport DOES serve a good document. */
const didDocumentRefused: InvariantCheck = (o) => {
  const base = requireInvariants(o, { controlResolves: true, notCached: true });
  const err = (o.invariants as Record<string, unknown>).resolutionError;
  return allOf(base, typeof err === 'string' && err.length > 0 ? { ok: true } : { ok: false, detail: `resolutionError must be a typed DID-Core error, got ${JSON.stringify(err)}` });
};

/** SSRF guard refused before any connect attempt and the same transport DOES connect to a public address. */
const ssrfBlockedBeforeConnect: InvariantCheck = (o) =>
  requireInvariants(o, { blockedPreConnect: true, connectAttempts: 0, controlPublicAddressConnects: true });

/**
 * Tampering is caught on a history that verified cleanly beforehand (chain + signed checkpoint intact, and the
 * production consumer — TrustProfileService — accepts it), so the detection is caused by the mutation alone.
 */
const auditTamperDetected = (extra: Record<string, unknown>): InvariantCheck => (o) =>
  requireInvariants(o, { controlIntact: true, controlConsumerHistoryVerified: true, ...extra });

export const INVARIANT_CHECKS: Record<string, InvariantCheck> = {
  'IDENTITY-001': (o) => {
    const hist = (o.invariants as Record<string, { allow?: number; deny?: number } | undefined>).victimHistoryDecisions;
    return allOf(
      requireInvariants(o, { policyCalls: 0, executorCalls: 0, victimReceiptsAdded: 0 }),
      hist !== undefined && hist.allow === 0 && hist.deny === 0
        ? { ok: true }
        : { ok: false, detail: `victim decision history must be untouched, got ${JSON.stringify(hist)}` },
    );
  },
  'IDENTITY-002': blockedBeforePolicy,
  'IDENTITY-003': blockedBeforePolicy,
  'IDENTITY-004': (o) => requireInvariants(o, { positiveControlAuthorized: true, executorCalls: 0 }),
  'CREDENTIAL-001': blockedBeforePolicy,
  'CREDENTIAL-002': blockedBeforePolicy,
  'CREDENTIAL-003': blockedBeforePolicy,
  'CREDENTIAL-004': blockedBeforePolicy,
  'CREDENTIAL-005': blockedBeforePolicy,
  'CREDENTIAL-006': blockedBeforePolicy,
  // The showcase: policy RAN (correctly denied); executor never did.
  'AUTHORITY-001': deniedByPolicy,
  'AUTHORITY-002': deniedByPolicy,
  'AUTHORITY-003': deniedByPolicy,
  'AUTHORITY-004': deniedByPolicy,
  // Delegation walker, exercised directly (the gateway accepts a single link): rejects the attack, accepts the control.
  'AUTHORITY-005': (o) => requireInvariants(o, { walkerRejected: true, controlAttenuatedChainAccepted: true }),
  'AUTHORITY-006': (o) => requireInvariants(o, { walkerRejected: true, controlWithinBudgetChainAccepted: true }),
  'STATUS-001': blockedBeforePolicy,
  'STATUS-002': blockedBeforePolicy,
  'STATUS-003': blockedBeforePolicy,
  // The tampered / foreign / unreachable status list stops the request at the credential stage: no policy, no executor.
  'STATUS-004': stoppedAtCredentialStage,
  'STATUS-005': stoppedAtCredentialStage,
  'STATUS-006': stoppedAtCredentialStage,
  'REPLAY-001': (o) => requireInvariants(o, { firstAuthorized: true, secondDenied: true, successfulRefunds: 1, executorCalls: 1 }),
  'REPLAY-002': (o) =>
    requireInvariants(o, { authorizedCount: 1, deniedCount: 99, replayDeniedCount: 99, successfulRefunds: 1, executorCalls: 1 }),
  'REPLAY-003': blockedBeforePolicy,
  'REPLAY-004': (o) => requireInvariants(o, { attackerDenied: true, legitAuthorized: true, successfulRefunds: 1, executorCalls: 1 }),
  // Loader boundary: the genuine artifact loads (control), the corrupted ones never yield an engine.
  'POLICY-001': (o) =>
    requireInvariants(o, {
      controlLoadsEngine: true,
      flippedByteStage: 'hash_mismatch',
      flippedByteEngineObtainable: false,
      garbageWithMatchingDigestPassesDigestGate: true,
      garbageRefusedAtInstantiation: true,
      garbageEngineObtainable: false,
    }),
  'POLICY-002': (o) => requireInvariants(o, { controlLoadsEngine: true, refusalStage: 'hash_mismatch', engineObtainable: false }),
  'POLICY-003': (o) => requireInvariants(o, { executorCalls: 0 }),
  'POLICY-004': (o) => requireInvariants(o, { schemaRejectedScore: true, controlValidWithoutScore: true, engineDecisionEffect: 'DENY' }),
  // Interior mutation / deletion / reorder / forgery / splice: the chain verifier rejects, and so does the consumer.
  'AUDIT-001': auditTamperDetected({ chainValid: false, consumerHistoryVerified: false }),
  'AUDIT-002': auditTamperDetected({ chainValid: false, consumerHistoryVerified: false }),
  'AUDIT-003': auditTamperDetected({ chainValid: false, consumerHistoryVerified: false }),
  'AUDIT-004': auditTamperDetected({ chainValid: false, consumerHistoryVerified: false }),
  'AUDIT-005': auditTamperDetected({ chainValid: false, consumerHistoryVerified: false }),
  'AUDIT-006': auditTamperDetected({ chainValid: false, consumerHistoryVerified: false }),
  // A coherent rewrite passes the chain walk by construction; the signed checkpoint must still reject it.
  'AUDIT-007': auditTamperDetected({ rewrittenChainCoherent: true, checkpointRejected: true, consumerHistoryVerified: false }),
  'AUDIT-008': auditTamperDetected({ anchoredValid: false, consumerHistoryVerified: false }),
  // Forged checkpoint (wrong signer): the genuine one verifies under the same pin, the forgery does not.
  'AUDIT-009': (o) => requireInvariants(o, { controlIntact: true, controlPinnedGenuineVerifies: true, checkpointValid: false }),
  'ATTEST-001': (o) => requireInvariants(o, { victimAuthorityCount: 1, controlTrustedAttestations: 1, untrustedRejected: 1 }),
  'ATTEST-002': (o) =>
    requireInvariants(o, { policyDeniedOverLimit: true, victimTrustedAttestations: 0, sybilRejected: 100, victimAuthorityCount: 1 }),
  'ATTEST-003': (o) => requireInvariants(o, { executorCalls: 0, victimTrustedAttestations: 2 }),
  'ATTEST-004': (o) => requireInvariants(o, { trustedBefore: 1, victimTrustedAttestations: 0 }),
  'ATTEST-005': (o) => requireInvariants(o, { controlTrustedAttestations: 1, wrongSubjectRejected: 1 }),
  'DIDWEB-001': didDocumentRefused,
  'DIDWEB-002': ssrfBlockedBeforeConnect,
  'DIDWEB-003': ssrfBlockedBeforeConnect,
  'DIDWEB-004': ssrfBlockedBeforeConnect,
  'DIDWEB-005': ssrfBlockedBeforeConnect,
  'DIDWEB-006': didDocumentRefused,
  'DIDWEB-007': didDocumentRefused,
  'DIDWEB-008': didDocumentRefused,
  'DIDWEB-009': didDocumentRefused,
  'DIDWEB-010': (o) => requireInvariants(o, { firstFailed: true, secondSucceeded: true, secondResolvedToExpectedDid: true }),
  'DIDWEB-011': (o) => requireInvariants(o, { refetchedEveryResolve: true, keyRotated: true, keyAfterIsRotatedKey: true }),
  'INFRA-001': (o) => requireInvariants(o, { executorCalls: 0, policyAllowedThenAuditVeto: true }),
  'INFRA-002': (o) => requireInvariants(o, { decisionEffect: 'ALLOW', outcomeState: 'FAILED', decisionAndOutcomeChained: true }),
  'INFRA-003': (o) => requireInvariants(o, { outcome: 'EXECUTION_UNCERTAIN', executorCalls: 1, auditAppendAttempts: 2 }),
  'INFRA-004': (o) => requireInvariants(o, { executorCalls: 0 }),
  'INFRA-005': (o) => requireInvariants(o, { executorCalls: 0, policySkipped: true }),
};

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
