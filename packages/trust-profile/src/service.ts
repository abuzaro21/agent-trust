import { canonicalJson, sha256Hex } from '@agent-trust/crypto';
import type { DidResolver } from '@agent-trust/did';
import type { Authority, ReasonCode, Validator } from '@agent-trust/schemas';
import { SCHEMA_ID_TRUST_PROFILE, createValidator } from '@agent-trust/schemas';
import {
  type CredentialClaims,
  type CredentialType,
  CredentialVerifier,
} from '@agent-trust/vc';
import {
  type AttestationStore,
  type AgentCredentialStore,
  type AttestationTrustPolicy,
  type ProfileContext,
  type TrustProfile,
  asCredentialType,
} from './types.js';

import {
  type ActionReceipt,
  type AuditLog,
  type SignedAuditCheckpoint,
  verifyAuditAgainstCheckpoint,
  verifyAuditChain,
  verifyCheckpointSignature,
} from '@agent-trust/audit';

function nowIso(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function emptyActionHistory(): NonNullable<TrustProfile['history']['byAction'][string]> {
  return {
    decisions: { allow: 0, deny: 0 },
    execution: { succeeded: 0, failed: 0, uncertain: 0 },
    reasonCodes: {},
  };
}

/**
 * TrustProfileService (Step 11B) — builds a CONTEXTUAL, EVIDENCE-BACKED
 * read model. The profile is a REPORT about verified evidence; it is never
 * an input to the policy engine and never bypasses it. Invariants:
 *
 *  - EVERY presented credential (delegation or attestation) is verified
 *    through the FULL CredentialVerifier pipeline — no lightweight path.
 *  - Attestation trust is scoped by issuer + attestation TYPE via
 *    AttestationTrustPolicy. ATTESTATION_TYPE_UNSUPPORTED for an unlisted
 *    (issuer, type) pair.
 *  - Count ≠ trust: N rejected attestations contribute nothing (Sybil
 *    resistance is structural — no aggregate number exists to inflate).
 *  - History comes ONLY from the verified audit chain + checkpoint. When
 *    integrity fails, ONLY the history section fails closed
 *    (history.integrity.verified=false, byAction empty) — identity,
 *    authority, and attestations remain independent evidence sections
 *    (TRUST_PROFILE_HISTORY_INVALID is recorded in the detail).
 *  - The output must validate against SCHEMA_ID_TRUST_PROFILE: score
 *    fields are structurally inexpressible.
 */
export interface TrustProfileDeps {
  didResolver: DidResolver;
  verifier: CredentialVerifier;
  attestationStore: AttestationStore;
  agentCredentialStore: AgentCredentialStore;
  attestationTrust: AttestationTrustPolicy;
  auditLog: AuditLog;
  /** Signed checkpoint binding the audit stream — history's trust root. */
  auditCheckpoint: SignedAuditCheckpoint;
  /** Stream the gateway wrote decision/outcome receipts to. */
  auditStreamId: string;
  /** DID pinned as the ONLY acceptable checkpoint signer. */
  checkpointSignerDid?: string;
  validator?: Validator;
}

export interface BuildProfileOptions {
  /** Frozen clock (unix seconds) — determinism for tests/demo. */
  now: number;
  context?: ProfileContext;
}

export class TrustProfileService {
  readonly #deps: TrustProfileDeps;
  readonly #validator: Validator;

  constructor(deps: TrustProfileDeps) {
    this.#deps = deps;
    this.#validator = deps.validator ?? createValidator();
  }

  async build(agentDid: string, opts: BuildProfileOptions): Promise<TrustProfile> {
    const { now } = opts;

    // ---- 1. identity — evidence, not assertion ----------------------------
    let resolved = false;
    let verificationMethodCount = 0;
    try {
      const resolution = await this.#deps.didResolver.resolve(agentDid);
      if (resolution.didDocument !== null && resolution.didResolutionMetadata.error === undefined) {
        resolved = true;
        verificationMethodCount = (resolution.didDocument.verificationMethod ?? []).length;
      }
    } catch {
      resolved = false;
    }

    // ---- 2. authority — from VERIFIED delegation credentials only ---------
    const authorityActive: TrustProfile['authority']['active'] = [];
    const credentialsState = { active: 0, suspended: 0, revoked: 0 };
    const context = opts.context;

    const delegationJwsList = await this.#deps.agentCredentialStore.listForSubject(agentDid);
    for (const jws of delegationJwsList) {
      const result = await this.#deps.verifier.verify(jws, { now, expectedSubject: agentDid });
      if (!result.valid) {
        // Status denials are reportable credential states, not noise.
        if (result.reasonCodes[0] === 'CREDENTIAL_REVOKED') credentialsState.revoked += 1;
        else if (result.reasonCodes[0] === 'CREDENTIAL_SUSPENDED') credentialsState.suspended += 1;
        continue; // unverifiable authority is simply absent — never approximated
      }
      const authority: Authority | undefined = result.facts.authority;
      if (authority === undefined) continue;
      credentialsState.active += 1;
      authorityActive.push({
        credentialId: result.facts.credentialId,
        issuer: result.facts.issuerDid,
        actions: [...authority.actions],
        resources: [...authority.resources],
        ...(authority.audience !== undefined ? { audience: [...authority.audience] } : {}),
        ...(authority.limits !== undefined ? { limits: { ...authority.limits } } : {}),
        ...(result.facts.validUntil !== undefined ? { validUntil: nowIso(result.facts.validUntil) } : {}),
        evidenceDigest: sha256Hex(canonicalJson(authority)),
        applicable: this.#isApplicable(authority, context),
      });
    }

    // ---- 3. attestations — full pipeline + TYPED issuer trust -------------
    const attestationsTrusted: TrustProfile['attestations']['trusted'] = [];
    const attestationsRejected: TrustProfile['attestations']['rejected'] = [];

    const attestationJwsList = await this.#deps.attestationStore.listForSubject(agentDid);
    for (const jws of attestationJwsList) {
      const result = await this.#deps.verifier.verify(jws, { now, expectedSubject: agentDid });
      if (!result.valid) {
        if (result.reasonCodes[0] === 'CREDENTIAL_REVOKED') credentialsState.revoked += 1;
        else if (result.reasonCodes[0] === 'CREDENTIAL_SUSPENDED') credentialsState.suspended += 1;
        attestationsRejected.push({ reasonCodes: [...result.reasonCodes] });
        continue;
      }
      const facts = result.facts;
      const attestation = facts.attestation;
      const supported: CredentialType | null = asCredentialType(facts.credentialType);
      if (attestation === undefined || supported === null) {
        attestationsRejected.push({
          credentialId: facts.credentialId,
          issuer: facts.issuerDid,
          reasonCodes: ['ATTESTATION_TYPE_UNSUPPORTED'],
        });
        continue;
      }
      // Trust is scoped by ISSUER + TYPE: trusting AcmeAudit for
      // SECURITY_REVIEW does not trust its CAPABILITY_ENDORSEMENTs.
      if (!(await this.#deps.attestationTrust.isTrusted(facts.issuerDid, attestation.type))) {
        attestationsRejected.push({
          credentialId: facts.credentialId,
          issuer: facts.issuerDid,
          reasonCodes: ['ATTESTATION_TYPE_UNSUPPORTED'],
        });
        continue;
      }
      credentialsState.active += 1;
      attestationsTrusted.push({
        credentialId: facts.credentialId,
        issuer: facts.issuerDid,
        type: attestation.type,
        statement: attestation.statement,
        domain: attestation.domain,
        ...(facts.validUntil !== undefined ? { validUntil: nowIso(facts.validUntil) } : {}),
      });
    }

    // ---- 4. history — verified audit chain + checkpoint ONLY --------------
    const history = await this.#buildHistory(agentDid);

    const profile: TrustProfile = {
      agent: { did: agentDid },
      generatedAt: nowIso(now),
      ...(context !== undefined ? { context } : {}),
      identity: {
        resolved,
        ...(verificationMethodCount > 0 ? { verificationMethodCount } : {}),
      },
      authority: { active: authorityActive },
      credentials: credentialsState,
      attestations: { trusted: attestationsTrusted, rejected: attestationsRejected },
      history,
    };

    const validation = this.#validator.validate(SCHEMA_ID_TRUST_PROFILE, profile);
    if (!validation.valid) {
      throw new Error('TRUST_PROFILE_HISTORY_INVALID: generated profile failed its own schema');
    }
    return profile;
  }

  /**
   * Context relevance is PRESENTATION (does this evidence speak to the
   * question being asked), never authorization. An authority entry is
   * applicable when the context action matches one of its actions AND the
   * context resource falls under one of its resource patterns (the same
   * prefix/equality semantics the policy engine uses).
   */
  #isApplicable(authority: Authority, context: ProfileContext | undefined): boolean {
    if (context === undefined) return true;
    if (context.action !== undefined && !authority.actions.includes(context.action)) return false;
    if (context.resource !== undefined) {
      const covered = authority.resources.some(
        (r) => r === context.resource || context.resource!.startsWith(`${r}:`),
      );
      if (!covered) return false;
    }
    return true;
  }

  /**
   * History aggregation (Step 11H). Two independent integrity gates, both
   * of which must pass: (a) the hash chain verifies receipt-by-receipt;
   * (b) the chain head matches the SIGNED checkpoint (full-database-rewrite
   * and truncation anchors). On any failure the ENTIRE history section
   * fails closed — a profile never summarizes an unverifiable history.
   *
   * Privacy: aggregation counts occurrences; receipts already store only
   * identifiers/digests, and nothing from receipt bodies beyond action
   * names, effect, reason codes, and timestamps enters the profile.
   */
  async #buildHistory(agentDid: string): Promise<TrustProfile['history']> {
    const { auditLog, auditStreamId, auditCheckpoint, checkpointSignerDid } = this.#deps;

    const failClosed = (detail: string): TrustProfile['history'] => ({
      integrity: { verified: false, detail },
      byAction: {},
    });

    let receipts: ActionReceipt[];
    try {
      receipts = await auditLog.readStream(auditStreamId);
    } catch {
      return failClosed('audit log unavailable');
    }

    const chain = verifyAuditChain(auditStreamId, receipts, this.#validator);
    if (!chain.valid) {
      return failClosed('audit chain failed verification');
    }

    const checkpointVerified = await verifyCheckpointSignature({
      checkpoint: auditCheckpoint,
      didResolver: this.#deps.didResolver,
      validator: this.#validator,
      opts: checkpointSignerDid !== undefined ? { expectedSignerDid: checkpointSignerDid } : {},
    });
    const against = verifyAuditAgainstCheckpoint({
      streamId: auditStreamId,
      receipts,
      checkpoint: auditCheckpoint,
      checkpointVerified,
    });
    if (!against.valid) {
      return failClosed('audit checkpoint does not anchor the chain');
    }

    const byAction: TrustProfile['history']['byAction'] = {};
    // Outcome events (correlation.decisionReceiptId present) reference the
    // decision they resolve; an ALLOW decision with NO outcome event is the
    // honest distributed-failure window (Step 10U) — counted as uncertain.
    const resolvedDecisionIds = new Set<string>();
    const decisionsAwaitingOutcome: { action: string; receiptId: string }[] = [];

    for (const receipt of receipts) {
      const body = receipt.body;
      // Attribution: the receipt's pinned security facts guarantee the
      // actor was authenticated at decision time — spoofed actors never
      // produced receipts (the gateway never writes them).
      if (body.actor.did !== agentDid) continue;

      const entry = byAction[body.request.action] ?? emptyActionHistory();
      const outcomeReceiptId = body.correlation?.decisionReceiptId;
      if (outcomeReceiptId !== undefined) {
        resolvedDecisionIds.add(outcomeReceiptId);
        const execution = body.execution;
        if (execution !== undefined) {
          if (execution.state === 'SUCCEEDED') entry.execution.succeeded += 1;
          else if (execution.state === 'FAILED') entry.execution.failed += 1;
        }
      } else {
        // Decision event (no correlation block): count the effect.
        if (body.decision.effect === 'ALLOW') {
          entry.decisions.allow += 1;
          decisionsAwaitingOutcome.push({ action: body.request.action, receiptId: body.receiptId });
        } else {
          // DENY and REQUIRE_APPROVAL are both non-executed decisions.
          entry.decisions.deny += 1;
          for (const code of body.decision.reasonCodes) {
            entry.reasonCodes[code] = (entry.reasonCodes[code] ?? 0) + 1;
          }
        }
      }
      entry.lastObservedAt = body.recordedAt;
      byAction[body.request.action] = entry;
    }

    for (const d of decisionsAwaitingOutcome) {
      if (!resolvedDecisionIds.has(d.receiptId)) {
        (byAction[d.action] ?? emptyActionHistory()).execution.uncertain += 1;
      }
    }

    return {
      integrity: {
        verified: true,
        verifiedThroughSequence: against.sequence,
        checkpointId: auditCheckpoint.payload.checkpointId,
        checkpointHeadHash: against.headHash,
      },
      byAction,
    };
  }
}
