import type { AgentProof, ReasonCode } from '@agent-trust/schemas';
import { SCHEMA_ID_TRUST_EVALUATE_REQUEST, createValidator, type Validator } from '@agent-trust/schemas';
import { canonicalJson, sha256, utf8, base64urlEncode, verifyProof } from '@agent-trust/crypto';
import { parseDidUrl } from '@agent-trust/did';
import type { PublicJwk } from '@agent-trust/crypto';
import type { MultiDidResolver } from '@agent-trust/did';
import type { ReplayProtector } from '@agent-trust/replay';
import type { DidResolver } from '@agent-trust/did';
import { validateDelegationChain } from '@agent-trust/delegation';
import type { CredentialVerifier } from '@agent-trust/vc';
import type { PolicyEngine } from '@agent-trust/policy';
import { buildReceiptBody, resultDigestOf, type AuditLog, type ActionReceipt } from '@agent-trust/audit';

import type {
  ActionExecutor,
  GatewayResult,
  GatewayStages,
} from './types.js';
import { GATEWAY_HTU, taskContent } from './request.js';
import { buildDelegationChain, buildVerifiedFacts, selectCredentials } from './credentials.js';

/**
 * TrustGateway (Step 10) — the composition boundary. The agent/LLM runtime
 * PROPOSES; this pipeline alone decides whether the executor may run:
 *
 *   1. request schema (fail closed)
 *   2. PoP / DID / signature / htu / temporal  (crypto FIRST)
 *   3. replay claim                            (only AFTER PoP — Step 7
 *                                               ordering is preserved)
 *   4. credential verification (selection → verifier: schema, issuer,
 *      kid ownership, signature, trust, dates, status, quarantine)
 *   5. delegation chain / attenuation (effective authority only)
 *   6. VerifiedFacts (centralized builder)
 *   7. policy (embedded OPA Wasm)
 *   8. decision receipt (append-only; audit-before-side-effect)
 *   9. DENY → return, executor count stays 0
 *  10. ALLOW → idempotent executor
 *  11. execution-outcome receipt (separate chained receipt — never a
 *      mutation of the decision receipt)
 *  12. structured result
 *
 * RECEIPT ATTRIBUTION (pre-Step-10 review A): only AUTHENTICATED actors
 * enter the ActionReceipt history. Failures before PoP (spoofed DIDs,
 * bad signatures, malformed requests) and pre-policy failures (replay,
 * credential, chain) are gateway denials — security telemetry — and are
 * NOT attributed as the claimed actor's trust history. The receipt body
 * schema's pinned `security` facts make an unverified attribution
 * inexpressible. If unauthenticated attack history is ever needed, it
 * must distinguish claimedActorDid from verifiedActorDid; they are never
 * collapsed here.
 *
 * No layer can be skipped: the executor is reachable ONLY through
 * handleTask; nothing in the production/demo wiring exposes it directly.
 */
export interface TrustGatewayDeps {
  /** Must support resolveVerificationMethod (MultiDidResolver provides it). */
  didResolver: MultiDidResolver;
  verifier: CredentialVerifier;
  replayProtector: ReplayProtector;
  policyEngine: PolicyEngine;
  auditLog: AuditLog;
  executor: ActionExecutor;
  /** Audit stream for decision/outcome receipts. */
  streamId: string;
  /** htu bound into task proofs. Default GATEWAY_HTU. */
  htu?: string;
  /** Frozen clock (unix seconds) — determinism for tests/demo. */
  clock: () => number;
  validator?: Validator;
}

export class TrustGateway {
  readonly #deps: TrustGatewayDeps;
  readonly #validator: Validator;
  readonly #htu: string;

  constructor(deps: TrustGatewayDeps) {
    this.#deps = deps;
    this.#validator = deps.validator ?? createValidator();
    this.#htu = deps.htu ?? GATEWAY_HTU;
  }

  async handleTask(request: unknown): Promise<GatewayResult> {
    const stages: GatewayStages = {
      identity: 'NOT_RUN',
      replay: 'NOT_RUN',
      credential: 'NOT_RUN',
      authority: 'NOT_RUN',
      policy: 'NOT_RUN',
      audit: 'NOT_RUN',
      execution: 'NOT_RUN',
    };

    // ---- 1. request schema -------------------------------------------------
    if (!this.#validator.validate(SCHEMA_ID_TRUST_EVALUATE_REQUEST, request).valid) {
      return denied('REQUEST_MALFORMED', stages, 'request failed the task schema');
    }
    const task = request as {
      taskId: string;
      actor: string;
      audience: string;
      action: string;
      resource: string;
      parameters?: { amount?: number; currency?: string };
      nonce?: string;
      credentials: string[];
      proof: AgentProof;
    };

    // ---- 2. PoP / identity (crypto first; NO replay claim yet) -------------
    stages.identity = 'FAIL';
    const kidResolution = await this.#deps.didResolver.resolveVerificationMethod(task.proof.kid);
    if (!kidResolution.ok || !kidResolution.method.publicKeyJwk) {
      return denied('IDENTITY_PROOF_INVALID', stages, 'proof kid did not resolve to a verification method');
    }
    // The task content digest is recomputed from RECEIVED fields — a wire
    // mutation without re-signing fails here (Step 10V).
    const digest = base64urlEncode(sha256(utf8(canonicalJson(taskContent(task)))));
    const pop = verifyProof({
      proof: task.proof,
      publicJwk: kidResolution.method.publicKeyJwk as PublicJwk,
      htu: this.#htu,
      requestBodyDigest: digest,
      now: this.#deps.clock(),
    });
    if (!pop.valid) {
      return denied('IDENTITY_PROOF_INVALID', stages, `proof verification failed: ${pop.error}`);
    }
    // Identity binding (Step 10D): the proof's key must belong to the
    // claimed actor — no authenticating as did:evil while presenting
    // did:trusted's authority.
    if (parseDidUrl(task.proof.kid).did !== task.actor) {
      return denied('IDENTITY_PROOF_INVALID', stages, 'proof kid does not belong to the claimed actor DID');
    }
    stages.identity = 'PASS';

    // ---- 3. replay claim (AFTER PoP — poisoning impossible) ----------------
    const replayDecision = await this.#deps.replayProtector.verifyAndClaim({
      audience: this.#htu,
      kid: task.proof.kid,
      jti: task.proof.jti,
      iat: task.proof.iat,
      exp: task.proof.exp,
      now: this.#deps.clock(),
    });
    if (replayDecision.outcome !== 'claimed') {
      stages.replay = 'FAIL';
      return denied(replayDecision.reasonCode, stages, 'replay gate denied');
    }
    stages.replay = 'PASS';

    // ---- 4. credential verification ----------------------------------------
    stages.credential = 'FAIL';
    const selection = selectCredentials({ credentials: task.credentials });
    if (!selection.ok) {
      return denied(selection.reasonCodes[0]!, stages, selection.detail);
    }

    interface VerifiedDelegation {
      issuerDid: string;
      subjectDid: string;
      nbf: number;
      exp?: number;
      authority: import('@agent-trust/schemas').Authority;
      types: string[];
    }
    const verified: VerifiedDelegation[] = [];
    for (const jws of selection.selection.delegationJwsList) {
      // First link binds to the authenticated actor; later links bind to
      // their issuer relationship via chain construction below.
      const expectedSubject =
        verified.length === 0 ? task.actor : undefined;
      const result = await this.#deps.verifier.verify(jws, {
        now: this.#deps.clock(),
        ...(expectedSubject !== undefined ? { expectedSubject } : {}),
        expectedType: 'AgentDelegationCredential',
      });
      if (!result.valid) {
        return denied(result.reasonCodes[0], stages, 'delegation credential verification failed');
      }
      const authority = result.facts.authority;
      if (authority === undefined) {
        return denied('VC_SCHEMA_INVALID', stages, 'delegation credential carries no authority');
      }
      verified.push({
        issuerDid: result.facts.issuerDid,
        subjectDid: result.facts.subjectDid,
        nbf: result.facts.validFrom,
        exp: result.facts.validUntil,
        authority,
        types: [result.facts.credentialType],
      });
    }
    stages.credential = 'PASS';

    // ---- 5. delegation chain / attenuation ---------------------------------
    stages.authority = 'FAIL';
    const chain = buildDelegationChain({ verifiedDelegations: verified, actorDid: task.actor });
    if (!chain.ok) {
      return denied(chain.reasonCodes[0]!, stages, chain.detail);
    }
    const attenuation = validateDelegationChain(chain.parties);
    if (!attenuation.ok) {
      return denied(attenuation.reasonCodes[0]!, stages, 'delegation chain attenuation violated');
    }
    stages.authority = 'PASS';

    // ---- 6. VerifiedFacts (centralized builder) ----------------------------
    const facts = buildVerifiedFacts({
      actorDid: task.actor,
      request: {
        action: task.action,
        resource: task.resource,
        audience: task.audience,
        parameters: task.parameters,
      },
      issuerDid: verified[0]!.issuerDid,
      credentialTypes: verified[0]!.types,
      effectiveAuthority: chain.effectiveAuthority.authority,
      now: this.#deps.clock(),
    });

    // ---- 7. policy ----------------------------------------------------------
    // Fail closed (Step 10X): an engine outage is a denial, never an escape.
    let decision: Awaited<ReturnType<PolicyEngine['evaluate']>>;
    try {
      decision = await this.#deps.policyEngine.evaluate(facts);
    } catch {
      stages.policy = 'DENY';
      const failBody = buildReceiptBody({
        receiptId: `rcpt_dec_${task.taskId}`,
        recordedAt: canonicalNow(this.#deps.clock()),
        actor: { did: task.actor },
        request: {
          action: task.action,
          resource: task.resource,
          audience: task.audience,
          parameters: task.parameters,
        },
        security: {
          proofVerified: true,
          credentialVerified: true,
          issuerTrusted: true,
          credentialActive: true,
          quarantined: false,
          replayChecked: true,
        },
        decision: {
          effect: 'DENY',
          reasonCodes: ['POLICY_EVALUATION_ERROR'],
          policy: { id: 'unknown', version: 'unknown', hash: 'unknown' },
        },
      });
      let receiptId: string | undefined;
      try {
        const failReceipt = await this.#deps.auditLog.append(this.#deps.streamId, failBody);
        receiptId = failReceipt.body.receiptId;
      } catch {
        // Audit also down: the denial stands, only the receipt is missing.
      }
      return {
        taskId: task.taskId,
        outcome: 'DENIED',
        effect: 'DENY',
        reasonCodes: ['POLICY_EVALUATION_ERROR'],
        stages,
        ...(receiptId !== undefined ? { decisionReceiptId: receiptId } : {}),
      };
    }
    stages.policy = decision.effect === 'ALLOW' ? 'ALLOW' : 'DENY';

    // ---- 8. decision receipt (append-only; audit-before-side-effect) -------
    const decisionBody = buildReceiptBody({
      receiptId: `rcpt_dec_${task.taskId}`,
      recordedAt: canonicalNow(this.#deps.clock()),
      actor: { did: task.actor },
      request: {
        action: task.action,
        resource: task.resource,
        audience: task.audience,
        parameters: task.parameters,
      },
      security: {
        proofVerified: true,
        credentialVerified: true,
        issuerTrusted: true,
        credentialActive: true,
        quarantined: false,
        replayChecked: true,
      },
      decision: {
        effect: decision.effect,
        reasonCodes: decision.reasonCodes,
        policy: decision.policy,
      },
    });
    let decisionReceipt: ActionReceipt;
    try {
      decisionReceipt = await this.#deps.auditLog.append(this.#deps.streamId, decisionBody);
      stages.audit = 'PASS';
    } catch {
      stages.audit = 'FAIL';
      // Audit-before-side-effect (Step 10K): the executor must NEVER run
      // without a durable decision receipt — even after policy ALLOW.
      if (decision.effect === 'ALLOW') {
        return {
          taskId: task.taskId,
          outcome: 'DENIED',
          effect: 'DENY',
          reasonCodes: ['AUDIT_LOG_UNAVAILABLE'],
          stages,
        };
      }
      // For DENY decisions the security outcome stands; the missing receipt
      // is marked in the stages.
      return {
        taskId: task.taskId,
        outcome: 'DENIED',
        effect: 'DENY',
        reasonCodes: decision.reasonCodes,
        stages,
      };
    }

    // ---- 9. DENY path: no executor call -------------------------------------
    if (decision.effect !== 'ALLOW') {
      return {
        taskId: task.taskId,
        outcome: 'DENIED',
        effect: 'DENY',
        reasonCodes: decision.reasonCodes,
        stages,
        decisionReceiptId: decisionReceipt.body.receiptId,
      };
    }

    // ---- 10. idempotent executor --------------------------------------------
    let execution: { state: 'SUCCEEDED' | 'FAILED'; result?: unknown; detail?: string };
    try {
      const result = await this.#deps.executor.execute({
        taskId: task.taskId,
        actorDid: task.actor,
        audienceDid: task.audience,
        action: task.action,
        resource: task.resource,
        parameters: task.parameters,
        decisionReceiptId: decisionReceipt.body.receiptId,
      });
      execution = { state: result.state, ...(result.result !== undefined ? { result: result.result } : {}), ...(result.detail !== undefined ? { detail: result.detail } : {}) };
    } catch (e) {
      execution = { state: 'FAILED', detail: String(e) };
    }
    stages.execution = execution.state;

    // ---- 11. execution-outcome receipt (separate chained event) -------------
    const outcomeBody = buildReceiptBody({
      receiptId: `rcpt_out_${task.taskId}`,
      recordedAt: canonicalNow(this.#deps.clock()),
      actor: { did: task.actor },
      request: {
        action: task.action,
        resource: task.resource,
        audience: task.audience,
        parameters: task.parameters,
      },
      security: {
        proofVerified: true,
        credentialVerified: true,
        issuerTrusted: true,
        credentialActive: true,
        quarantined: false,
        replayChecked: true,
      },
      decision: {
        effect: decision.effect,
        reasonCodes: decision.reasonCodes,
        policy: decision.policy,
      },
      execution: {
        state: execution.state,
        ...(execution.result !== undefined ? { resultDigest: resultDigestOf(execution.result) } : {}),
      },
      correlation: {
        taskId: task.taskId,
        decisionReceiptId: decisionReceipt.body.receiptId,
      },
    });
    let executionReceiptId: string | undefined;
    try {
      const outcomeReceipt = await this.#deps.auditLog.append(this.#deps.streamId, outcomeBody);
      executionReceiptId = outcomeReceipt.body.receiptId;
    } catch {
      // DISTRIBUTED FAILURE WINDOW (honest P0 semantics): the side effect
      // ran but the outcome receipt could not be persisted. We do NOT
      // retry the side effect blindly. The result is deterministic:
      // execution outcome is known to this process, but the audit trail
      // is incomplete and needs reconciliation.
      stages.audit = 'FAIL';
      return {
        taskId: task.taskId,
        outcome: 'EXECUTION_UNCERTAIN',
        effect: 'ALLOW',
        reasonCodes: ['AUDIT_OUTCOME_UNRECORDED'],
        stages,
        decisionReceiptId: decisionReceipt.body.receiptId,
      };
    }

    if (execution.state === 'FAILED') {
      return {
        taskId: task.taskId,
        outcome: 'EXECUTION_FAILED',
        effect: 'ALLOW',
        reasonCodes: decision.reasonCodes,
        stages,
        decisionReceiptId: decisionReceipt.body.receiptId,
        executionReceiptId,
      };
    }

    // ---- 12. structured result ----------------------------------------------
    return {
      taskId: task.taskId,
      outcome: 'AUTHORIZED',
      effect: 'ALLOW',
      reasonCodes: decision.reasonCodes,
      stages,
      decisionReceiptId: decisionReceipt.body.receiptId,
      executionReceiptId,
    };
  }
}

function denied(
  reasonCode: ReasonCode,
  stages: GatewayStages,
  detail: string,
): GatewayResult {
  void detail; // deterministic diagnostics live in reason codes, not prose
  return {
    taskId: '',
    outcome: 'DENIED',
    effect: 'DENY',
    reasonCodes: [reasonCode],
    stages,
  };
}

function canonicalNow(unix: number): string {
  return new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export type { AgentProof, ReasonCode };
