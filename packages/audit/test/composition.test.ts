import { beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';

import { LocalSigner, withDid, createProof, requestBodyDigestOf } from '@agent-trust/crypto';
import { MultiDidResolver, InMemoryDidResolver, didDocumentForJwk } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import { BitstringStatusChecker, InMemoryAgentQuarantineStore, InMemoryStatusListStore, StatusListManager } from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector, verifyProofWithReplay } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine, type OpaWasmPolicyEngine } from '@agent-trust/policy';

import { SECURITY_OK } from './fixture.js';
import {
  AuditCheckpointService,
  InMemoryAuditLog,
  buildReceiptBody,
  verifyAuditAgainstCheckpoint,
  verifyAuditChain,
  verifyCheckpointSignature,
} from '../src/index.js';
import type { SignedAuditCheckpoint } from '../src/types.js';

/**
 * 9W — thin composition: the full trust pipeline of Step 8 extended with
 * audit. Real keys, real VCs, real status lists, real replay, real Wasm
 * policy → ALLOW receipt (seq 1) → DENY receipt (seq 2) → signed
 * checkpoint → chain + checkpoint verification.
 */

const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');

const NOW_UNIX = 1_757_944_800; // 2026-09-15T12:00:00Z
const NOW = '2026-09-15T12:00:00Z';
const ORG_DID = 'did:web:acme.example:org';
const SUPPORT_AGENT_DID = 'did:web:agents.acme.example:support-1';
const REFUND_AGENT_DID = 'did:web:payments.example:refund-agent';
const ANCHOR_DID = 'did:web:audit.acme.example:anchor';
const STREAM = 'acme-demo';
const HTU = 'https://gateway.example/v1/trust/evaluate';

const canonicalNow = (unix: number): string =>
  new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

describe('trust pipeline → receipts → checkpoint (9W)', () => {
  let engine: OpaWasmPolicyEngine;
  let log: InMemoryAuditLog;
  let checkpoint: SignedAuditCheckpoint;
  let deps: Awaited<ReturnType<typeof buildWorld>>;

  beforeAll(async () => {
    const policyResult = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
    if (!policyResult.ok) throw new Error(`policy failed to load: ${policyResult.detail}`);
    engine = policyResult.engine as OpaWasmPolicyEngine;
    deps = await buildWorld();
  });

  async function decide(amount: number): Promise<import('@agent-trust/policy').PolicyDecision> {
    const body = {
      actor: SUPPORT_AGENT_DID,
      action: 'refund:create',
      resource: 'order:ORD-918',
      parameters: { amount, currency: 'SAR' },
    };
    const { proof, requestBodyDigest } = await deps.supportAgent.createProofBundle(body, HTU);
    const multi = new MultiDidResolver([deps.resolver]);
    const resolved = await multi.resolveVerificationMethod(proof.kid);
    if (!resolved.ok || !resolved.method.publicKeyJwk) throw new Error('kid resolution failed');
    const replay = await verifyProofWithReplay(
      { proof, publicJwk: resolved.method.publicKeyJwk, htu: HTU, requestBodyDigest, now: NOW_UNIX },
      deps.replay.protector,
    );
    if (!replay.ok) throw new Error(`replay gate: ${JSON.stringify(replay)}`);
    const vc = await deps.verifier.verify(deps.delegationJws, {
      now: NOW_UNIX,
      expectedSubject: SUPPORT_AGENT_DID,
      expectedType: 'AgentDelegationCredential',
    });
    if (!vc.valid) throw new Error(`credential gate: ${JSON.stringify(vc)}`);
    return engine.evaluate({
      actor: { did: SUPPORT_AGENT_DID, controller: ORG_DID },
      request: {
        action: 'refund:create',
        resource: 'order:ORD-918',
        audience: REFUND_AGENT_DID,
        parameters: { amount, currency: 'SAR' },
      },
      identity: { proofVerified: true },
      credential: { verified: true, issuer: ORG_DID, issuerTrusted: true, types: ['VerifiableCredential', 'AgentDelegationCredential'] },
      authority: {
        actions: vc.facts.authority!.actions,
        resources: vc.facts.authority!.resources,
        audience: vc.facts.authority!.audience,
        limits: vc.facts.authority!.limits,
      },
      status: { credentialActive: true, quarantined: false },
      replay: { checked: true, claimed: true },
      context: { now: canonicalNow(NOW_UNIX) },
    });
  }

  it('ALLOW 120 → receipt seq 1; DENY 5000 → receipt seq 2; checkpoint verifies both (9T/9W)', async () => {
    log = new InMemoryAuditLog();
    const anchor = new AuditCheckpointService(deps.anchorSigner);

    // Decision 1 — the canonical ALLOW scenario.
    const allow = await decide(120);
    expect(allow.effect).toBe('ALLOW');
    const allowBody = buildReceiptBody({
      receiptId: 'rcpt_comp_allow_01',
      recordedAt: NOW,
      actor: { did: SUPPORT_AGENT_DID, controller: ORG_DID },
      request: { action: 'refund:create', resource: 'order:ORD-918', audience: REFUND_AGENT_DID, parameters: { amount: 120, currency: 'SAR' } },
      authority: { credentialId: deps.delegationCredentialId, issuer: ORG_DID },
      security: SECURITY_OK,
      decision: { effect: allow.effect as never, reasonCodes: allow.reasonCodes as never, policy: allow.policy as never },
      execution: { state: 'NOT_EXECUTED' },
    });
    const allowReceipt = await log.append(STREAM, allowBody);
    expect(allowReceipt.body.sequence).toBe(1);

    // Decision 2 — the canonical DENY scenario, same legitimate agent.
    const deny = await decide(5000);
    expect(deny.effect).toBe('DENY');
    expect(deny.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    const denyBody = buildReceiptBody({
      receiptId: 'rcpt_comp_deny_01',
      recordedAt: NOW,
      actor: { did: SUPPORT_AGENT_DID, controller: ORG_DID },
      request: { action: 'refund:create', resource: 'order:ORD-918', audience: REFUND_AGENT_DID, parameters: { amount: 5000, currency: 'SAR' } },
      authority: { credentialId: deps.delegationCredentialId, issuer: ORG_DID },
      security: SECURITY_OK,
      decision: { effect: deny.effect as never, reasonCodes: deny.reasonCodes as never, policy: deny.policy as never },
    });
    const denyReceipt = await log.append(STREAM, denyBody);
    expect(denyReceipt.body.sequence).toBe(2);
    expect(denyReceipt.previousHash).toBe(allowReceipt.eventHash);

    // The history: ALLOW then DENY, cryptographically chained.
    const chain = await log.readStream(STREAM);
    expect(chain.map((r) => r.body.decision.effect)).toEqual(['ALLOW', 'DENY']);
    expect(verifyAuditChain(STREAM, chain).valid).toBe(true);

    // Anchor the head and verify independently.
    checkpoint = await anchor.issue({ checkpointId: 'ckpt_comp_0001', streamId: STREAM, receipts: chain, issuedAt: NOW });
    const cpVerified = await verifyCheckpointSignature({
      checkpoint,
      didResolver: deps.resolver,
      opts: { expectedSignerDid: ANCHOR_DID, now: NOW_UNIX },
    });
    expect(cpVerified.valid).toBe(true);
    expect(
      verifyAuditAgainstCheckpoint({ streamId: STREAM, receipts: chain, checkpoint, checkpointVerified: cpVerified }).valid,
    ).toBe(true);
  });
});

/** Real trust-stack fixture (mirrors packages/policy composition). */
async function buildWorld() {
  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const supportSigner = withDid(LocalSigner.generate(), SUPPORT_AGENT_DID);
  const anchorSigner = withDid(LocalSigner.generate(), ANCHOR_DID);
  const resolver = new InMemoryDidResolver([
    didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
    didDocumentForJwk(SUPPORT_AGENT_DID, await supportSigner.publicKey()),
    didDocumentForJwk(ANCHOR_DID, await anchorSigner.publicKey()),
  ]);
  const statusStore = new InMemoryStatusListStore();
  const manager = new StatusListManager(statusStore, { clock: () => NOW_UNIX });
  const REV_LIST = 'https://acme.example/status/rev/1';
  await manager.createList({ id: REV_LIST, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 64 });
  const delegationIndex = await manager.assignIndex(REV_LIST);
  const issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  const { jws: delegationJws } = await issuer.issueDelegation({
    subjectDid: SUPPORT_AGENT_DID,
    authority: {
      actions: ['refund:create'],
      resources: ['order:*'],
      audience: [REFUND_AGENT_DID],
      limits: { amount: 500, currency: 'SAR' },
      delegationDepth: 0,
    },
    validFrom: NOW_UNIX - 3600,
    validUntil: NOW_UNIX + 86_400,
    credentialStatus: {
      id: `${REV_LIST}#${delegationIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(delegationIndex),
      statusListCredential: REV_LIST,
    },
  });
  const trustStore = new InMemoryIssuerTrustStore().trust(ORG_DID, 'AgentDelegationCredential');
  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore,
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
    quarantineStore: new InMemoryAgentQuarantineStore(),
  });
  const replayStore = new InMemoryReplayStore({ clock: () => NOW_UNIX });
  const supportAgent = {
    signer: supportSigner,
    async createProofBundle(body: unknown, htu: string) {
      const digest = requestBodyDigestOf(body);
      const proof = await createProof(supportSigner, {
        htu,
        requestBodyDigest: digest,
        jti: `jti-${Math.random().toString(36).slice(2, 14)}${Math.random().toString(36).slice(2, 14)}`,
        iat: NOW_UNIX - 5,
        exp: NOW_UNIX + 300,
      });
      return { proof, requestBodyDigest: digest };
    },
  };
  return {
    orgSigner,
    supportAgent,
    anchorSigner,
    resolver,
    verifier,
    replay: { store: replayStore, protector: new ReplayProtector(replayStore) },
    delegationJws,
    delegationCredentialId: 'vc_comp_fixture_01',
  };
}
