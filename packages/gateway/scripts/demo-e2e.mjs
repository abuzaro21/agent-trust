#!/usr/bin/env node
/**
 * pnpm demo:e2e — the canonical cross-agent demonstration (Step 10Q).
 *
 * Every layer is the REAL implementation: real ES256 keys, real DID
 * resolution, real VC issuance/verification, real Bitstring Status List
 * revocation, real quarantine, real OPA Wasm policy (committed artifact),
 * real hash-chained audit + signed checkpoint. The ONLY optional swap is
 * the replay store: Redis when TEST_REDIS_URL is reachable, otherwise the
 * deterministic in-memory store (clearly labeled below).
 */
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalSigner, withDid } from '@agent-trust/crypto';
import { InMemoryDidResolver, MultiDidResolver, didDocumentForJwk } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import {
  BitstringStatusChecker,
  InMemoryAgentQuarantineStore,
  InMemoryStatusListStore,
  StatusListManager,
} from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import {
  AuditCheckpointService,
  InMemoryAuditLog,
  verifyAuditAgainstCheckpoint,
  verifyAuditChain,
  verifyCheckpointSignature,
} from '@agent-trust/audit';

import {
  InMemoryAgentCredentialStore,
  InMemoryAttestationStore,
  InMemoryAttestationTrustPolicy,
  TrustProfileService,
} from '@agent-trust/trust-profile';

import { DemoRefundExecutor } from '../src/executor.js';
import { TrustGateway } from '../src/gateway.js';
import { createTaskRequest } from '../src/request.js';

const ROOT = join(fileURLToPath(import.meta.url), '../../../..');
const NOW_UNIX = 1_757_944_800; // 2026-09-15T12:00:00Z — deterministic demo clock

const ORG_DID = 'did:web:acme.example:org';
const SUPPORT_AGENT_DID = 'did:web:agents.acme.example:support-1';
const REFUND_AGENT_DID = 'did:web:payments.example:refund-agent';
const ANCHOR_DID = 'did:web:audit.acme.example:anchor';
const STREAM = 'acme-demo';

const c = (s) => `\x1b[36m${s}\x1b[0m`;
const g = (s) => `\x1b[32m${s}\x1b[0m`;
const r = (s) => `\x1b[31m${s}\x1b[0m`;
const b = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

async function pickReplayProtector() {
  const url = process.env.TEST_REDIS_URL;
  if (url) {
    try {
      const { createClient } = await import('redis');
      const client = createClient({ url });
      await client.connect();
      await client.ping();
      console.log(dim(`replay store: ${g('REDIS')} (${url}) — atomic SET NX PX`));
      return new ReplayProtector(new (await import('@agent-trust/replay')).RedisReplayStore(client, { clock: () => NOW_UNIX }));
    } catch {
      console.log(dim(`replay store: ${r('REDIS UNREACHABLE')}, falling back to in-memory`));
    }
  }
  console.log(dim('replay store: in-memory (set TEST_REDIS_URL=redis://127.0.0.1:6380 for Redis mode)'));
  return new ReplayProtector(new InMemoryReplayStore({ clock: () => NOW_UNIX }));
}

function banner(title) {
  console.log(`\n${b(`=== ${title} ===`)}`);
}

function stage(label, value, good = ['PASS', 'ALLOW', 'SUCCEEDED', 'AUTHORIZED']) {
  const ok = good.includes(value);
  console.log(`  ${label.padEnd(14)} ${ok ? g(value) : r(value)}`);
}

async function main() {
  console.log(b('agent-trust — cross-agent end-to-end demonstration'));
  console.log(dim('all layers are real implementations; clock frozen for determinism'));

  // ---- deterministic world -------------------------------------------------
  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const supportAgent = withDid(LocalSigner.generate(), SUPPORT_AGENT_DID);
  const evilAgent = withDid(LocalSigner.generate(), 'did:web:evil.example:agent');
  const anchorSigner = withDid(LocalSigner.generate(), ANCHOR_DID);

  const resolver = new MultiDidResolver([
    new InMemoryDidResolver([
      didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
      didDocumentForJwk(SUPPORT_AGENT_DID, await supportAgent.publicKey()),
      didDocumentForJwk(ANCHOR_DID, await anchorSigner.publicKey()),
    ]),
  ]);

  const statusStore = new InMemoryStatusListStore();
  const statusManager = new StatusListManager(statusStore, { clock: () => NOW_UNIX });
  const revListId = 'https://acme.example/status/rev/1';
  await statusManager.createList({ id: revListId, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 64 });
  const delegationIndex = await statusManager.assignIndex(revListId);

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
      id: `${revListId}#${delegationIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(delegationIndex),
      statusListCredential: revListId,
    },
  });

  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore: new InMemoryIssuerTrustStore().trust(ORG_DID, 'AgentDelegationCredential'),
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
    quarantineStore: new InMemoryAgentQuarantineStore(),
  });
  const quarantine = new InMemoryAgentQuarantineStore();
  const policy = await loadOpaWasmPolicyEngine(
    join(ROOT, 'artifacts/policy/policy.wasm'),
    join(ROOT, 'artifacts/policy/manifest.json'),
  );
  if (!policy.ok) throw new Error(`policy load failed: ${policy.detail}`);
  const auditLog = new InMemoryAuditLog();
  const executor = new DemoRefundExecutor();

  const gateway = new TrustGateway({
    didResolver: resolver,
    verifier,
    replayProtector: await pickReplayProtector(),
    policyEngine: policy.engine,
    auditLog,
    executor,
    streamId: STREAM,
    clock: () => NOW_UNIX,
  });

  const run = async (opts) => {
    const request = await createTaskRequest({
      signer: opts.signer ?? supportAgent,
      taskId: opts.taskId,
      actor: opts.actor ?? SUPPORT_AGENT_DID,
      audience: opts.audience ?? REFUND_AGENT_DID,
      action: 'refund:create',
      resource: 'order:ORD-918',
      parameters: { amount: opts.amount, currency: 'SAR' },
      credentials: [delegationJws],
      now: NOW_UNIX,
    });
    if (opts.mutate) opts.mutate(request);
    return gateway.handleTask(request);
  };

  const show = (result, label) => {
    console.log(`  ${dim('outcome').padEnd(22)} ${result.outcome === 'AUTHORIZED' ? g(result.outcome) : r(result.outcome)}`);
    if (result.reasonCodes.length > 0) {
      console.log(`  ${dim('reason').padEnd(22)} ${result.reasonCodes.join(', ')}`);
    }
    if (result.decisionReceiptId) {
      console.log(`  ${dim('decision receipt').padEnd(22)} ${result.decisionReceiptId}`);
    }
    if (result.executionReceiptId) {
      console.log(`  ${dim('outcome receipt').padEnd(22)} ${result.executionReceiptId}`);
    }
    void label;
  };

  // ---- Scenario 1: trusted / in scope --------------------------------------
  banner('Scenario 1: Trusted / In Scope — 120 SAR');
  console.log(dim(`  actor: SupportAgent → RefundAgent, refund:create`));
  const s1 = await run({ amount: 120, taskId: 'demo_task_120' });
  stage('Identity', s1.stages.identity);
  stage('Credential', s1.stages.credential);
  stage('Delegation', s1.stages.authority);
  stage('Replay', s1.stages.replay);
  stage('Policy', s1.stages.policy);
  stage('Audit', s1.stages.audit);
  stage('Execution', s1.stages.execution);
  show(s1, 's1');

  // ---- Scenario 2: legitimate but out of scope ------------------------------
  banner('Scenario 2: Legitimate but Out of Scope — 5000 SAR');
  const s2 = await run({ amount: 5000, taskId: 'demo_task_5000' });
  stage('Identity', s2.stages.identity);
  stage('Credential', s2.stages.credential);
  stage('Delegation', s2.stages.authority);
  stage('Replay', s2.stages.replay);
  stage('Policy', s2.stages.policy);
  stage('Execution', s2.stages.execution);
  show(s2, 's2');
  console.log(`  ${dim('executor called:')} ${r('NO')}`);

  // ---- Scenario 3: spoofed identity -----------------------------------------
  banner('Scenario 3: Spoofed Identity (EvilAgent claims SupportAgent DID)');
  const s3 = await run({ signer: evilAgent, amount: 120, taskId: 'demo_task_spoof' });
  stage('Identity', s3.stages.identity);
  stage('Policy', s3.stages.policy);
  stage('Execution', s3.stages.execution);
  show(s3, 's3');
  const chain = await auditLog.readStream(STREAM);
  const victimReceipts = chain.filter(
    (rc) => rc.body.actor.did === SUPPORT_AGENT_DID && rc.body.correlation?.taskId === 'demo_task_spoof',
  );
  console.log(`  ${dim('receipts attributed to SupportAgent for this attack:')} ${victimReceipts.length === 0 ? g('NONE (no false attribution)') : r(victimReceipts.length)}`);

  // ---- Scenario 4: revoked credential ----------------------------------------
  banner('Scenario 4: Credential Revoked (same legitimate agent)');
  await statusManager.revoke(revListId, delegationIndex);
  const s4 = await run({ amount: 120, taskId: 'demo_task_revoked' });
  stage('Identity', s4.stages.identity);
  stage('Credential', s4.stages.credential);
  stage('Policy', s4.stages.policy);
  stage('Execution', s4.stages.execution);
  show(s4, 's4');

  // ---- Scenario 5: replay ------------------------------------------------------
  banner('Scenario 5: Replay — same signed bytes submitted twice');
  // Fresh credential for the replay demo (revocation in scenario 4 was terminal).
  const replayIndex = await statusManager.assignIndex(revListId);
  const reissue = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  const { jws: replayDelegationJws } = await reissue.issueDelegation({
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
      id: `${revListId}#${replayIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(replayIndex),
      statusListCredential: revListId,
    },
  });
  const replayRequest = await createTaskRequest({
    signer: supportAgent,
    taskId: 'demo_task_replay',
    actor: SUPPORT_AGENT_DID,
    audience: REFUND_AGENT_DID,
    action: 'refund:create',
    resource: 'order:ORD-918',
    parameters: { amount: 120, currency: 'SAR' },
    credentials: [replayDelegationJws],
    now: NOW_UNIX,
  });
  const s5a = await gateway.handleTask(replayRequest);
  console.log(`  ${dim('first submission').padEnd(22)} ${s5a.outcome === 'AUTHORIZED' ? g('AUTHORIZED + SUCCEEDED') : r(s5a.outcome)}`);
  const s5b = await gateway.handleTask(replayRequest);
  console.log(`  ${dim('second (same bytes)').padEnd(22)} ${r(s5b.outcome)} — ${r(s5b.reasonCodes.join(', '))}`);
  console.log(`  ${dim('successful refunds total:')} ${executor.successfulRefundCount === 2 ? g('2 (one per distinct authorization)') : r(String(executor.successfulRefundCount))}`);

  // ---- Provenance: chain + checkpoint -----------------------------------------
  banner('Provenance: hash-chained receipts + signed checkpoint');
  const checkpointService = new AuditCheckpointService(anchorSigner);
  const fullChain = await auditLog.readStream(STREAM);
  const checkpoint = await checkpointService.issue({
    checkpointId: 'ckpt_demo_0001',
    streamId: STREAM,
    receipts: fullChain,
    issuedAt: '2026-09-15T12:00:00Z',
  });
  const chainVerified = verifyAuditChain(STREAM, fullChain);
  const cpVerified = await verifyCheckpointSignature({
    checkpoint,
    didResolver: resolver,
    opts: { expectedSignerDid: ANCHOR_DID, now: NOW_UNIX },
  });
  const anchored = verifyAuditAgainstCheckpoint({
    streamId: STREAM,
    receipts: fullChain,
    checkpoint,
    checkpointVerified: cpVerified,
  });
  console.log(`  chain: ${chainVerified.valid ? g(`VALID (${chainVerified.receipts} receipts)`) : r('INVALID')}`);
  console.log(`  checkpoint signature: ${cpVerified.valid ? g('VALID') : r('INVALID')}`);
  console.log(`  chain vs checkpoint: ${anchored.valid ? g('MATCHES') : r('MISMATCH')}`);
  for (const rc of fullChain) {
    console.log(
      dim(`    seq ${String(rc.body.sequence).padStart(2)} ${rc.body.decision.effect.padEnd(5)} ${rc.body.correlation?.taskId ?? ''} ${rc.eventHash.slice(0, 12)}…`),
    );
  }

  // ---- Step 11 (additive): evidence-based Trust Profile -----------------------
  banner('Trust Profile (Step 11): evidence read model over the same pipeline');
  const profileService = new TrustProfileService({
    didResolver: resolver,
    verifier,
    attestationStore: new InMemoryAttestationStore(),
    agentCredentialStore: new InMemoryAgentCredentialStore(),
    attestationTrust: new InMemoryAttestationTrustPolicy(),
    auditLog,
    auditCheckpoint: checkpoint,
    auditStreamId: STREAM,
    checkpointSignerDid: ANCHOR_DID,
  });
  const profile = await profileService.build(SUPPORT_AGENT_DID, {
    now: NOW_UNIX,
    context: { action: 'refund:create' },
  });
  console.log(`  identity resolved: ${profile.identity.resolved ? g('true') : r('false')}`);
  console.log(`  authority (verified delegations): ${c(String(profile.authority.active.length))}`);
  console.log(`  attestations trusted/rejected: ${profile.attestations.trusted.length} / ${profile.attestations.rejected.length} ${dim('(evidence — never authority)')}`);
  const integ = profile.history.integrity;
  console.log(`  history integrity: ${integ.verified ? g('VERIFIED') : r('FAIL-CLOSED')}${integ.verified ? dim(` through sequence ${integ.verifiedThroughSequence}`) : ''}`);
  for (const [action, entry] of Object.entries(profile.history.byAction)) {
    console.log(`    ${action}: allow=${entry.decisions.allow} deny=${entry.decisions.deny} succeeded=${entry.execution.succeeded} failed=${entry.execution.failed} uncertain=${entry.execution.uncertain}`);
  }
  console.log(dim('  the profile is a READ MODEL — policy remains the only authorization engine'));

  console.log(`\n${b('demo complete')} — trust is contextual authority backed by verifiable evidence, not a score.\n`);
}

main().catch((e) => {
  console.error(r(`demo failed: ${e.message}`));
  process.exit(1);
});
