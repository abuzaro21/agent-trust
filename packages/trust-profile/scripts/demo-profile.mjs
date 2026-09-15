#!/usr/bin/env node
/**
 * pnpm demo:profile — evidence-based Trust Profiles (Step 11).
 *
 * Real components only: real keys, real DID resolution, real VC pipeline
 * (attestations verified through the SAME CredentialVerifier as every
 * other credential), real Bitstring Status List revocation, real
 * hash-chained audit + signed checkpoint. The profile is a READ MODEL:
 * it reports verified evidence and NEVER authorizes anything.
 */
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalSigner, withDid } from '@agent-trust/crypto';
import { InMemoryDidResolver, MultiDidResolver, didDocumentForJwk } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import { BitstringStatusChecker, InMemoryStatusListStore, StatusListManager } from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import { AuditCheckpointService, InMemoryAuditLog } from '@agent-trust/audit';

import { DemoRefundExecutor } from '../../gateway/src/executor.js';
import { TrustGateway } from '../../gateway/src/gateway.js';
import { createTaskRequest } from '../../gateway/src/request.js';

import {
  InMemoryAgentCredentialStore,
  InMemoryAttestationStore,
  InMemoryAttestationTrustPolicy,
  TrustProfileService,
} from '../src/index.js';

const ROOT = join(fileURLToPath(import.meta.url), '../../../..');
const NOW_UNIX = 1_789_473_600; // 2026-09-15T12:00:00Z — deterministic demo clock

const ORG_DID = 'did:web:acme.example:org';
const SUPPORT_AGENT_DID = 'did:web:agents.acme.example:support-1';
const REFUND_AGENT_DID = 'did:web:payments.example:refund-agent';
const AUDITOR_DID = 'did:web:audit.acme.example:auditor';
const ANCHOR_DID = 'did:web:audit.acme.example:anchor';
const STREAM = 'acme-demo';

const c = (s) => `\x1b[36m${s}\x1b[0m`;
const g = (s) => `\x1b[32m${s}\x1b[0m`;
const r = (s) => `\x1b[31m${s}\x1b[0m`;
const b = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

function banner(title) {
  console.log(`\n${b(`=== ${title} ===`)}`);
}

async function main() {
  console.log(b('agent-trust — evidence-based Trust Profiles (Step 11)'));
  console.log(dim('the profile is a REPORT about verified evidence; policy remains the only authorization engine'));

  // ---- deterministic world ---------------------------------------------------
  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const auditorSigner = withDid(LocalSigner.generate(), AUDITOR_DID);
  const anchorSigner = withDid(LocalSigner.generate(), ANCHOR_DID);
  const supportAgent = withDid(LocalSigner.generate(), SUPPORT_AGENT_DID);
  const sybilSigner = withDid(LocalSigner.generate(), 'did:web:sybil.example:agent');

  const resolverCore = new InMemoryDidResolver([
    didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
    didDocumentForJwk(AUDITOR_DID, await auditorSigner.publicKey()),
    didDocumentForJwk(ANCHOR_DID, await anchorSigner.publicKey()),
    didDocumentForJwk(SUPPORT_AGENT_DID, await supportAgent.publicKey()),
    didDocumentForJwk(REFUND_AGENT_DID, await LocalSigner.generate().publicKey()),
  ]);
  const resolver = new MultiDidResolver([resolverCore]);
  resolverCore.register(didDocumentForJwk('did:web:sybil.example:agent', await sybilSigner.publicKey()));

  // Status lists: one per ISSUER (the checker binds list controller = credential issuer).
  const statusStore = new InMemoryStatusListStore();
  const statusManager = new StatusListManager(statusStore, { clock: () => NOW_UNIX });
  const revListId = 'https://acme.example/status/rev/1';
  await statusManager.createList({ id: revListId, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 256 });
  const audListId = 'https://audit.acme.example/status/rev/1';
  await statusManager.createList({ id: audListId, purpose: 'revocation', controllerDid: AUDITOR_DID, sizeBits: 256 });

  const issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  const auditorIssuer = new CredentialIssuer(auditorSigner, { issuerDid: AUDITOR_DID });
  const sybilIssuer = new CredentialIssuer(sybilSigner, { issuerDid: 'did:web:sybil.example:agent' });

  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore: new InMemoryIssuerTrustStore()
      .trust(ORG_DID, 'AgentDelegationCredential')
      .trust(ORG_DID, 'AgentAttestationCredential')
      .trust(AUDITOR_DID, 'AgentAttestationCredential'),
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
  });

  // Typed attestation trust: issuer + TYPE pairs. The auditor is trusted
  // for capability endorsements and security reviews — nothing else.
  const attestationTrust = new InMemoryAttestationTrustPolicy()
    .trust(AUDITOR_DID, 'CAPABILITY_ENDORSEMENT')
    .trust(AUDITOR_DID, 'SECURITY_REVIEW');

  const attestationStore = new InMemoryAttestationStore({ clock: () => NOW_UNIX });
  const agentCredentialStore = new InMemoryAgentCredentialStore({ clock: () => NOW_UNIX });

  // ---- evidence registration ---------------------------------------------------
  banner('Registering evidence for the support agent');
  const delegationIndex = await statusManager.assignIndex(revListId);
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
  agentCredentialStore.add(SUPPORT_AGENT_DID, delegationJws);
  console.log(`  ${dim('delegation credential:')} ${c('registered')} (org-issued, status-anchored)`);

  const audIndex = await statusManager.assignIndex(audListId);
  const { jws: endorsementJws } = await auditorIssuer.issueAttestation({
    subjectDid: SUPPORT_AGENT_DID,
    attestation: { type: 'CAPABILITY_ENDORSEMENT', domain: 'refunds', statement: 'ENDORSED' },
    validFrom: NOW_UNIX - 3600,
    validUntil: NOW_UNIX + 86_400,
    credentialStatus: {
      id: `${audListId}#${audIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(audIndex),
      statusListCredential: audListId,
    },
  });
  attestationStore.add(SUPPORT_AGENT_DID, endorsementJws);
  console.log(`  ${dim('attestation (auditor, CAPABILITY_ENDORSEMENT):')} ${c('registered')}`);

  // 3 untrusted Sybil vouches — they will land in `rejected`, never `trusted`.
  for (let i = 0; i < 3; i++) {
    const { jws } = await sybilIssuer.issueAttestation({
      subjectDid: SUPPORT_AGENT_DID,
      attestation: { type: 'CAPABILITY_ENDORSEMENT', domain: 'refunds', statement: 'APPROVED' },
      validFrom: NOW_UNIX - 3600,
      validUntil: NOW_UNIX + 86_400,
    });
    attestationStore.add(SUPPORT_AGENT_DID, jws);
  }
  console.log(`  ${dim('untrusted self-vouches:')} ${c('3 registered')} (issued by a nobody)`);
  console.log(dim('  registration is NOT trust — every credential is re-verified from its bytes'));

  // ---- real gateway activity → auditable history -------------------------------
  banner('Real gateway activity (audit-before-side-effect receipts)');
  const policy = await loadOpaWasmPolicyEngine(
    join(ROOT, 'artifacts/policy/policy.wasm'),
    join(ROOT, 'artifacts/policy/manifest.json'),
  );
  if (!policy.ok) throw new Error(`policy load failed: ${policy.detail}`);
  const auditLog = new InMemoryAuditLog();
  const gateway = new TrustGateway({
    didResolver: resolver,
    verifier,
    replayProtector: new ReplayProtector(new InMemoryReplayStore({ clock: () => NOW_UNIX })),
    policyEngine: policy.engine,
    auditLog,
    executor: new DemoRefundExecutor(),
    streamId: STREAM,
    clock: () => NOW_UNIX,
  });

  const runTask = async (taskId, amount) => {
    const request = await createTaskRequest({
      signer: supportAgent,
      taskId,
      actor: SUPPORT_AGENT_DID,
      audience: REFUND_AGENT_DID,
      action: 'refund:create',
      resource: 'order:ORD-918',
      parameters: { amount, currency: 'SAR' },
      credentials: [delegationJws],
      now: NOW_UNIX,
    });
    return gateway.handleTask(request);
  };
  const t1 = await runTask('profile_task_120', 120);
  const t2 = await runTask('profile_task_5000', 5000);
  console.log(`  task 120 SAR: ${t1.outcome === 'AUTHORIZED' ? g('ALLOW + executed') : r(t1.outcome)}`);
  console.log(`  task 5000 SAR: ${t2.effect === 'DENY' ? r('DENY') : g(t2.outcome)} ${dim(`(${t2.reasonCodes.join(', ')})`)}`);

  // ---- signed checkpoint over the history ---------------------------------------
  const anchorSignerService = new AuditCheckpointService(anchorSigner);
  const checkpoint = await anchorSignerService.issue({
    checkpointId: 'ckpt_profile_demo',
    streamId: STREAM,
    receipts: await auditLog.readStream(STREAM),
    issuedAt: '2026-09-15T12:00:00Z',
  });
  const profileService = new TrustProfileService({
    didResolver: resolver,
    verifier,
    attestationStore,
    agentCredentialStore,
    attestationTrust,
    auditLog,
    auditCheckpoint: checkpoint,
    auditStreamId: STREAM,
    checkpointSignerDid: ANCHOR_DID,
  });

  // ---- build + render the profile -------------------------------------------------
  banner('Trust Profile — did:web:agents.acme.example:support-1');
  const profile = await profileService.build(SUPPORT_AGENT_DID, { now: NOW_UNIX, context: { action: 'refund:create' } });

  console.log(`  identity: resolved=${profile.identity.resolved ? c('true') : r('false')}${profile.identity.verificationMethodCount !== undefined ? dim(` (${profile.identity.verificationMethodCount} verification method)`) : ''}`);

  console.log(`\n  ${b('authority (from VERIFIED delegation credentials only)')}`);
  for (const a of profile.authority.active) {
    console.log(`    ${c(a.credentialId)}  ${dim('issuer:')} ${a.issuer}`);
    console.log(`      actions: ${a.actions.join(', ')}  resources: ${a.resources.join(', ')}`);
    if (a.audience) console.log(`      audience: ${a.audience.join(', ')}`);
    if (a.limits) console.log(`      limits: ${JSON.stringify(a.limits)}`);
    console.log(`      applicable(context refund:create): ${a.applicable ? g('true') : r('false')}  ${dim('evidence:')} sha256:${a.evidenceDigest.slice(0, 16)}…`);
  }

  console.log(`\n  ${b('credentials (status-counted by the full pipeline)')}`);
  console.log(`    active: ${g(String(profile.credentials.active))}  suspended: ${profile.credentials.suspended}  revoked: ${r(String(profile.credentials.revoked))}`);

  console.log(`\n  ${b('attestations — EVIDENCE, never authority')}`);
  for (const t of profile.attestations.trusted) {
    console.log(`    ${g('trusted ')} ${t.type} / ${t.statement} on ${c(t.domain)}  ${dim('by')} ${t.issuer}`);
  }
  for (const rej of profile.attestations.rejected) {
    console.log(`    ${r('rejected')} ${rej.credentialId ? dim(rej.credentialId) + ' ' : ''}${dim('(' + rej.reasonCodes.join(', ') + ')')}`);
  }
  console.log(`    ${dim('trust is scoped by issuer+type; 3 untrusted vouches contribute NOTHING')}`);

  console.log(`\n  ${b('history (verified hash chain + signed checkpoint)')}`);
  const integ = profile.history.integrity;
  console.log(`    integrity: ${integ.verified ? g('VERIFIED') : r('FAIL-CLOSED')}${integ.verified ? dim(` through sequence ${integ.verifiedThroughSequence} (checkpoint ${integ.checkpointId}, head sha256:${integ.checkpointHeadHash.slice(0, 16)}…)`) : dim(` (${integ.detail})`)}`);
  for (const [action, entry] of Object.entries(profile.history.byAction)) {
    console.log(`    ${c(action)}: allow=${entry.decisions.allow} deny=${entry.decisions.deny}  succeeded=${entry.execution.succeeded} failed=${entry.execution.failed} uncertain=${entry.execution.uncertain}`);
    for (const [code, count] of Object.entries(entry.reasonCodes)) {
      console.log(`      ${dim('reason codes:')} ${r(code)} ×${count}`);
    }
    console.log(`      ${dim('last observed:')} ${entry.lastObservedAt}`);
  }

  banner('What the profile does NOT contain');
  console.log(`  ${r('No trust score.')} No reputation. No rating. No number a vouching swarm`);
  console.log('  could inflate: the schema structurally forbids score fields, policy');
  console.log('  remains the ONLY authorization engine, and a profile with trusted');
  console.log('  attestations but no delegation credential authorizes nothing.');
  console.log('');
  console.log('  Trust score: NONE — intentionally not used.');
}

main().catch((e) => {
  console.error(r(`demo failed: ${e.message}`));
  process.exit(1);
});
