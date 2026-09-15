import { describe, expect, it } from 'vitest';
import { join } from 'node:path';

import { LocalSigner, withDid } from '@agent-trust/crypto';
import { jwkThumbprint } from '@agent-trust/crypto';
import { DidKeyResolver, MultiDidResolver, WebDidResolver, didWebToUrl, type DidWebHttpClient, type DidWebHttpResponse } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import { BitstringStatusChecker, InMemoryStatusListStore, StatusListManager } from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import { AuditCheckpointService, InMemoryAuditLog } from '@agent-trust/audit';
import { TrustProfileService } from '@agent-trust/trust-profile';

import { DemoRefundExecutor } from '../src/executor.js';
import { TrustGateway } from '../src/gateway.js';
import { createTaskRequest } from '../src/request.js';

/**
 * Step 12 (Gateway compatibility) — the SAME trust pipeline, with every
 * identity resolved through the REAL WebDidResolver over a controlled
 * HTTP transport. Changing the identity method must not change what an
 * agent is authorized to do: the policy semantics are identical to the
 * did:key world, and a profile built over did:web identities shows no
 * special treatment.
 */

const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');

const NOW = 1_789_473_600; // 2026-09-15T12:00:00Z
const HOST = 'trust.example.com';
const ORG_DID = `did:web:${HOST}:org`;
const SUPPORT_DID = `did:web:${HOST}:agents:support`;
const REFUND_DID = `did:web:${HOST}:agents:refund`;
const EVIL_DID = `did:web:evil.example:agent`;
const STREAM = 'acme-demo';

async function buildDidWebWorld() {
  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const supportSigner = withDid(LocalSigner.generate(), SUPPORT_DID);
  const refundSigner = withDid(LocalSigner.generate(), REFUND_DID);
  const evilSigner = withDid(LocalSigner.generate(), EVIL_DID);
  const anchorSigner = withDid(LocalSigner.generate(), `did:web:${HOST}:audit`);

  // The controlled "web host": DID documents keyed by resolution URL.
  const docs = new Map<string, string>();
  async function register(did: string, signer: ReturnType<typeof withDid>) {
    const jwk = await signer.publicKey();
    // The SAME derivation the resolver uses — no hand-built URLs.
    const url = didWebToUrl(did).toString();
    docs.set(url, JSON.stringify({
      id: did,
      verificationMethod: [
        { id: `${did}#${jwkThumbprint(jwk)}`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk },
      ],
    }));
    return `${did}#${jwkThumbprint(jwk)}`;
  }
  const orgKid = await register(ORG_DID, orgSigner);
  const supportKid = await register(SUPPORT_DID, supportSigner);
  await register(REFUND_DID, refundSigner);
  await register(EVIL_DID, evilSigner);
  await register(`did:web:${HOST}:audit`, anchorSigner);

  let networkCalls = 0;
  const http: DidWebHttpClient = {
    get: async (url, _options): Promise<DidWebHttpResponse> => {
      networkCalls += 1;
      const body = docs.get(url.toString());
      if (body === undefined) return { status: 404, headers: {}, body: '' };
      return { status: 200, headers: { 'cache-control': 'max-age=60' }, body };
    },
  };
  const webResolver = new WebDidResolver({ http, clock: () => Date.now(), networkPolicy: { blockPrivateNetworks: true } });
  const resolver = new MultiDidResolver([webResolver, new DidKeyResolver()]);

  const statusStore = new InMemoryStatusListStore();
  const statusManager = new StatusListManager(statusStore, { clock: () => NOW });
  const revListId = `https://${HOST}/status/rev/1`;
  await statusManager.createList({ id: revListId, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 64 });
  const delegationIndex = await statusManager.assignIndex(revListId);

  const issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  const { jws: delegationJws } = await issuer.issueDelegation({
    subjectDid: SUPPORT_DID,
    authority: {
      actions: ['refund:create'],
      resources: ['order:*'],
      audience: [REFUND_DID],
      limits: { amount: 500, currency: 'SAR' },
      delegationDepth: 0,
    },
    validFrom: NOW - 3600,
    validUntil: NOW + 86_400,
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
  });

  const policy = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
  if (!policy.ok) throw new Error(`policy load failed: ${policy.detail}`);
  const auditLog = new InMemoryAuditLog();
  const executor = new DemoRefundExecutor();
  const gateway = new TrustGateway({
    didResolver: resolver,
    verifier,
    replayProtector: new ReplayProtector(new InMemoryReplayStore({ clock: () => NOW })),
    policyEngine: policy.engine,
    auditLog,
    executor,
    streamId: STREAM,
    clock: () => NOW,
  });

  const checkpoint = await new AuditCheckpointService(anchorSigner).issue({
    checkpointId: 'ckpt_didweb',
    streamId: STREAM,
    receipts: [],
    issuedAt: '2026-09-15T12:00:00Z',
  });

  return {
    gateway,
    executor,
    resolver,
    webResolver,
    orgSigner,
    supportSigner,
    evilSigner,
    delegationJws,
    orgKid,
    supportKid,
    auditLog,
    checkpoint,
    verifier,
    anchorSigner,
    networkCalls: () => networkCalls,
  };
}

async function task(world: Awaited<ReturnType<typeof buildDidWebWorld>>, opts: {
  amount: number;
  taskId: string;
  signer?: (typeof world)['supportSigner'] | (typeof world)['evilSigner'];
  actor?: string;
}) {
  const request = await createTaskRequest({
    signer: opts.signer ?? world.supportSigner,
    taskId: opts.taskId,
    actor: opts.actor ?? SUPPORT_DID,
    audience: REFUND_DID,
    action: 'refund:create',
    resource: 'order:ORD-918',
    parameters: { amount: opts.amount, currency: 'SAR' },
    credentials: [world.delegationJws],
    now: NOW,
  });
  return world.gateway.handleTask(request);
}

describe('did:web Gateway compatibility (Step 12)', () => {
  it('120 SAR → ALLOW + executed; 5000 SAR → DENY AUTHORITY_LIMIT_EXCEEDED (identical semantics to did:key)', async () => {
    const world = await buildDidWebWorld();
    const ok = await task(world, { amount: 120, taskId: 'web_task_120' });
    expect(ok.outcome).toBe('AUTHORIZED');
    expect(ok.effect).toBe('ALLOW');
    expect(world.executor.callCount.total).toBe(1);

    const over = await task(world, { amount: 5000, taskId: 'web_task_5000' });
    expect(over.effect).toBe('DENY');
    expect(over.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    expect(world.executor.callCount.total).toBe(1);
  });

  it('performance observation (non-gating): cold network resolution vs warm cache', async () => {
    const world = await buildDidWebWorld();
    const cold0 = performance.now();
    await task(world, { amount: 120, taskId: 'perf_cold' });
    const coldMs = performance.now() - cold0;
    const warm0 = performance.now();
    await task(world, { amount: 120, taskId: 'perf_warm' });
    const warmMs = performance.now() - warm0;
    // Measurement only — no assertion on latency (CI must not fail on it).
    console.log(
      `  did:web perf: cold task ${coldMs.toFixed(1)} ms → warm (cached identities) ${warmMs.toFixed(1)} ms`,
    );
  });

  it('identity keys ARE discovered via web resolution; the cache absorbs repeats within TTL', async () => {
    const world = await buildDidWebWorld();
    await task(world, { amount: 120, taskId: 'web_task_cache1' });
    const afterFirst = world.networkCalls();
    expect(afterFirst).toBeGreaterThanOrEqual(2); // org DID + support DID fetched for real
    await task(world, { amount: 120, taskId: 'web_task_cache2' });
    // Same identities within the 60s max-age → zero additional network calls.
    expect(world.networkCalls()).toBe(afterFirst);
  });

  it('spoofed did:web actor (evil key, claimed support DID) → IDENTITY_PROOF_INVALID', async () => {
    const world = await buildDidWebWorld();
    const result = await task(world, { amount: 120, taskId: 'web_task_spoof', signer: world.evilSigner, actor: SUPPORT_DID });
    expect(result.effect).toBe('DENY');
    expect(result.reasonCodes).toContain('IDENTITY_PROOF_INVALID');
    expect(world.executor.callCount.total).toBe(0);
  });

  it('credential signed under the ORG document verifies; the same bytes claim nothing about other hosts', async () => {
    const world = await buildDidWebWorld();
    const resolved = await world.resolver.resolveVerificationMethod(world.orgKid);
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.didDocument.id).toBe(ORG_DID);
    // A kid pointing at a DIFFERENT did:web DID's document fails exactly.
    const foreign = await world.resolver.resolveVerificationMethod(`${EVIL_DID}#key-1`);
    expect(foreign.ok).toBe(false);
  });

  it('Trust Profile over did:web identity: resolved=true, authority intact, NO web trust bonus', async () => {
    const world = await buildDidWebWorld();
    await task(world, { amount: 120, taskId: 'web_profile_1' });
    await task(world, { amount: 5000, taskId: 'web_profile_2' });
    // Re-anchor the checkpoint over the receipts that exist now.
    world.checkpoint = await new AuditCheckpointService(world.anchorSigner).issue({
      checkpointId: 'ckpt_profile',
      streamId: STREAM,
      receipts: await world.auditLog.readStream(STREAM),
      issuedAt: '2026-09-15T12:00:00Z',
    });
    const { InMemoryAgentCredentialStore, InMemoryAttestationStore, InMemoryAttestationTrustPolicy } =
      await import('@agent-trust/trust-profile');
    const agentCredentialStore = new InMemoryAgentCredentialStore();
    agentCredentialStore.add(SUPPORT_DID, world.delegationJws);
    const profile = await new TrustProfileService({
      didResolver: world.resolver,
      verifier: world.verifier,
      attestationStore: new InMemoryAttestationStore(),
      agentCredentialStore,
      attestationTrust: new InMemoryAttestationTrustPolicy(),
      auditLog: world.auditLog,
      auditCheckpoint: world.checkpoint,
      auditStreamId: STREAM,
    }).build(SUPPORT_DID, { now: NOW, context: { action: 'refund:create' } });

    expect(profile.agent.did).toBe(SUPPORT_DID);
    expect(profile.identity.resolved).toBe(true);
    expect(profile.authority.active).toHaveLength(1);
    expect(profile.authority.active[0]!.applicable).toBe(true);
    expect(profile.attestations.trusted).toEqual([]);
    if (!profile.history.integrity.verified) throw new Error('history failed: ' + JSON.stringify(profile.history.integrity));
    expect(profile.history.byAction['refund:create']!.decisions).toEqual({ allow: 1, deny: 1 });
    expect(JSON.stringify(profile)).not.toMatch(/score|rating|stars/i);
  });
});
