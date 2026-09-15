import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { join } from 'node:path';

import { LocalSigner, withDid, createProof, requestBodyDigestOf, canonicalJson, utf8, sha256, base64urlEncode } from '@agent-trust/crypto';
import type { Signer } from '@agent-trust/crypto';
import { InMemoryDidResolver, MultiDidResolver, didDocumentForJwk } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import { BitstringStatusChecker, InMemoryAgentQuarantineStore, InMemoryStatusListStore, StatusListManager } from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine, type OpaWasmPolicyEngine } from '@agent-trust/policy';
import { InMemoryAuditLog } from '@agent-trust/audit';

import { DemoRefundExecutor } from '../src/executor.js';
import { TrustGateway, type TrustGatewayDeps } from '../src/gateway.js';
import { GATEWAY_HTU, taskContent, type AgentTaskRequest } from '../src/request.js';

const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');

export const NOW_UNIX = 1_757_944_800; // 2026-09-15T12:00:00Z
export const ORG_DID = 'did:web:acme.example:org';
export const SUPPORT_AGENT_DID = 'did:web:agents.acme.example:support-1';
export const REFUND_AGENT_DID = 'did:web:payments.example:refund-agent';
export const STREAM = 'acme-demo';

const canonicalNow = (unix: number): string =>
  new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

export interface World {
  deps: TrustGatewayDeps;
  gateway: TrustGateway;
  executor: DemoRefundExecutor;
  supportAgent: Signer;
  evilAgent: Signer;
  delegationJws: string;
  statusManager: StatusListManager;
  delegationIndex: number;
  revListId: string;
  quarantine: InMemoryAgentQuarantineStore;
  clock: { now: number };
  auditLog: InMemoryAuditLog;
}

export async function buildWorld(opts: { statusPurpose?: 'revocation' | 'suspension' } = {}): Promise<World> {
  const clock = { now: NOW_UNIX };
  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const supportAgent = withDid(LocalSigner.generate(), SUPPORT_AGENT_DID);
  const evilAgent = withDid(LocalSigner.generate(), 'did:web:evil.example:agent');

  const resolver = new MultiDidResolver([
    new InMemoryDidResolver([
      didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
      didDocumentForJwk(SUPPORT_AGENT_DID, await supportAgent.publicKey()),
      didDocumentForJwk('did:web:evil.example:agent', await evilAgent.publicKey()),
    ]),
  ]);

  const statusStore = new InMemoryStatusListStore();
  const statusManager = new StatusListManager(statusStore, { clock: () => clock.now });
  const revListId = 'https://acme.example/status/rev/1';
  const purpose = opts.statusPurpose ?? 'revocation';
  await statusManager.createList({ id: revListId, purpose, controllerDid: ORG_DID, sizeBits: 64 });
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
      statusPurpose: purpose,
      statusListIndex: String(delegationIndex),
      statusListCredential: revListId,
    },
  });

  const trustStore = new InMemoryIssuerTrustStore().trust(ORG_DID, 'AgentDelegationCredential');
  const quarantine = new InMemoryAgentQuarantineStore();
  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore,
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
    quarantineStore: quarantine,
  });
  const replayProtector = new ReplayProtector(new InMemoryReplayStore({ clock: () => clock.now }));
  const policyResult = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
  if (!policyResult.ok) throw new Error(`policy load failed: ${policyResult.detail}`);
  const auditLog = new InMemoryAuditLog({ idFactory: (() => {
    let n = 0;
    return () => `rcpt_${String(++n).padStart(6, '0')}`;
  })() });
  const executor = new DemoRefundExecutor();

  const deps: TrustGatewayDeps = {
    didResolver: resolver,
    verifier,
    replayProtector,
    policyEngine: policyResult.engine,
    auditLog,
    executor,
    streamId: STREAM,
    clock: () => clock.now,
  };
  return {
    deps,
    gateway: new TrustGateway(deps),
    executor,
    supportAgent,
    evilAgent,
    delegationJws,
    statusManager,
    delegationIndex,
    revListId,
    quarantine,
    clock,
    auditLog,
  };
}

/** Build a signed task request with a fresh jti. */
export async function taskRequest(world: World, opts: {
  actor?: string;
  signer?: Signer;
  taskId?: string;
  action?: string;
  resource?: string;
  audience?: string;
  amount?: number;
  currency?: string;
  credentials?: string[];
  mutate?: (req: AgentTaskRequest) => void;
}): Promise<AgentTaskRequest> {
  const signer = opts.signer ?? world.supportAgent;
  const actor = opts.actor ?? SUPPORT_AGENT_DID;
  const { createTaskRequest } = await import('../src/request.js');
  const request = await createTaskRequest({
    signer,
    taskId: opts.taskId ?? `task_${Math.random().toString(36).slice(2, 10)}`,
    actor,
    audience: opts.audience ?? REFUND_AGENT_DID,
    action: opts.action ?? 'refund:create',
    resource: opts.resource ?? 'order:ORD-918',
    parameters: { amount: opts.amount ?? 120, currency: opts.currency ?? 'SAR' },
    credentials: opts.credentials ?? [world.delegationJws],
    now: world.clock.now,
  });
  if (opts.mutate) opts.mutate(request);
  return request;
}

export { canonicalNow, canonicalJson, utf8, sha256, base64urlEncode, taskContent, requestBodyDigestOf, createProof };
