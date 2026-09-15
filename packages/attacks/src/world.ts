import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalSigner, withDid, canonicalJson, sha256, utf8, base64urlEncode, type Signer } from '@agent-trust/crypto';
import { DidKeyResolver, InMemoryDidResolver, MultiDidResolver, didDocumentForJwk } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import { BitstringStatusChecker, InMemoryAgentQuarantineStore, InMemoryStatusListStore, StatusListManager } from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import { AuditCheckpointService, InMemoryAuditLog, type SignedAuditCheckpoint } from '@agent-trust/audit';
import {
  InMemoryAgentCredentialStore,
  InMemoryAttestationStore,
  InMemoryAttestationTrustPolicy,
} from '@agent-trust/trust-profile';

import { DemoRefundExecutor } from '../../gateway/src/executor.js';
import { TrustGateway, type TrustGatewayDeps } from '../../gateway/src/gateway.js';
import { createTaskRequest, type AgentTaskRequest } from '../../gateway/src/request.js';

/**
 * One isolated, fully-deterministic world per scenario (Step 13R). Every
 * attack builds a FRESH world — no cross-scenario state, no order
 * dependence. Clock frozen at 2026-09-15T12:00:00Z (Step 13S).
 */

export const NOW = 1_789_473_600; // 2026-09-15T12:00:00Z
export const HOST = 'trust.example.com';
export const ORG_DID = `did:web:${HOST}:org`;
export const SUPPORT_DID = `did:web:${HOST}:agents:support`;
export const REFUND_DID = `did:web:${HOST}:agents:refund`;
export const EVIL_DID = 'did:web:evil.example:agent';
export const ANCHOR_DID = `did:web:${HOST}:audit`;
export const STREAM = 'attack-demo';

// Locate the hash-pinned policy artifact regardless of execution layout:
// plain Node/tsx from the repo (dev), vitest, or a bundled server (Docker
// standalone), where import.meta.dirname no longer points into the repo.
function findAttackRepoRoot(): string {
  const starts = [process.env.AGENT_TRUST_REPO_ROOT, process.cwd()];
  for (const start of starts) {
    if (start === undefined || start === '') continue;
    let dir = resolve(start);
    for (let up = 0; up < 8; up++) {
      if (existsSync(join(dir, 'artifacts', 'policy', 'policy.wasm'))) return dir;
      const parent = resolve(dir, '..');
      if (parent === dir) break;
      dir = parent;
    }
  }
  // Fall back to the source-relative path (dev/tsx layout, pre-bundle).
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
}
const ROOT = findAttackRepoRoot();
const WASM_PATH = join(ROOT, 'artifacts', 'policy', 'policy.wasm').replaceAll('\\', '/');
const MANIFEST_PATH = join(ROOT, 'artifacts', 'policy', 'manifest.json').replaceAll('\\', '/');
/** Committed artifact paths, resolved for any execution layout. */
export const ATTACK_WASM_PATH = WASM_PATH;

export interface AttackWorld {
  gateway: TrustGateway;
  resolverCore: InMemoryDidResolver;
  gatewayDeps: TrustGatewayDeps;
  executor: DemoRefundExecutor;
  auditLog: InMemoryAuditLog;
  policyCalls: { n: number };
  replayStore: InMemoryReplayStore;
  statusManager: StatusListManager;
  statusStore: InMemoryStatusListStore;
  revListId: string;
  suspListId: string;
  quarantine: InMemoryAgentQuarantineStore;
  trustStore: InMemoryIssuerTrustStore;
  orgSigner: Signer;
  evilSigner: Signer;
  supportSigner: Signer;
  issuer: CredentialIssuer;
  /** Delegation for SUPPORT_DID: refund:create, order:*, ≤500 SAR. */
  delegationJws: string;
  delegationStatusIndex: number;
  attestationStore: InMemoryAttestationStore;
  agentCredentialStore: InMemoryAgentCredentialStore;
  attestationTrust: InMemoryAttestationTrustPolicy;
  auditorIssuer: CredentialIssuer;
  audListId: string;
  checkpointService: AuditCheckpointService;
  /** Lease the next index on the org revocation list. */
  nextRevIndex: () => Promise<number>;
  /** Standard ALLOW-able task request for the support agent. */
  task: (opts?: { amount?: number; taskId?: string; credentials?: string[]; signer?: Signer; actor?: string; audience?: string; resource?: string; mutate?: (r: AgentTaskRequest) => void }) => Promise<AgentTaskRequest>;
}

let worldCounter = 0;

export async function buildAttackWorld(): Promise<AttackWorld> {
  const id = ++worldCounter;

  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const supportSigner = withDid(LocalSigner.generate(), SUPPORT_DID);
  const evilSigner = withDid(LocalSigner.generate(), EVIL_DID);
  const auditorSigner = withDid(LocalSigner.generate(), `did:web:audit.acme.example:auditor`);
  const anchorSigner = withDid(LocalSigner.generate(), ANCHOR_DID);

  const resolverCore = new InMemoryDidResolver([
    didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
    didDocumentForJwk(SUPPORT_DID, await supportSigner.publicKey()),
    didDocumentForJwk(EVIL_DID, await evilSigner.publicKey()),
    didDocumentForJwk(REFUND_DID, await LocalSigner.generate().publicKey()),
    didDocumentForJwk('did:web:audit.acme.example:auditor', await auditorSigner.publicKey()),
    didDocumentForJwk(ANCHOR_DID, await anchorSigner.publicKey()),
  ]);
  const resolver = new MultiDidResolver([resolverCore, new DidKeyResolver()]);

  const statusStore = new InMemoryStatusListStore();
  const statusManager = new StatusListManager(statusStore, { clock: () => NOW });
  const revListId = `https://${HOST}/status/rev/1`;
  const suspListId = `https://${HOST}/status/susp/1`;
  await statusManager.createList({ id: revListId, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 256 });
  await statusManager.createList({ id: suspListId, purpose: 'suspension', controllerDid: ORG_DID, sizeBits: 256 });
  const audListId = 'https://audit.acme.example/status/rev/1';
  await statusManager.createList({ id: audListId, purpose: 'revocation', controllerDid: 'did:web:audit.acme.example:auditor', sizeBits: 256 });

  const issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  const auditorIssuer = new CredentialIssuer(auditorSigner, { issuerDid: 'did:web:audit.acme.example:auditor' });

  const delegationStatusIndex = await statusManager.assignIndex(revListId);
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
      id: `${revListId}#${delegationStatusIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(delegationStatusIndex),
      statusListCredential: revListId,
    },
  });

  const trustStore = new InMemoryIssuerTrustStore()
    .trust(ORG_DID, 'AgentDelegationCredential')
    .trust(ORG_DID, 'AgentMembershipCredential')
    .trust(ORG_DID, 'AgentAttestationCredential')
    .trust('did:web:audit.acme.example:auditor', 'AgentAttestationCredential');

  const quarantine = new InMemoryAgentQuarantineStore();
  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore,
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
    quarantineStore: quarantine,
  });

  const replayStore = new InMemoryReplayStore({ clock: () => NOW });
  const replayProtector = new ReplayProtector(replayStore);

  const policyCalls = { n: 0 };
  const policy = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
  if (!policy.ok) throw new Error(`policy load failed: ${policy.detail}`);
  const countingPolicy = {
    evaluate: async (input: unknown) => {
      policyCalls.n += 1;
      return policy.engine.evaluate(input);
    },
  };

  const auditLog = new InMemoryAuditLog({
    idFactory: (() => {
      let n = 0;
      return () => `rcpt_${String(++n).padStart(6, '0')}`;
    })(),
  });
  const executor = new DemoRefundExecutor();

  const gatewayDeps: TrustGatewayDeps = {
    didResolver: resolver,
    verifier,
    replayProtector,
    policyEngine: countingPolicy,
    auditLog,
    executor,
    streamId: STREAM,
    clock: () => NOW,
  };
  const gateway = new TrustGateway(gatewayDeps);

  const attestationStore = new InMemoryAttestationStore({ clock: () => NOW });
  const agentCredentialStore = new InMemoryAgentCredentialStore({ clock: () => NOW });
  const attestationTrust = new InMemoryAttestationTrustPolicy();

  let revCursor = 1;
  const nextRevIndex = (): Promise<number> => statusManager.assignIndex(revListId);
  void revCursor;

  const task: AttackWorld['task'] = async (opts = {}) => {
    const r = await createTaskRequest({
      signer: opts.signer ?? supportSigner,
      taskId: opts.taskId ?? `atk_${id}_${Math.random().toString(36).slice(2, 8)}`,
      actor: opts.actor ?? SUPPORT_DID,
      audience: opts.audience ?? REFUND_DID,
      action: 'refund:create',
      resource: opts.resource ?? 'order:ORD-918',
      parameters: { amount: opts.amount ?? 120, currency: 'SAR' },
      credentials: opts.credentials ?? [delegationJws],
      now: NOW,
    });
    if (opts.mutate) opts.mutate(r);
    return r;
  };

  return {
    gateway,
    resolverCore,
    gatewayDeps,
    executor,
    auditLog,
    policyCalls,
    replayStore,
    statusManager,
    statusStore,
    revListId,
    suspListId,
    quarantine,
    trustStore,
    orgSigner,
    evilSigner,
    supportSigner,
    issuer,
    delegationJws,
    delegationStatusIndex,
    attestationStore,
    agentCredentialStore,
    attestationTrust,
    auditorIssuer,
    audListId,
    checkpointService: new AuditCheckpointService(anchorSigner),
    nextRevIndex,
    task,
  };
}

export async function anchorCheckpoint(world: AttackWorld, checkpointId = 'ckpt_attack'): Promise<SignedAuditCheckpoint> {
  return world.checkpointService.issue({
    checkpointId,
    streamId: STREAM,
    receipts: await world.auditLog.readStream(STREAM),
    issuedAt: '2026-09-15T12:00:00Z',
  });
}

/** Issue a fresh attestation about the support agent (default: auditor). */
export async function issueAttestation(
  world: AttackWorld,
  opts: {
    issuer?: 'auditor' | 'org' | 'evil';
    type?: 'CAPABILITY_ENDORSEMENT' | 'SECURITY_REVIEW' | 'OPERATIONAL_APPROVAL';
    subject?: string;
    validFrom?: number;
    validUntil?: number;
  } = {},
): Promise<{ jws: string; statusIndex: number }> {
  const statusIndex = await world.statusManager.assignIndex(world.audListId);
  const issuer =
    opts.issuer === 'org' ? world.issuer : opts.issuer === 'evil' ? new CredentialIssuer(world.evilSigner, { issuerDid: EVIL_DID }) : world.auditorIssuer;
  const issuerDid = opts.issuer === 'org' ? ORG_DID : opts.issuer === 'evil' ? EVIL_DID : 'did:web:audit.acme.example:auditor';
  const { jws } = await issuer.issueAttestation({
    subjectDid: opts.subject ?? SUPPORT_DID,
    attestation: {
      type: opts.type ?? 'CAPABILITY_ENDORSEMENT',
      domain: 'refunds',
      statement: 'ENDORSED',
    },
    validFrom: opts.validFrom ?? NOW - 3600,
    validUntil: opts.validUntil ?? NOW + 86_400,
    credentialStatus: {
      id: `${world.audListId}#${statusIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(statusIndex),
      statusListCredential: world.audListId,
    },
  });
  void issuerDid;
  return { jws, statusIndex };
}

export { base64urlEncode, canonicalJson, sha256, utf8 };
