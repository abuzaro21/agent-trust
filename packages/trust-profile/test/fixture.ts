import { join } from 'node:path';

import { LocalSigner, withDid, type Signer } from '@agent-trust/crypto';
import { InMemoryDidResolver, MultiDidResolver, didDocumentForJwk } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import { BitstringStatusChecker, InMemoryStatusListStore, StatusListManager } from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import {
  AuditCheckpointService,
  InMemoryAuditLog,
  type SignedAuditCheckpoint,
} from '@agent-trust/audit';

import { DemoRefundExecutor } from '../../gateway/src/executor.js';
import { TrustGateway, type TrustGatewayDeps } from '../../gateway/src/gateway.js';

import {
  InMemoryAgentCredentialStore,
  InMemoryAttestationStore,
  InMemoryAttestationTrustPolicy,
  TrustProfileService,
} from '../src/index.js';

export const WASM_PATH = join(__dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/');
export const MANIFEST_PATH = join(__dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/');

export const NOW_UNIX = 1_789_473_600; // 2026-09-15T12:00:00Z
export const ORG_DID = 'did:web:acme.example:org';
export const AGENT_DID = 'did:web:agents.acme.example:support-1';
export const EVIL_DID = 'did:web:evil.example:agent';
export const AUDITOR_DID = 'did:web:audit.acme.example:auditor';
export const ANCHOR_DID = 'did:web:audit.acme.example:anchor';
export const REFUND_AGENT_DID = 'did:web:payments.example:refund-agent';
export const STREAM = 'acme-demo';

export interface World {
  clock: { now: number };
  resolver: MultiDidResolver;
  /** The underlying in-memory resolver — tests register extra DIDs here. */
  resolverCore: InMemoryDidResolver;
  issuer: CredentialIssuer;
  auditorIssuer: CredentialIssuer;
  orgSigner: Signer;
  auditorSigner: Signer;
  agentSigner: Signer;
  evilSigner: Signer;
  verifier: CredentialVerifier;
  trustStore: InMemoryIssuerTrustStore;
  attestationTrust: InMemoryAttestationTrustPolicy;
  attestationStore: InMemoryAttestationStore;
  agentCredentialStore: InMemoryAgentCredentialStore;
  statusManager: StatusListManager;
  revListId: string;
  /** Auditor-controlled revocation list (for auditor-signed attestations). */
  audListId: string;
  /** Lease the next status index on a list. */
  nextStatusIndex: (listId?: string) => Promise<number>;
  gateway: TrustGateway;
  gatewayDeps: TrustGatewayDeps;
  executor: DemoRefundExecutor;
  auditLog: InMemoryAuditLog;
  checkpointService: AuditCheckpointService;
  checkpoint: SignedAuditCheckpoint;
  profileService: TrustProfileService;
}

export async function buildWorld(opts: { failTaskIds?: string[] } = {}): Promise<World> {
  const clock = { now: NOW_UNIX };

  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const auditorSigner = withDid(LocalSigner.generate(), AUDITOR_DID);
  const agentSigner = withDid(LocalSigner.generate(), AGENT_DID);
  const evilSigner = withDid(LocalSigner.generate(), EVIL_DID);
  const anchorSigner = withDid(LocalSigner.generate(), ANCHOR_DID);

  const resolverCore = new InMemoryDidResolver([
    didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
    didDocumentForJwk(AUDITOR_DID, await auditorSigner.publicKey()),
    didDocumentForJwk(ANCHOR_DID, await anchorSigner.publicKey()),
    didDocumentForJwk(AGENT_DID, await agentSigner.publicKey()),
    didDocumentForJwk(EVIL_DID, await evilSigner.publicKey()),
    didDocumentForJwk(REFUND_AGENT_DID, await LocalSigner.generate().publicKey()),
  ]);
  const resolver = new MultiDidResolver([resolverCore]);

  const statusStore = new InMemoryStatusListStore();
  const statusManager = new StatusListManager(statusStore, { clock: () => clock.now });
  const revListId = 'https://acme.example/status/rev/1';
  await statusManager.createList({ id: revListId, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 4096 });
  const audListId = 'https://audit.acme.example/status/rev/1';
  await statusManager.createList({ id: audListId, purpose: 'revocation', controllerDid: AUDITOR_DID, sizeBits: 4096 });
  const nextStatusIndex = (listId: string = revListId): Promise<number> => statusManager.assignIndex(listId);

  const issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  const auditorIssuer = new CredentialIssuer(auditorSigner, { issuerDid: AUDITOR_DID });

  const trustStore = new InMemoryIssuerTrustStore()
    .trust(ORG_DID, 'AgentDelegationCredential')
    .trust(ORG_DID, 'AgentMembershipCredential')
    .trust(ORG_DID, 'AgentAttestationCredential')
    // The auditor may SIGN attestation credentials the verifier accepts;
    // whether a given attestation TYPE from it is trusted is a separate,
    // issuer+TYPE-scoped decision (attestationTrust).
    .trust(AUDITOR_DID, 'AgentAttestationCredential');
  // NOTE: EVIL_DID is trusted for NOTHING.

  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore,
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
  });

  const attestationStore = new InMemoryAttestationStore({ clock: () => clock.now });
  const agentCredentialStore = new InMemoryAgentCredentialStore({ clock: () => clock.now });
  const attestationTrust = new InMemoryAttestationTrustPolicy();

  const replayProtector = new ReplayProtector(new InMemoryReplayStore({ clock: () => clock.now }));
  const policyResult = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
  if (!policyResult.ok) throw new Error(`policy load failed: ${policyResult.detail}`);

  const auditLog = new InMemoryAuditLog({
    idFactory: (() => {
      let n = 0;
      return () => `rcpt_${String(++n).padStart(6, '0')}`;
    })(),
  });
  const executor = new DemoRefundExecutor({ failTaskIds: opts.failTaskIds });
  const gatewayDeps: TrustGatewayDeps = {
    didResolver: resolver,
    verifier,
    replayProtector,
    policyEngine: policyResult.engine,
    auditLog,
    executor,
    streamId: STREAM,
    clock: () => clock.now,
  };

  const checkpointService = new AuditCheckpointService(anchorSigner);
  const anchorCheckpoint = async (): Promise<SignedAuditCheckpoint> =>
    checkpointService.issue({
      checkpointId: 'ckpt_profile_0001',
      streamId: STREAM,
      receipts: await auditLog.readStream(STREAM),
      issuedAt: '2026-09-15T12:00:00Z',
    });
  const checkpoint = await anchorCheckpoint();

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

  return {
    clock,
    resolver,
    resolverCore,
    issuer,
    auditorIssuer,
    orgSigner,
    auditorSigner,
    agentSigner,
    evilSigner,
    verifier,
    trustStore,
    attestationTrust,
    attestationStore,
    agentCredentialStore,
    statusManager,
    revListId,
    audListId,
    nextStatusIndex,
    gateway: new TrustGateway(gatewayDeps),
    gatewayDeps,
    executor,
    auditLog,
    checkpointService,
    checkpoint,
    profileService,
  };
}

// ------------------------------------------------------------ helpers

export function statusEntry(listId: string, index: number) {
  return {
    id: `${listId}#${index}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation' as const,
    statusListIndex: String(index),
    statusListCredential: listId,
  };
}

export async function statusIndexOf(jws: string): Promise<number> {
  const payload = JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8')) as {
    vc: { credentialStatus: { statusListIndex: string } };
  };
  return Number(payload.vc.credentialStatus.statusListIndex);
}

/** Issue one delegation credential for the agent through the org issuer. */
export async function issueDelegation(
  world: World,
  opts: {
    subject?: string;
    validFrom?: number;
    validUntil?: number;
    actions?: string[];
    issuer?: 'org' | 'evil';
  } = {},
): Promise<{ jws: string; statusIndex: number }> {
  const statusIndex = await world.nextStatusIndex();
  const issuer =
    opts.issuer === 'evil' ? new CredentialIssuer(world.evilSigner, { issuerDid: EVIL_DID }) : world.issuer;
  const { jws } = await issuer.issueDelegation({
    subjectDid: opts.subject ?? AGENT_DID,
    authority: {
      actions: opts.actions ?? ['refund:create'],
      resources: ['order:*'],
      audience: [REFUND_AGENT_DID],
      limits: { amount: 500, currency: 'SAR' },
      delegationDepth: 0,
    },
    validFrom: opts.validFrom ?? NOW_UNIX - 3600,
    validUntil: opts.validUntil ?? NOW_UNIX + 86_400,
    credentialStatus: statusEntry(world.revListId, statusIndex),
  });
  return { jws, statusIndex };
}

/** Issue one attestation credential. Default issuer: the auditor. */
export async function issueAttestation(
  world: World,
  opts: {
    subject?: string;
    type?: 'CAPABILITY_ENDORSEMENT' | 'SECURITY_REVIEW' | 'OPERATIONAL_APPROVAL';
    statement?: 'ENDORSED' | 'APPROVED' | 'OBSERVED';
    validFrom?: number;
    validUntil?: number;
    issuer?: 'org' | 'auditor' | 'evil';
    statusIndex?: number;
    /** Override the status list id (attack simulations). */
    statusListId?: string;
  } = {},
): Promise<{ jws: string; statusIndex: number }> {
  const issuerDid = opts.issuer === 'org' ? ORG_DID : opts.issuer === 'evil' ? EVIL_DID : AUDITOR_DID;
  // Status-binding rule (Step 6E): the status list must be controlled by
  // the credential issuer — auditor attestations revoke on the AUDITOR list.
  const listId = opts.statusListId ?? (issuerDid === AUDITOR_DID ? world.audListId : world.revListId);
  const statusIndex = opts.statusIndex ?? (await world.nextStatusIndex(listId));
  const issuer =
    opts.issuer === 'org'
      ? world.issuer
      : opts.issuer === 'evil'
        ? new CredentialIssuer(world.evilSigner, { issuerDid: EVIL_DID })
        : world.auditorIssuer;
  const { jws } = await issuer.issueAttestation({
    subjectDid: opts.subject ?? AGENT_DID,
    attestation: {
      type: opts.type ?? 'CAPABILITY_ENDORSEMENT',
      domain: 'refunds',
      statement: opts.statement ?? 'ENDORSED',
    },
    validFrom: opts.validFrom ?? NOW_UNIX - 3600,
    validUntil: opts.validUntil ?? NOW_UNIX + 86_400,
    credentialStatus: statusEntry(listId, statusIndex),
  });
  return { jws, statusIndex };
}
