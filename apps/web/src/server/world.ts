import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalSigner, withDid, type Signer } from '@agent-trust/crypto';
import { InMemoryDidResolver, MultiDidResolver, didDocumentForJwk, type DidDocument } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import {
  BitstringStatusChecker,
  InMemoryAgentQuarantineStore,
  InMemoryStatusListStore,
  StatusListManager,
} from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import { AuditCheckpointService, InMemoryAuditLog, verifyAuditAgainstCheckpoint, verifyAuditChain, verifyCheckpointSignature, type ActionReceipt, type SignedAuditCheckpoint } from '@agent-trust/audit';
import { InMemoryAgentCredentialStore, InMemoryAttestationStore, InMemoryAttestationTrustPolicy, TrustProfileService } from '@agent-trust/trust-profile';
import { DemoRefundExecutor } from '@agent-trust/gateway';
import { TrustGateway, createTaskRequest, type GatewayResult } from '@agent-trust/gateway';

import {
  identityMode,
  loadLiveIdentities,
  LiveDidWebResolver,
  verifySelfResolution,
} from './identity';

/**
 * STEP 14 — the single deterministic demo world (14U). One module, one
 * lazily-built instance for the server process. The dashboard is a VIEW
 * over this: every decision comes out of the REAL gateway/pipeline —
 * nothing in this layer reimplements authorization, and no trust logic
 * ever runs in the browser.
 *
 * STEP 16 — deployment modes: DEMO_IDENTITY_MODE=web turns org/support/
 * refund into REAL did:web identities (stable keys from deployment
 * secrets, documents resolved over public HTTPS by the hardened Step 12
 * resolver; misconfiguration fails startup, never silently falls back).
 * DEMO_REDIS_URL moves replay to the atomic Redis store (also fail-
 * startup if configured-but-unreachable). Audit log, demo executor,
 * status/quarantine/attestation stores remain process-local single-
 * replica state — the deployment pins replicas=1 and the UI labels this
 * honestly as the Challenge Demo Environment.
 */

export const NOW = 1_789_473_600; // 2026-09-15T12:00:00Z — frozen demo clock
export const ORG_DID = 'did:web:acme.example:org';
export const SUPPORT_DID = 'did:web:agents.acme.example:support-1';
export const REFUND_DID = 'did:web:payments.example:refund-agent';
export const EVIL_DID = 'did:web:evil.example:agent';
export const AUDITOR_DID = 'did:web:audit.acme.example:auditor';
export const ANCHOR_DID = 'did:web:audit.acme.example:anchor';
export const STREAM = 'acme-demo';

/**
 * Repo-root resolution that survives BOTH dev (`import.meta.url` under
 * apps/web/src/server) and production server bundles (chunks emitted under
 * .next/server/**). Precedence: explicit env → walk up from module/cwd
 * looking for artifacts/policy/policy.wasm → cwd.
 */
function findRepoRoot(): string {
  const candidates = [process.env.AGENT_TRUST_REPO_ROOT, dirname(fileURLToPath(import.meta.url)), process.cwd()];
  for (const start of candidates) {
    if (start === undefined || start === '') continue;
    let dir = start;
    for (let up = 0; up < 8; up++) {
      const candidate = join(dir, 'artifacts', 'policy', 'policy.wasm');
      if (existsSync(candidate)) return dir;
      dir = resolve(dir, '..');
    }
  }
  return process.cwd();
}

const REPO_ROOT = findRepoRoot();
export const ATTACKS_DIR = join(REPO_ROOT, 'artifacts', 'attacks');
const WASM_PATH = join(REPO_ROOT, 'artifacts/policy/policy.wasm');
const MANIFEST_PATH = join(REPO_ROOT, 'artifacts/policy/manifest.json');

export const AGENT_LABELS: Record<string, string> = {
  [SUPPORT_DID]: 'SupportAgent',
  [REFUND_DID]: 'RefundAgent',
  [ORG_DID]: 'AcmeOrg (issuer)',
  [AUDITOR_DID]: 'AcmeAudit (auditor)',
  [EVIL_DID]: 'EvilAgent',
};

export interface DemoWorld {
  gateway: TrustGateway;
  auditLog: InMemoryAuditLog;
  executor: DemoRefundExecutor;
  resolver: MultiDidResolver;
  verifier: CredentialVerifier;
  attestationStore: InMemoryAttestationStore;
  agentCredentialStore: InMemoryAgentCredentialStore;
  statusManager: StatusListManager;
  revListId: string;
  quarantine: InMemoryAgentQuarantineStore;
  supportSigner: Signer;
  evilSigner: Signer;
  orgSigner: Signer;
  primaryDelegationJws: string;
  /** Re-anchor the signed checkpoint over the CURRENT chain head. */
  anchor: () => Promise<SignedAuditCheckpoint>;
  latestCheckpoint: SignedAuditCheckpoint | null;
  /** 'redis' when DEMO_REDIS_URL is live; 'in-memory' otherwise. */
  replayStoreKind: 'redis' | 'in-memory';
  /** 'web' when org/support/refund are REAL did:web identities. */
  identityMode: 'fixture' | 'web';
  /** dids:web:  live org/support/refund DIDs; fixture: the demo fixtures. */
  dids: Record<'org' | 'support' | 'refund', string>;
  /** Live mode: the public documents the deployment serves (never keys). */
  liveDocuments: DidDocument[];
}

// Next.js may evaluate route bundles in separate module graphs — anchor the
// demo world on globalThis so every route shares ONE world (one gateway,
// one audit chain), as a deployed single-process server would.
declare global {
  // eslint-disable-next-line no-var
  var __agentTrustDemoWorld: Promise<DemoWorld> | undefined;
}

export function demoWorld(): Promise<DemoWorld> {
  globalThis.__agentTrustDemoWorld ??= buildDemoWorld();
  // A failed build must not poison the singleton: the next request retries
  // (transient Redis/HTTPS hiccups recover; config errors fail again with
  // the same machine-readable message).
  globalThis.__agentTrustDemoWorld.catch(() => {
    globalThis.__agentTrustDemoWorld = undefined;
  });
  return globalThis.__agentTrustDemoWorld;
}

async function buildDemoWorld(): Promise<DemoWorld> {
  // STEP 16 — identity modes. 'web' (public deployment): org/support/
  // refund are REAL did:web identities whose private keys come only from
  // deployment secrets (stable across restarts) and whose documents are
  // fetched over public HTTPS by the hardened Step 12 resolver — any
  // failure throws HERE, failing startup loudly (16H: no silent fallback).
  // 'fixture' (local dev): in-memory did:web-named fixtures. evil/auditor/
  // anchor remain fixtures in BOTH modes — they exist to demonstrate
  // denial and evidence-scoping, never to represent real actors.
  const mode = identityMode();
  const live = mode === 'web' ? await loadLiveIdentities() : null;
  const orgDid = live?.orgDid ?? ORG_DID;
  const supportDid = live?.supportDid ?? SUPPORT_DID;
  const refundDid = live?.refundDid ?? REFUND_DID;

  const evilSigner = withDid(LocalSigner.generate(), EVIL_DID);
  const auditorSigner = withDid(LocalSigner.generate(), AUDITOR_DID);
  const anchorSigner = withDid(LocalSigner.generate(), ANCHOR_DID);
  const orgSigner = live?.orgSigner ?? withDid(LocalSigner.generate(), ORG_DID);
  const supportSigner = live?.supportSigner ?? withDid(LocalSigner.generate(), SUPPORT_DID);
  const refundSignerPub = live
    ? await live.refundSigner.publicKey()
    : await LocalSigner.generate().publicKey();

  const inMemory = new InMemoryDidResolver([
    didDocumentForJwk(EVIL_DID, await evilSigner.publicKey()),
    didDocumentForJwk(AUDITOR_DID, await auditorSigner.publicKey()),
    didDocumentForJwk(ANCHOR_DID, await anchorSigner.publicKey()),
  ]);
  if (live === null) {
    inMemory.register(didDocumentForJwk(ORG_DID, await orgSigner.publicKey()));
    inMemory.register(didDocumentForJwk(SUPPORT_DID, await supportSigner.publicKey()));
    inMemory.register(didDocumentForJwk(REFUND_DID, refundSignerPub));
  } else {
    // Live mode: prove the public documents resolve over real HTTPS BEFORE
    // the world exists (16H). The live resolver is consulted FIRST so the
    // three real DIDs ride the hardened transport; everything else falls
    // through to the fixture registry.
    await verifySelfResolution(live);
  }
  const resolver = new MultiDidResolver(
    live !== null ? [new LiveDidWebResolver(live), inMemory] : [inMemory],
  );

  const statusStore = new InMemoryStatusListStore();
  const statusManager = new StatusListManager(statusStore, { clock: () => NOW });
  // 65,536 slots: the public demo is multi-judge — every 'revoked' click
  // leases a fresh index and revokes it; the primary credential's slot is
  // leased once at startup and never revoked (14W isolation preserved at
  // any click volume a challenge window can produce).
  const revListId = 'https://acme.example/status/rev/1';
  await statusManager.createList({ id: revListId, purpose: 'revocation', controllerDid: orgDid, sizeBits: 65_536 });
  const audListId = 'https://audit.acme.example/status/rev/1';
  await statusManager.createList({ id: audListId, purpose: 'revocation', controllerDid: AUDITOR_DID, sizeBits: 256 });

  const issuer = new CredentialIssuer(orgSigner, { issuerDid: orgDid });
  const auditorIssuer = new CredentialIssuer(auditorSigner, { issuerDid: AUDITOR_DID });

  const primaryIndex = await statusManager.assignIndex(revListId);
  const { jws: primaryDelegationJws } = await issuer.issueDelegation({
    subjectDid: supportDid,
    authority: {
      actions: ['refund:create'],
      resources: ['order:*'],
      audience: [refundDid],
      limits: { amount: 500, currency: 'SAR' },
      delegationDepth: 0,
    },
    validFrom: NOW - 3600,
    validUntil: NOW + 86_400,
    credentialStatus: {
      id: `${revListId}#${primaryIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(primaryIndex),
      statusListCredential: revListId,
    },
  });

  const trustStore = new InMemoryIssuerTrustStore()
    .trust(orgDid, 'AgentDelegationCredential')
    .trust(orgDid, 'AgentMembershipCredential')
    .trust(orgDid, 'AgentAttestationCredential')
    .trust(AUDITOR_DID, 'AgentAttestationCredential');

  const quarantine = new InMemoryAgentQuarantineStore();
  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore,
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
    quarantineStore: quarantine,
  });

  // DEMO_REDIS_URL (optional in dev, REQUIRED commitment in prod): the real
  // atomic SET NX PX replay store in deployment; in-memory stays the
  // zero-config default for local dev. If Redis is configured and
  // unreachable, startup FAILS (16H) — no silent downgrade.
  const { store: replayStore, kind: replayStoreKind } = await pickReplayStore();
  const replayProtector = new ReplayProtector(replayStore);
  const policy = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
  if (!policy.ok) {
    throw new Error(`policy artifact failed to load (${policy.reasonCode}): ${policy.detail}`);
  }
  const auditLog = new InMemoryAuditLog();
  const executor = new DemoRefundExecutor();

  const gateway = new TrustGateway({
    didResolver: resolver,
    verifier,
    replayProtector,
    policyEngine: policy.engine,
    auditLog,
    executor,
    streamId: STREAM,
    clock: () => NOW,
  });

  // Seed evidence for the profile: one trusted attestation and one vouch
  // from an untrusted issuer (shown as REJECTED — never aggregated).
  const attestationStore = new InMemoryAttestationStore({ clock: () => NOW });
  const agentCredentialStore = new InMemoryAgentCredentialStore({ clock: () => NOW });
  const attestationTrust = new InMemoryAttestationTrustPolicy().trust(AUDITOR_DID, 'SECURITY_REVIEW');
  const audIndex = await statusManager.assignIndex(audListId);
  const { jws: securityReviewJws } = await auditorIssuer.issueAttestation({
    subjectDid: supportDid,
    attestation: { type: 'SECURITY_REVIEW', domain: 'refunds', statement: 'APPROVED' },
    validFrom: NOW - 3600,
    validUntil: NOW + 86_400,
    credentialStatus: {
      id: `${audListId}#${audIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(audIndex),
      statusListCredential: audListId,
    },
  });
  await attestationStore.add(supportDid, securityReviewJws);
  // A self-vouch from an untrusted issuer (valid signature, no trust).
  const { jws: fakeVouchJws } = await new CredentialIssuer(evilSigner, { issuerDid: EVIL_DID }).issueAttestation({
    subjectDid: supportDid,
    attestation: { type: 'CAPABILITY_ENDORSEMENT', domain: 'refunds', statement: 'ENDORSED' },
    validFrom: NOW - 3600,
    validUntil: NOW + 86_400,
  });
  await attestationStore.add(supportDid, fakeVouchJws);
  await agentCredentialStore.add(supportDid, primaryDelegationJws);

  let latestCheckpoint: SignedAuditCheckpoint | null = null;
  const anchor = async (): Promise<SignedAuditCheckpoint> => {
    latestCheckpoint = await new AuditCheckpointService(anchorSigner).issue({
      checkpointId: `ckpt_web_${String(anchorCount++).padStart(4, '0')}`,
      streamId: STREAM,
      receipts: await auditLog.readStream(STREAM),
      issuedAt: '2026-09-15T12:00:00Z',
    });
    return latestCheckpoint;
  };
  let anchorCount = 0;
  await anchor();

  return {
    gateway,
    auditLog,
    executor,
    resolver,
    verifier,
    attestationStore,
    agentCredentialStore,
    statusManager,
    revListId,
    quarantine,
    supportSigner,
    evilSigner,
    orgSigner,
    primaryDelegationJws,
    replayStoreKind,
    identityMode: mode,
    dids: { org: orgDid, support: supportDid, refund: refundDid },
    liveDocuments: live?.documents ?? [],
    anchor,
    get latestCheckpoint() {
      return latestCheckpoint;
    },
  };
}

// ------------------------------------------------------------ profile

export interface ProfileSnapshot {
  profile: Awaited<ReturnType<TrustProfileService['build']>>;
}

/**
 * Build the TrustProfile against a FRESH checkpoint of the current chain
 * (the dashboard is a view: history integrity must reflect state NOW).
 */
export async function profileSnapshot(agentDid?: string): Promise<ProfileSnapshot> {
  const w = await demoWorld();
  const target =
    agentDid === undefined || agentDid === 'support' || agentDid === SUPPORT_DID || agentDid === w.dids.support
      ? w.dids.support
      : agentDid;
  const checkpoint = await w.anchor();
  const service = new TrustProfileService({
    didResolver: w.resolver,
    verifier: w.verifier,
    attestationStore: w.attestationStore,
    agentCredentialStore: w.agentCredentialStore,
    attestationTrust: new InMemoryAttestationTrustPolicy().trust(AUDITOR_DID, 'SECURITY_REVIEW'),
    auditLog: w.auditLog,
    auditCheckpoint: checkpoint,
    auditStreamId: STREAM,
    checkpointSignerDid: ANCHOR_DID,
  });
  const profile = await service.build(target, { now: NOW, context: { action: 'refund:create' } });
  return { profile };
}

async function pickReplayStore(): Promise<{
  store: import('@agent-trust/replay').ReplayStore;
  kind: 'redis' | 'in-memory';
}> {
  const url = process.env.DEMO_REDIS_URL;
  if (url === undefined || url === '') {
    return { store: new InMemoryReplayStore({ clock: () => NOW }), kind: 'in-memory' };
  }
  try {
    const { createClient } = await import('redis');
    const client = createClient({
      url,
      // Survive managed-Redis failovers / brief provider hiccups: keep
      // retrying (bounded backoff) and swallow transport errors into the
      // retry loop instead of killing the process — while requests during
      // the window still fail CLOSED via the store (REPLAY_PROTECTION_
      // UNAVAILABLE, never a silent in-memory fallback).
      socket: {
        reconnectStrategy: (retries) => (retries > 20 ? new Error('redis reconnect budget exhausted') : Math.min(2 ** Math.min(retries, 6) * 50, 4000)),
      },
    });
    client.on('error', () => {
      /* node-redis surfaces transport errors as events; without a listener
         they become uncaughtException and crash the server. */
    });
    await client.connect();
    await client.ping();
    const { RedisReplayStore } = await import('@agent-trust/replay');
    return { store: new RedisReplayStore(client, { clock: () => NOW }), kind: 'redis' };
  } catch (e) {
    // STEP 16H: a configured Redis is a COMMITMENT, not a hint — failing
    // startup is louder and safer than downgrading replay guarantees
    // mid-demo. (Runtime Redis errors keep failing closed per-request with
    // REPLAY_PROTECTION_UNAVAILABLE, proven by the integration suite.)
    // Step 16X: credentials inside the URL are scrubbed — this message can
    // surface through /api/demo/status detail.
    const scrubbed = String(e).replace(/(redis(?:s)?:\/\/)([^@/\s]*)@/gi, '$1***@');
    throw new Error(`DEMO_REDIS_URL unreachable (${scrubbed}) — refusing to start with a downgraded replay store`);
  }
}

// ------------------------------------------------------------ scenarios

export type PresetId =
  | 'valid-120'
  | 'over-5000'
  | 'spoof'
  | 'revoked'
  | 'replay'
  | 'quarantine'
  | 'wrong-audience'
  | 'tampered';

let taskCounter = 0;
/** Ref-count of in-flight quarantine presets (16U — concurrent judges). */
let evilQuarantineRuns = 0;
function nextTaskId(preset: string): string {
  // Fresh taskId AND a fresh proof (unique jti) on every intentional run
  // (14V) — ordinary button presses never look "broken by replay".
  return `web_${preset}_${Date.now().toString(36)}_${++taskCounter}`;
}

export interface EvaluationOutcome {
  result: GatewayResult;
  /** Receipts written by THIS run (decision ± outcome), newest last. */
  runReceipts: ActionReceipt[];
  /** For replay preset: the first (successful) run, then the replay. */
  firstResult?: GatewayResult;
  note?: string;
}

async function makeRequest(
  w: DemoWorld,
  opts: {
    preset: string;
    signer?: Signer;
    actor?: string;
    audience?: string;
    amount?: number;
    currency?: string;
    resource?: string;
    credentials?: string[];
  },
) {
  return createTaskRequest({
    signer: opts.signer ?? w.supportSigner,
    taskId: nextTaskId(opts.preset),
    actor: opts.actor ?? w.dids.support,
    audience: opts.audience ?? w.dids.refund,
    action: 'refund:create',
    resource: opts.resource ?? 'order:ORD-918',
    parameters: { amount: opts.amount ?? 120, currency: opts.currency ?? 'SAR' },
    credentials: opts.credentials ?? [w.primaryDelegationJws],
    now: NOW,
  });
}

/** The gateway names decision/outcome receipts rcpt_dec_<taskId> /
 * rcpt_out_<taskId> — match either the correlation field or that suffix. */
function receiptTaskOf(r: ActionReceipt): string | undefined {
  return r.body.correlation?.taskId ?? r.body.receiptId.match(/rcpt_(?:dec|out)_(.+)$/)?.[1];
}

async function receiptsByTask(w: DemoWorld, taskId: string): Promise<ActionReceipt[]> {
  const all = await w.auditLog.readStream(STREAM);
  return all.filter((r) => receiptTaskOf(r) === taskId);
}

export async function runPreset(preset: PresetId): Promise<EvaluationOutcome> {
  const w = await demoWorld();
  switch (preset) {
    case 'valid-120': {
      const req = await makeRequest(w, { preset: 'valid' });
      const result = await w.gateway.handleTask(req);
      return { result, runReceipts: await receiptsByTask(w, req.taskId) };
    }
    case 'over-5000': {
      const req = await makeRequest(w, { preset: 'over', amount: 5000 });
      const result = await w.gateway.handleTask(req);
      return { result, runReceipts: await receiptsByTask(w, req.taskId) };
    }
    case 'spoof': {
      // Evil signs with ITS OWN key but claims the Support DID — the
      // receipt trail stays clean because this dies at PoP, pre-audit.
      const req = await makeRequest(w, { preset: 'spoof', signer: w.evilSigner });
      const result = await w.gateway.handleTask(req);
      return { result, runReceipts: [], note: 'No receipt attributed to the victim — spoof denied before audit.' };
    }
    case 'revoked': {
      // Isolated credential (14W): the PRIMARY demo credential never dies.
      // Each click leases a fresh status index (list sized for multi-judge
      // use) — one judge's revocation cannot ruin another's scenario.
      const index = await w.statusManager.assignIndex(w.revListId);
      const { jws } = await new CredentialIssuer(w.orgSigner, { issuerDid: w.dids.org }).issueDelegation({
        subjectDid: w.dids.support,
        authority: { actions: ['refund:create'], resources: ['order:*'], audience: [w.dids.refund], limits: { amount: 500, currency: 'SAR' }, delegationDepth: 0 },
        validFrom: NOW - 3600,
        validUntil: NOW + 86_400,
        credentialStatus: { id: `${w.revListId}#${index}`, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: w.revListId },
      });
      await w.statusManager.revoke(w.revListId, index);
      const req = await makeRequest(w, { preset: 'revoked', credentials: [jws] });
      const result = await w.gateway.handleTask(req);
      return { result, runReceipts: [], note: 'Isolated credential revoked — primary demo credential unaffected.' };
    }
    case 'replay': {
      const req = await makeRequest(w, { preset: 'replay' });
      const firstResult = await w.gateway.handleTask(req);
      // The replay preset deliberately reuses the SAME signed proof bytes.
      const result = await w.gateway.handleTask(req);
      return {
        firstResult,
        result,
        runReceipts: await receiptsByTask(w, req.taskId),
        note: 'First run authorized; identical replay denied. Logical refunds: 1.',
      };
    }
    case 'quarantine': {
      // Multi-judge safe (16U): concurrent quarantine runs share the flag;
      // it is released only when the LAST in-flight quarantine run ends —
      // one judge's click can never release another's scenario mid-run.
      evilQuarantineRuns += 1;
      w.quarantine.quarantine(EVIL_DID, 'demo: emergency kill switch');
      const req = await makeRequest(w, { preset: 'quarantine', signer: w.evilSigner, actor: EVIL_DID });
      try {
        const result = await w.gateway.handleTask(req);
        return { result, runReceipts: [], note: 'Quarantined identity denied even with a valid proof; release restores normal evaluation.' };
      } finally {
        if (--evilQuarantineRuns === 0) w.quarantine.release(EVIL_DID);
      }
    }
    case 'wrong-audience': {
      const req = await makeRequest(w, { preset: 'audience', audience: EVIL_DID });
      const result = await w.gateway.handleTask(req);
      return { result, runReceipts: await receiptsByTask(w, req.taskId) };
    }
    case 'tampered': {
      // Sign 120 SAR, then mutate the received body to 5000 SAR — the PoP
      // digest check fails BEFORE the tampered value can reach policy.
      const req = await makeRequest(w, { preset: 'tampered', amount: 120 });
      req.parameters = { amount: 5000, currency: 'SAR' };
      const result = await w.gateway.handleTask(req);
      return { result, runReceipts: [], note: 'Policy never evaluated 5000 SAR — tampering caught at identity stage.' };
    }
  }
}

export interface CustomRunInput {
  actorLabel?: string;
  amount?: number;
  currency?: string;
  resource?: string;
  audienceLabel?: string;
}

export async function runCustom(input: CustomRunInput): Promise<EvaluationOutcome> {
  const w = await demoWorld();
  const req = await makeRequest(w, {
    preset: 'custom',
    amount: input.amount ?? 120,
    currency: input.currency ?? 'SAR',
    resource: input.resource ?? 'order:ORD-918',
  });
  const result = await w.gateway.handleTask(req);
  return { result, runReceipts: await receiptsByTask(w, req.taskId) };
}

// ------------------------------------------------------------ snapshots

export interface AuditSnapshot {
  receipts: ActionReceipt[];
  chain: Awaited<ReturnType<typeof verifyAuditChain>>;
  checkpoint: {
    id: string;
    sequence: number;
    signatureValid: boolean;
    chainMatches: boolean;
    headHash: string;
  };
}

export async function auditSnapshot(): Promise<AuditSnapshot> {
  const w = await demoWorld();
  const receipts = await w.auditLog.readStream(STREAM);
  const chain = verifyAuditChain(STREAM, receipts);
  const cp = await w.anchor();
  const signatureValid = await verifyCheckpointSignature({
    checkpoint: cp,
    didResolver: w.resolver,
    opts: { expectedSignerDid: ANCHOR_DID, now: NOW },
  });
  const anchored = verifyAuditAgainstCheckpoint({
    streamId: STREAM,
    receipts,
    checkpoint: cp,
    checkpointVerified: signatureValid,
  });
  return {
    receipts,
    chain,
    checkpoint: {
      id: cp.payload.checkpointId,
      sequence: cp.payload.sequence,
      signatureValid: signatureValid.valid,
      // Anchoring against a longer chain is EXPECTED as receipts accrue;
      // report both facts honestly.
      chainMatches: anchored.valid,
      headHash: cp.payload.headHash,
    },
  };
}


// ------------------------------------------------------------ DTO mapping

import type { DecisionDto, ReceiptDto } from '@/lib/dto';

/** Server-side sanitizer: identifiers, digests, decisions — never raw
 *  credentials, never key material (SECURITY section of Step 14). */
export function toDecisionDto(result: GatewayResult): DecisionDto {
  return {
    taskId: result.taskId,
    outcome: result.outcome,
    ...(result.effect !== undefined ? { effect: result.effect } : {}),
    reasonCodes: result.reasonCodes,
    stages: result.stages,
    ...(result.decisionReceiptId !== undefined ? { decisionReceiptId: result.decisionReceiptId } : {}),
    ...(result.executionReceiptId !== undefined ? { executionReceiptId: result.executionReceiptId } : {}),
  };
}

export function toReceiptDto(r: ActionReceipt): ReceiptDto {
  const body = r.body;
  return {
    sequence: body.sequence,
    recordedAt: body.recordedAt,
    actorDid: body.actor.did,
    action: body.request.action,
    resource: body.request.resource,
    ...(body.request.parameters?.amount !== undefined ? { amount: body.request.parameters.amount } : {}),
    ...(body.request.parameters?.currency !== undefined ? { currency: body.request.parameters.currency } : {}),
    effect: body.decision.effect,
    reasonCodes: body.decision.reasonCodes,
    ...(body.execution?.state !== undefined ? { executionState: body.execution.state } : {}),
    ...(body.correlation?.taskId !== undefined
      ? { taskId: body.correlation.taskId }
      : body.receiptId.match(/^rcpt_(?:dec|out)_(.+)$/)
        ? { taskId: body.receiptId.match(/^rcpt_(?:dec|out)_(.+)$/)![1] }
        : {}),
    eventHash: r.eventHash,
    receiptId: body.receiptId,
  };
}
