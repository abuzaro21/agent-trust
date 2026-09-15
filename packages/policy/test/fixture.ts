import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { PolicyManifest } from '../src/index.js';

/**
 * Canonical Step 8 scenario fixtures — shared by the engine, parity,
 * property, and composition tests.
 */

export const NOW = '2026-09-15T12:00:00Z';

export const SUPPORT_AGENT_DID = 'did:web:agents.acme.example:support-1';
export const REFUND_AGENT_DID = 'did:web:payments.example:refund-agent';
export const ORG_DID = 'did:web:acme.example:org';

export const CASE_A_ALLOW = {
  amount: 120,
  currency: 'SAR',
} as const;

export const CASE_B_DENY = {
  amount: 5000,
  currency: 'SAR',
} as const;

/** The VerifiedFacts shape the PDP accepts (mirror of the schema). */
export interface VerifiedFactsFixture {
  actor: { did: string; controller?: string };
  request: {
    action: string;
    resource: string;
    audience: string;
    parameters?: { amount?: number; currency?: string };
  };
  identity: { proofVerified: true };
  credential: {
    verified: true;
    issuer: string;
    issuerTrusted: true;
    types: string[];
  };
  authority: {
    actions: string[];
    resources: string[];
    audience?: string[];
    limits?: { amount?: number; currency?: string; perDay?: number };
    validFrom?: string;
    validUntil?: string;
  };
  status: { credentialActive: true; quarantined: false };
  replay: { checked: true; claimed: true };
  context: { now: string };
}

export function canonicalPolicyInput(opts: {
  action?: string;
  resource?: string;
  audience?: string;
  amount?: number;
  currency?: string;
  authority?: Partial<VerifiedFactsFixture['authority']>;
  now?: string;
}): VerifiedFactsFixture {
  const authority: VerifiedFactsFixture['authority'] = {
    actions: ['refund:create'],
    resources: ['order:*'],
    audience: [REFUND_AGENT_DID],
    limits: { amount: 500, currency: 'SAR' },
    ...opts.authority,
  };
  return {
    actor: { did: SUPPORT_AGENT_DID, controller: ORG_DID },
    request: {
      action: opts.action ?? 'refund:create',
      resource: opts.resource ?? 'order:ORD-918',
      audience: opts.audience ?? REFUND_AGENT_DID,
      parameters: { amount: opts.amount ?? CASE_A_ALLOW.amount, currency: opts.currency ?? 'SAR' },
    },
    identity: { proofVerified: true },
    credential: {
      verified: true,
      issuer: ORG_DID,
      issuerTrusted: true,
      types: ['VerifiableCredential', 'AgentDelegationCredential'],
    },
    authority,
    status: { credentialActive: true, quarantined: false },
    replay: { checked: true, claimed: true },
    context: { now: opts.now ?? NOW },
  };
}

export async function readPolicyArtifacts(): Promise<{
  wasm: Buffer;
  manifest: PolicyManifest;
}> {
  const artifactsDir = join(__dirname, '../../../artifacts/policy').replaceAll('\\', '/');
  const [wasm, manifestRaw] = await Promise.all([
    readFile(join(artifactsDir, 'policy.wasm')),
    readFile(join(artifactsDir, 'manifest.json'), 'utf8'),
  ]);
  return { wasm, manifest: JSON.parse(manifestRaw) as PolicyManifest };
}

export function loadPolicyArtifactsPaths(dirname: string): { WASM_PATH: string; MANIFEST_PATH: string } {
  return {
    WASM_PATH: join(dirname, '../../../artifacts/policy/policy.wasm').replaceAll('\\', '/'),
    MANIFEST_PATH: join(dirname, '../../../artifacts/policy/manifest.json').replaceAll('\\', '/'),
  };
}

/* -------------------------------------------------------------------------
 * Full trust-stack fixture (8R) — every layer is the REAL implementation.
 * ---------------------------------------------------------------------- */

import { LocalSigner, type Signer, withDid } from '@agent-trust/crypto';
import type { PublicJwk } from '@agent-trust/crypto';
import { InMemoryDidResolver as Resolver, didDocumentForJwk as docForJwk } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import {
  InMemoryAgentQuarantineStore,
  InMemoryStatusListStore,
  StatusListManager,
} from '@agent-trust/status';
import { ReplayProtector } from '@agent-trust/replay';
import { InMemoryReplayStore } from '@agent-trust/replay';
import {
  createProof,
  requestBodyDigestOf,
} from '@agent-trust/crypto';

export const NOW_UNIX = 1_757_944_800; // 2026-09-15T12:00:00Z (used across layers)
// NOTE: SUPPORT_AGENT_DID / REFUND_AGENT_DID / ORG_DID reuse the constants
// declared at the top of this file (single source of truth).
const REV_LIST_ID = 'https://acme.example/status/rev/1';

interface AgentKeyBundle {
  signer: Signer;
  jwk: PublicJwk;
  createProofBundle: (
    body: unknown,
    htu: string,
  ) => Promise<{ proof: import('@agent-trust/schemas').AgentProof; requestBodyDigest: string }>;
}

async function agentKey(did: string): Promise<AgentKeyBundle> {
  const signer = withDid(LocalSigner.generate(), did);
  const jwk = await signer.publicKey();
  return {
    signer,
    jwk,
    async createProofBundle(body: unknown, htu: string) {
      const requestBodyDigest = requestBodyDigestOf(body);
      const proof = await createProof(signer, {
        htu,
        requestBodyDigest,
        jti: `jti-${Math.random().toString(36).slice(2, 14)}-${Math.random().toString(36).slice(2, 14)}`,
        iat: NOW_UNIX - 5,
        exp: NOW_UNIX + 300,
      });
      return { proof, requestBodyDigest };
    },
  };
}

export interface TrustStackWorld {
  agentKeys: { supportAgent: AgentKeyBundle; refundAgent: AgentKeyBundle };
  resolver: Resolver;
  verifier: CredentialVerifier;
  quarantine: InMemoryAgentQuarantineStore;
  status: {
    manager: StatusListManager;
    revListId: string;
    delegationIndex: number;
  };
  replay: { store: InMemoryReplayStore; protector: ReplayProtector };
  delegationJws: string;
}

export async function buildTrustStackWorld(): Promise<TrustStackWorld> {
  // Organization (issuer) + agents with real keypairs and real DIDs.
  const orgSigner = withDid(LocalSigner.generate(), ORG_DID);
  const supportAgent = await agentKey(SUPPORT_AGENT_DID);
  const refundAgent = await agentKey(REFUND_AGENT_DID);

  // Real resolver holding the org + agents' documents.
  const resolver = new Resolver([
    docForJwk(ORG_DID, await orgSigner.publicKey()),
    docForJwk(SUPPORT_AGENT_DID, supportAgent.jwk),
    docForJwk(REFUND_AGENT_DID, refundAgent.jwk),
  ]);

  // Real status lists (revocation + suspension) via the manager.
  const statusStore = new InMemoryStatusListStore();
  const manager = new StatusListManager(statusStore, { clock: () => NOW_UNIX });
  await manager.createList({
    id: REV_LIST_ID,
    purpose: 'revocation',
    controllerDid: ORG_DID,
    sizeBits: 128,
  });

  // Issue the delegation credential WITH a live status entry, via the real issuer.
  const delegationIndex = await manager.assignIndex(REV_LIST_ID);
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
    validFrom: NOW_UNIX - 3_600,
    validUntil: NOW_UNIX + 86_400,
    credentialStatus: {
      id: `${REV_LIST_ID}#${delegationIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(delegationIndex),
      statusListCredential: REV_LIST_ID,
    },
  });

  // Real verifier with all gates wired.
  const trustStore = new InMemoryIssuerTrustStore().trust(ORG_DID, 'AgentDelegationCredential');
  const quarantine = new InMemoryAgentQuarantineStore();
  const { BitstringStatusChecker } = await import('@agent-trust/status');
  const verifier = new CredentialVerifier({
    didResolver: resolver,
    trustStore,
    statusChecker: new BitstringStatusChecker({ kind: 'store', store: statusStore }),
    quarantineStore: quarantine,
  });

  // Real replay stack.
  const replayStore = new InMemoryReplayStore({ clock: () => NOW_UNIX });
  const protector = new ReplayProtector(replayStore);

  return {
    agentKeys: { supportAgent, refundAgent },
    resolver,
    verifier,
    quarantine,
    status: { manager, revListId: REV_LIST_ID, delegationIndex },
    replay: { store: replayStore, protector },
    delegationJws,
  };
}
