#!/usr/bin/env node
/**
 * pnpm demo:e2e:web — LIVE did:web identity mode (Step 12AB).
 *
 * Unlike the deterministic demo:e2e (in-memory fixtures), this command runs
 * the SAME gateway/policy/audit stack but discovers every identity through
 * REAL HTTPS resolution of hosted DID documents, signing with the keys
 * initialized by `demo:did:init` (.local/demo-keys/ — stable across runs,
 * Step 12Z). No mock transports.
 *
 * Deployment-gated: requires DEMO_DID_DOMAIN pointing at a host that serves
 * the generated documents, and DEMO_DID_ALLOW_PRIVATE=1 only for a local
 * trusted test host. Without a configured public domain this exits 3 with
 * the setup instructions — that is a DEPLOYMENT gate, not a failure of the
 * resolver (deterministic transport tests cover CI).
 */
import { join } from 'node:path';

import { withDid, jwkThumbprint } from '@agent-trust/crypto';
import { MultiDidResolver, WebDidResolver } from '@agent-trust/did';
import { CredentialIssuer, CredentialVerifier, InMemoryIssuerTrustStore } from '@agent-trust/vc';
import { BitstringStatusChecker, InMemoryStatusListStore, StatusListManager } from '@agent-trust/status';
import { InMemoryReplayStore, ReplayProtector } from '@agent-trust/replay';
import { loadOpaWasmPolicyEngine } from '@agent-trust/policy';
import { InMemoryAuditLog } from '@agent-trust/audit';

import { DemoRefundExecutor } from '../packages/gateway/src/executor.js';
import { TrustGateway } from '../packages/gateway/src/gateway.js';
import { createTaskRequest } from '../packages/gateway/src/request.js';

import { NOW_UNIX, didFor, loadOrCreateAgentKey, pathToSegments, requireEnv } from './demo-identity-lib.mjs';

const ROOT = join(import.meta.dirname, '..');

const domain = process.env.DEMO_DID_DOMAIN;
if (domain === undefined || domain === '') {
  console.error('DEMO_DID_DOMAIN is required for live web mode.');
  console.error('This command is deployment-gated: publish the demo:did:init');
  console.error('documents on a real HTTPS host first. CI covers did:web');
  console.error('semantics with deterministic transport tests instead.');
  process.exit(3);
}

const ORG_DID = didFor(domain, pathToSegments('org'));
const SUPPORT_DID = didFor(domain, pathToSegments('agents/support'));
const REFUND_DID = didFor(domain, pathToSegments('agents/refund'));

const b = (s) => `\x1b[1m${s}\x1b[0m`;
const g = (s) => `\x1b[32m${s}\x1b[0m`;
const r = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

function mustLoadIdentity(name, did) {
  const loaded = loadOrCreateAgentKey(name, did, { allowCreate: false });
  if (loaded === null) {
    console.error(r(`identity "${name}" is not initialized under ${did}`));
    console.error(`run: DEMO_DID_DOMAIN=${domain} pnpm demo:did:init`);
    process.exit(3);
  }
  return withDid(loaded.signer, did);
}

console.log(b('agent-trust — LIVE did:web identity mode'));
console.log(dim(`identities: ${ORG_DID}  ${SUPPORT_DID}  → real HTTPS resolution`));

const orgSigner = mustLoadIdentity('org', ORG_DID);
const supportSigner = mustLoadIdentity('support', SUPPORT_DID);
const refundDid = REFUND_DID; // audience only — its key is hosted, not held

// REAL resolver: NodeHttpsDidWebClient + DNS + HTTPS. Allowlist pinned to
// the deployment domain (Step 12F). Local trusted test hosts need the env
// override, and nothing else bypasses private-address blocking.
const blockPrivate = process.env.DEMO_DID_ALLOW_PRIVATE !== '1';
const webResolver = new WebDidResolver({
  networkPolicy: { allowedHosts: [domain.replace(/%3A\d+$/, '').split(':')[0]], blockPrivateNetworks: blockPrivate },
  timeoutMs: 10_000,
});
const resolver = new MultiDidResolver([webResolver]);

const statusStore = new InMemoryStatusListStore();
const statusManager = new StatusListManager(statusStore, { clock: () => NOW_UNIX });
const revListId = `https://${domain.replace(/%3A\d+$/, '').split(':')[0]}/status/rev/1`;
await statusManager.createList({ id: revListId, purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 64 });
const delegationIndex = await statusManager.assignIndex(revListId);

// One cold-resolution timing observation (non-gating, Step 12 Performance).
const t0 = performance.now();
const orgDoc = await webResolver.resolve(ORG_DID, { noCache: true });
const coldMs = (performance.now() - t0).toFixed(1);
if (orgDoc.didDocument === null) {
  console.error(r(`cold resolution of ${ORG_DID} failed: ${orgDoc.didResolutionMetadata.error ?? orgDoc.didResolutionMetadata.message}`));
  console.error('publish the demo:did:init documents on this host first.');
  process.exit(1);
}
const t1 = performance.now();
await webResolver.resolve(ORG_DID);
const warmMs = (performance.now() - t1).toFixed(1);
console.log(dim(`identity discovery: cold ${coldMs} ms (NETWORK) → warm ${warmMs} ms (CACHE) — crypto verification unchanged`));

const issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
const { jws: delegationJws } = await issuer.issueDelegation({
  subjectDid: SUPPORT_DID,
  authority: {
    actions: ['refund:create'],
    resources: ['order:*'],
    audience: [refundDid],
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
});

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
  replayProtector: new ReplayProtector(new InMemoryReplayStore({ clock: () => NOW_UNIX })),
  policyEngine: policy.engine,
  auditLog,
  executor,
  streamId: 'acme-web',
  clock: () => NOW_UNIX,
});

async function runTask(taskId, amount) {
  const request = await createTaskRequest({
    signer: supportSigner,
    taskId,
    actor: SUPPORT_DID,
    audience: refundDid,
    action: 'refund:create',
    resource: 'order:ORD-918',
    parameters: { amount, currency: 'SAR' },
    credentials: [delegationJws],
    now: NOW_UNIX,
  });
  return gateway.handleTask(request);
}

const ok = await runTask('web_demo_120', 120);
console.log(`  120 SAR  → ${ok.outcome === 'AUTHORIZED' ? g('ALLOW + executed') : r(ok.outcome)}`);
const over = await runTask('web_demo_5000', 5000);
console.log(`  5000 SAR → ${over.effect === 'DENY' ? r(`DENY (${over.reasonCodes.join(', ')})`) : g(over.outcome)}`);

if (ok.outcome !== 'AUTHORIZED' || over.effect !== 'DENY') {
  console.error(r('live web mode produced unexpected decisions'));
  process.exit(1);
}
console.log(`\n${b('live mode complete')} — same policy semantics; identity discovery via DNS+HTTPS only.\n`);
