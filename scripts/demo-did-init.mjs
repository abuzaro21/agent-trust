#!/usr/bin/env node
/**
 * pnpm demo:did:init — one-time demo identity initialization (Step 12X).
 *
 * DEMO_DID_DOMAIN=trust.example.com [DEMO_DID_PATH=agents/support] \
 *   pnpm demo:did:init
 *
 * Generates (once, then reuses) a PRIVATE key per demo agent in the
 * gitignored .local/demo-keys/ and writes the PUBLIC did.json documents to
 * .local/did-host/ — the exact files to publish at the domain's HTTPS root.
 * Nothing private is ever written to the published output.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { jwkThumbprint } from '@agent-trust/crypto';

import {
  DEMO_AGENTS,
  DID_OUT_DIR,
  KEY_DIR,
  didFor,
  loadOrCreateAgentKey,
  pathToSegments,
  requireEnv,
  urlFor,
} from './demo-identity-lib.mjs';

const domain = requireEnv('DEMO_DID_DOMAIN');
// Optional explicit single-agent path; default layout supports both demo agents.
const singlePath = process.env.DEMO_DID_PATH;

const agents =
  singlePath !== undefined && singlePath !== ''
    ? [{ name: singlePath.split('/').filter(Boolean).pop() ?? 'agent', path: singlePath }]
    : DEMO_AGENTS;

console.log(`initializing demo did:web identities on ${domain}`);

for (const agent of agents) {
  const segments = pathToSegments(agent.path);
  const did = didFor(domain, segments);
  const { signer, created } = loadOrCreateAgentKey(agent.name, did);
  const jwk = await signer.publicKey();
  const kid = `${did}#${jwkThumbprint(jwk)}`;

  const document = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    verificationMethod: [
      { id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk },
    ],
    authentication: [kid],
  };

  const outFile = join(DID_OUT_DIR, ...segments, 'did.json');
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, `${JSON.stringify(document, null, 2)}\n`);

  console.log(`\n  DID:        ${did}`);
  console.log(`  resolves:   ${urlFor(did)}`);
  console.log(`  kid:        ${kid}`);
  console.log(`  key:        ${created ? 'generated (private: .local/demo-keys/ — gitignored, NOT for publication)' : 'reused (stable identity across runs)'}`);
  console.log(`  document:   ${outFile.replace(/\\/g, '/')}  (public key material only)`);
}

console.log('\nnext: publish the .local/did-host/ tree at the HTTPS root of');
console.log(`${domain} so each did.json file is served at its derived URL.`);
console.log('then run: DEMO_DID_DOMAIN=' + domain + ' pnpm demo:e2e:web');
