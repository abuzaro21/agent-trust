#!/usr/bin/env node
/**
 * pnpm demo:did:resolve <did> — live did:web resolution, real network
 * (Step 12AA). Deterministic output lines for demos/debugging:
 *
 *   DID / Resolution URL / Transport / Source / Document ID /
 *   Verification methods / Supported ES256 key / Result
 */
import { WebDidResolver, didWebToUrl, validatePublicJwk } from '@agent-trust/did';

const did = process.argv[2];
if (!did || !did.startsWith('did:web:')) {
  console.error('usage: pnpm demo:did:resolve did:web:<host>[:<path>...]');
  process.exit(2);
}

const resolver = new WebDidResolver({
  timeoutMs: 8_000,
  // Public demo hosts only: the deployment domain is the allowlist entry.
  networkPolicy:
    process.env.DEMO_DID_ALLOW_PRIVATE === '1'
      ? { blockPrivateNetworks: false }
      : { blockPrivateNetworks: true },
});

const line = (k, v) => console.log(`${k.padEnd(20)} ${v}`);

line('DID', did);
try {
  line('Resolution URL', didWebToUrl(did).toString());
} catch (e) {
  line('Result', `INVALID_DID (${e.message})`);
  process.exit(1);
}
line('Transport', 'HTTPS');

const hadCache = resolver.peekCache(did) !== undefined;
const result = await resolver.resolve(did);
line('Source', hadCache ? 'CACHE' : 'NETWORK');

if (result.didDocument === null) {
  line('Result', `FAILED (${result.didResolutionMetadata.error ?? 'internal'}${result.didResolutionMetadata.message ? `: ${result.didResolutionMetadata.message}` : ''})`);
  process.exit(1);
}

line('Document ID', result.didDocument.id === did ? 'MATCH' : 'MISMATCH');
const methods = result.didDocument.verificationMethod ?? [];
line('Verification methods', String(methods.length));

const supported = methods.filter((m) => {
  const v = validatePublicJwk(m.publicKeyJwk ?? {});
  return v.ok && typeof m.id === 'string' && m.id.startsWith(`${did}#`);
});
line('Supported ES256 key', supported.length > 0 ? 'PASS' : 'NONE');
line('Result', 'RESOLVED');
for (const m of supported) {
  console.log(`  ${m.id}`);
}
