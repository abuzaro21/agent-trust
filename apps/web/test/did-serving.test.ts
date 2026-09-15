import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { LocalSigner } from '@agent-trust/crypto';

import {
  didForSegments,
  didToRoute,
  loadLiveIdentities,
  parseKeySecret,
  type LiveIdentitySet,
} from '../src/server/identity';
import { GET as getDidDocument } from '../src/app/agents/[name]/did.json/route';

/**
 * STEP 16E/16F — public did:web document serving.
 *
 * The route must serve ONLY public material (the scan asserts no private
 * `d` field ever appears), at exactly the URLs the did:web method derives,
 * with bounded Cache-Control so emergency key rotation stays practical.
 */

const DOMAIN = 'did-host.test';

async function getDoc(name: string): Promise<{ status: number; json: unknown; headers: Headers }> {
  const res = await getDidDocument(new Request(`https://did-host.test/agents/${name}/did.json`), {
    params: Promise.resolve({ name }),
  });
  const headers = res.headers;
  let json: unknown;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { status: res.status, json, headers };
}

describe('did.json serving — fixture mode', () => {
  it('fixture mode exposes NO public documents (404)', async () => {
    const res = await getDoc('support');
    expect(res.status).toBe(404);
  });
});

describe('did.json serving — live web mode', () => {
  let live: LiveIdentitySet;

  beforeAll(async () => {
    process.env.DEMO_IDENTITY_MODE = 'web';
    process.env.DEMO_DID_DOMAIN = DOMAIN;
    process.env.DEMO_ORG_KEY_JSON = JSON.stringify(LocalSigner.generate().exportPrivateJwk());
    process.env.DEMO_SUPPORT_KEY_JSON = JSON.stringify(LocalSigner.generate().exportPrivateJwk());
    process.env.DEMO_REFUND_KEY_JSON = JSON.stringify(LocalSigner.generate().exportPrivateJwk());
    live = await loadLiveIdentities();
  });

  afterAll(() => {
    // Restore the process environment — later files in this worker must
    // still see default fixture mode.
    delete process.env.DEMO_IDENTITY_MODE;
    delete process.env.DEMO_DID_DOMAIN;
    delete process.env.DEMO_ORG_KEY_JSON;
    delete process.env.DEMO_SUPPORT_KEY_JSON;
    delete process.env.DEMO_REFUND_KEY_JSON;
  });

  it('serves each live identity at its derived did:web URL', async () => {
    for (const name of ['org', 'support', 'refund'] as const) {
      const did = didForSegments(DOMAIN, ['agents', name]);
      // Route file sits at /agents/[...path]/did.json — the static 'agents'
      // prefix is already consumed by the route itself.
      const { status, json, headers } = await getDoc(name);
      expect(status).toBe(200);
      const doc = json as { id?: string; verificationMethod?: { publicKeyJwk?: Record<string, unknown> }[] };
      expect(doc.id).toBe(did);
      expect(doc.verificationMethod?.[0]?.publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
      expect(headers.get('cache-control')).toContain('max-age=300');
      expect(headers.get('content-type')).toContain('did');
    }
  });

  it('never leaks private key material (scan for "d")', async () => {
    const { json } = await getDoc('support');
    const serialized = JSON.stringify(json);
    expect(serialized).not.toMatch(/"d"\s*:/);
    expect(serialized).not.toMatch(/"dp"|"dq"|"p"\s*:|"q"\s*:/);
    expect(serialized).not.toContain('privateKey');
  });

  it('served document is exactly the published LiveIdentitySet document', async () => {
    const supportDoc = live.documents.find((d) => d.id.includes('support'));
    const { json } = await getDoc('support');
    expect(json).toEqual(supportDoc);
  });

  it('unknown paths 404', async () => {
    const res = await getDoc('intruder');
    expect(res.status).toBe(404);
  });
});

describe('identity helpers', () => {
  it('didToRoute mirrors did:web URL derivation incl. prefixes', () => {
    expect(didToRoute('did:web:example.com')).toBe('/.well-known/did.json');
    expect(didToRoute(didForSegments('example.com', ['agents', 'support']))).toBe('/agents/support/did.json');
    expect(didToRoute(didForSegments('example.com', ['demo', 'agents', 'support']))).toBe(
      '/demo/agents/support/did.json',
    );
  });

  it('didForSegments encodes explicit ports as %3A', () => {
    expect(didForSegments('example.com:8443', ['agents', 'org'])).toBe(
      'did:web:example.com%3A8443:agents:org',
    );
  });

  it('parseKeySecret rejects non-P-256 or malformed secrets', () => {
    expect(() => parseKeySecret('{"kty":"RSA"}', 'did:web:x:agents:org')).toThrow(/P-256/);
    expect(() => parseKeySecret('not json', 'did:web:x:agents:org')).toThrow(/JSON/);
    const good = LocalSigner.generate();
    expect(() => parseKeySecret(JSON.stringify(good.exportPrivateJwk()), 'did:web:x:agents:org')).not.toThrow();
  });
});
