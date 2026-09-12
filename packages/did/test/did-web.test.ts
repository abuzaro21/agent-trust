import { describe, expect, it } from 'vitest';

import { DidWebResolver, didWebToUrl } from '../src/index.js';

describe('didWebToUrl', () => {
  it('maps a domain-only DID to .well-known', () => {
    expect(didWebToUrl('did:web:example.com').toString()).toBe(
      'https://example.com/.well-known/did.json',
    );
  });

  it('maps path components to directories ending in did.json', () => {
    expect(didWebToUrl('did:web:agents.acme.example:refund-1').toString()).toBe(
      'https://agents.acme.example/refund-1/did.json',
    );
  });

  it('decodes an encoded port', () => {
    expect(didWebToUrl('did:web:example.com%3A8443').toString()).toBe(
      'https://example.com:8443/.well-known/did.json',
    );
  });

  it('rejects query and fragment characters (resolution-abuse guard)', () => {
    expect(() => didWebToUrl('did:web:example.com?x=1')).toThrow();
    expect(() => didWebToUrl('did:web:example.com#frag')).toThrow();
  });
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/did+json' },
  });
}

const DOC = {
  id: 'did:web:agents.acme.example:refund-1',
  verificationMethod: [
    {
      id: 'did:web:agents.acme.example:refund-1#key-1',
      type: 'JsonWebKey2020',
      controller: 'did:web:agents.acme.example:refund-1',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'BBBB' },
    },
  ],
};

describe('DidWebResolver', () => {
  it('resolves a hosted DID document via injectable fetch', async () => {
    const fetches: string[] = [];
    const resolver = new DidWebResolver({
      fetchImpl: async (input, init) => {
        fetches.push(String(input));
        return jsonResponse(DOC);
      },
    });
    const result = await resolver.resolve('did:web:agents.acme.example:refund-1');
    expect(result.didDocument).toEqual(DOC);
    expect(fetches).toEqual(['https://agents.acme.example/refund-1/did.json']);
  });

  it('maps 404 to notFound', async () => {
    const resolver = new DidWebResolver({
      fetchImpl: async () => new Response('gone', { status: 404 }),
    });
    const result = await resolver.resolve('did:web:missing.example');
    expect(result.didResolutionMetadata.error).toBe('notFound');
  });

  it('maps non-JSON bodies to representationNotSupported', async () => {
    const resolver = new DidWebResolver({
      fetchImpl: async () => new Response('<html>not json</html>', { status: 200 }),
    });
    const result = await resolver.resolve('did:web:example.com');
    expect(result.didResolutionMetadata.error).toBe('representationNotSupported');
  });

  it('rejects a body without an id string', async () => {
    const resolver = new DidWebResolver({
      fetchImpl: async () => jsonResponse({ hello: 'world' }),
    });
    const result = await resolver.resolve('did:web:example.com');
    expect(result.didResolutionMetadata.error).toBe('representationNotSupported');
  });

  it('maps fetch failure (timeout) to internalError — never throws into the caller', async () => {
    const resolver = new DidWebResolver({
      timeoutMs: 20,
      fetchImpl: (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new Error('aborted')),
          );
        }),
    });
    const result = await resolver.resolve('did:web:slow.example');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('internalError');
  });
});

describe('end-to-end identity loop: signer → did:key → resolve → PoP', () => {
  it('verifies a proof with the key resolved from the DID the proof claims', async () => {
    const { LocalSigner, jwkThumbprint, createProof, requestBodyDigestOf, verifyProof } =
      await import('@agent-trust/crypto');
    const { DidKeyResolver, MultiDidResolver, didKeyFromPublicKeyJwk } = await import(
      '../src/index.js'
    );

    // 1. Agent generates a key; its DID derives from the public key itself.
    const signer = LocalSigner.generate();
    const jwk = await signer.publicKey();
    const did = didKeyFromPublicKeyJwk(jwk);
    const kid = `${did}#${jwkThumbprint(jwk)}`;

    // 2. Agent signs a request proof bound to this exact body + endpoint.
    const body = { actor: did, action: 'refund:create', amount: 120 };
    const htu = 'https://trust-gateway.internal/v1/trust/evaluate';
    const proof = {
      ...(await createProof(signer, {
        htu,
        requestBodyDigest: requestBodyDigestOf(body),
        jti: 'jti-e2e-0123456789ab',
        iat: 1_757_800_000,
        exp: 1_757_800_300,
      })),
      kid,
    };

    // 3. Gateway resolves kid → verification method → public JWK, no trust
    //    in anything the request says about itself.
    const multi = new MultiDidResolver([new DidKeyResolver()]);
    const resolved = await multi.resolveVerificationMethod(kid);
    expect(resolved.ok).toBe(true);
    if (!resolved.ok || !resolved.method.publicKeyJwk) {
      throw new Error('resolution failed');
    }

    // 4. Proof verifies against the RESOLVED key.
    const verification = verifyProof({
      proof,
      publicJwk: resolved.method.publicKeyJwk,
      htu,
      requestBodyDigest: requestBodyDigestOf(body),
      now: 1_757_800_010,
    });
    expect(verification).toEqual({ valid: true });

    // 5. Spoofing: an evil agent claims the same DID but signs with its own
    //    key — verification against the RESOLVED key must fail.
    const evil = LocalSigner.generate();
    const evilProof = await createProof(evil, {
      htu,
      requestBodyDigest: requestBodyDigestOf(body),
      jti: 'jti-evil-0123456789ab',
      iat: 1_757_800_000,
      exp: 1_757_800_300,
    });
    const evilVerification = verifyProof({
      proof: evilProof,
      publicJwk: resolved.method.publicKeyJwk,
      htu,
      requestBodyDigest: requestBodyDigestOf(body),
      now: 1_757_800_010,
    });
    expect(evilVerification).toEqual({ valid: false, error: 'PROOF_SIGNATURE_INVALID' });
  });
});
