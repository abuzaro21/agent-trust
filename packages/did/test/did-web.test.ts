import { describe, expect, it } from 'vitest';

import {
  NodeHttpsDidWebClient,
  WebDidResolver,
  classifyAddress,
  didWebToUrl,
  parseDidWebIdentifier,
  validateDidWebDocument,
  validatePublicJwk,
  type DidWebHttpClient,
  type DidWebHttpResponse,
} from '../src/index.js';

/**
 * Step 12C — strict did:web parser. Deterministic rejection: what is
 * invalid stays invalid; WHATWG URL normalization never rescues it.
 */

describe('didWebToUrl derivation (12B)', () => {
  it('root DID → .well-known/did.json', () => {
    expect(didWebToUrl('did:web:example.com').toString()).toBe(
      'https://example.com/.well-known/did.json',
    );
  });

  it('path DID → <path>/did.json', () => {
    expect(didWebToUrl('did:web:trust.example.com:agents:support').toString()).toBe(
      'https://trust.example.com/agents/support/did.json',
    );
  });

  it('encoded port decodes exactly once', () => {
    expect(didWebToUrl('did:web:example.com%3A8443:agents:support').toString()).toBe(
      'https://example.com:8443/agents/support/did.json',
    );
  });

  it('URL derivation is HTTPS by construction', () => {
    expect(didWebToUrl('did:web:example.com').protocol).toBe('https:');
  });
});

describe('strict parser negative controls (12C)', () => {
  const rejects = (did: string) => expect(() => parseDidWebIdentifier(did)).toThrow();

  it('wrong DID method', () => {
    rejects('did:key:z6Mk');
    rejects('did:webvh:example.com');
  });
  it('empty host / empty identifier', () => {
    rejects('did:web:');
    rejects('did:web::agents:support');
  });
  it('IP literals (v4 and bracketed v6)', () => {
    rejects('did:web:127.0.0.1');
    rejects('did:web:10.0.0.1:agents');
    rejects('did:web:%5B%3A%3A1%5D');
  });
  it('invalid hostname (bad labels, hyphen edges, empty label)', () => {
    rejects('did:web:-example.com');
    rejects('did:web:example.com-');
    rejects('did:web:exam_ple.com');
    rejects('did:web:example..com');
    rejects('did:web:exam ple.com');
  });
  it('embedded credentials (@) and slashes', () => {
    rejects('did:web:user@example.com');
    rejects('did:web:example.com//evil');
    rejects('did:web:example.com/agents');
  });
  it('query and fragment', () => {
    rejects('did:web:example.com?x=1');
    rejects('did:web:example.com#frag');
  });
  it('control characters and backslashes', () => {
    rejects('did:web:example.com%09agents');
    rejects('did:web:example.com%00');
    rejects('did:web:example.com:%5cagents');
  });
  it('path traversal and dot segments', () => {
    rejects('did:web:example.com:..');
    rejects('did:web:example.com:agents:..:secrets');
    rejects('did:web:example.com:.');
  });
  it('encoded path separator tricks', () => {
    rejects('did:web:example.com:agents%2F..%2Fadmin');
    rejects('did:web:example.com:agents%5csecrets');
  });
  it('invalid percent encoding', () => {
    rejects('did:web:example%ZZ.com');
    rejects('did:web:example.com%3');
  });
  it('absurdly long DID and too many segments', () => {
    rejects(`did:web:${'a'.repeat(300)}`);
    rejects(`did:web:example.com${':seg'.repeat(20)}`);
  });
  it('bad encoded port', () => {
    rejects('did:web:example.com%3A99999');
    rejects('did:web:example.com%3Aab');
  });
});

describe('address classification (12G)', () => {
  const unsafe = [
    '127.0.0.1', '127.255.0.7', '0.0.0.0', '10.1.2.3', '172.16.0.1', '172.31.255.255',
    '192.168.1.1', '169.254.169.254', '100.64.0.1', '198.18.0.1', '224.0.0.1', '240.0.0.1',
    '::', '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:127.0.0.1',
    '::ffff:10.0.0.1', '::ffff:169.254.169.254', '64:ff9b::127.0.0.1',
  ];
  for (const ip of unsafe) {
    it(`rejects ${ip}`, () => {
      expect(classifyAddress(ip)).toEqual({ safe: false, reason: expect.any(String) });
    });
  }
  const safe = ['8.8.8.8', '1.1.1.1', '2606:4700::1111', '172.32.0.1', '192.169.0.1'];
  for (const ip of safe) {
    it(`accepts public ${ip}`, () => {
      expect(classifyAddress(ip)).toEqual({ safe: true });
    });
  }
});

// ---------------------------------------------------------------- harness

const DID = 'did:web:trust.example.com:agents:support';
const VALID_JWK = {
  kty: 'EC', crv: 'P-256',
  x: 'msBtjfUwG7cVv0tDC48SBzX5CpG9q7CkGmNqDSDYnJc',
  y: '0KFXhkJr-N0iKkPBN0V0pS1WQvH5VGNYFc0Kt1BMJm0',
};
const VALID_DOC = {
  id: DID,
  verificationMethod: [
    { id: `${DID}#key-1`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: VALID_JWK },
  ],
};

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): DidWebHttpResponse {
  return {
    status,
    headers: { 'content-type': 'application/did+json', ...headers },
    body: JSON.stringify(body),
  };
}

function clientOf(responder: (url: URL) => Promise<DidWebHttpResponse>): DidWebHttpClient {
  return { get: responder };
}

describe('document validation (12M–12P)', () => {
  it('accepts a well-formed document', () => {
    const v = validateDidWebDocument(VALID_DOC, DID);
    expect(v.ok).toBe(true);
  });

  it('CRITICAL: document.id mismatch fails (did:web spec id binding)', () => {
    const v = validateDidWebDocument({ ...VALID_DOC, id: 'did:web:evil.example' }, DID);
    expect(v).toEqual({ ok: false, reason: expect.stringContaining('mismatch') });
  });

  it('rejects arrays, primitives, missing id', () => {
    expect(validateDidWebDocument([], DID).ok).toBe(false);
    expect(validateDidWebDocument('str', DID).ok).toBe(false);
    expect(validateDidWebDocument(null, DID).ok).toBe(false);
    expect(validateDidWebDocument({ verificationMethod: [] }, DID).ok).toBe(false);
  });

  it('rejects method ids owned by another DID (kid ownership, 12P)', () => {
    const doc = {
      id: DID,
      verificationMethod: [
        { id: 'did:web:example.com:agents:other#key-1', type: 'JsonWebKey2020', publicKeyJwk: VALID_JWK },
      ],
    };
    expect(validateDidWebDocument(doc, DID).ok).toBe(false);
  });

  it('rejects private JWK material (12N)', () => {
    for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      const jwk = { ...VALID_JWK, [field]: 'LEAKED' };
      expect(validatePublicJwk(jwk).ok).toBe(false);
    }
  });

  it('rejects unsupported key types deterministically (12O)', () => {
    expect(validatePublicJwk({ kty: 'RSA', n: 'x', e: 'AQAB' }).ok).toBe(false);
    expect(validatePublicJwk({ kty: 'EC', crv: 'secp256k1', x: 'a', y: 'b' }).ok).toBe(false);
    expect(validatePublicJwk({ kty: 'EC', crv: 'P-256', x: '', y: 'b' }).ok).toBe(false);
    expect(validatePublicJwk({ kty: 'OKP', crv: 'Ed25519', x: 'a' }).ok).toBe(false);
  });
});

describe('WebDidResolver — mandatory security matrix (12D–12L)', () => {
  it('valid path DID resolves through the HTTP seam', async () => {
    const urls: string[] = [];
    const resolver = new WebDidResolver({
      http: clientOf(async (url) => {
        urls.push(url.toString());
        return jsonResponse(VALID_DOC);
      }),
    });
    const result = await resolver.resolve(DID);
    expect(result.didDocument?.id).toBe(DID);
    expect(urls).toEqual(['https://trust.example.com/agents/support/did.json']);
  });

  it('wrong document.id → fail, and NOT cached', async () => {
    const resolver = new WebDidResolver({
      http: clientOf(async () => jsonResponse({ ...VALID_DOC, id: 'did:web:evil.example' })),
    });
    const r1 = await resolver.resolve(DID);
    expect(r1.didDocument).toBeNull();
    expect(resolver.peekCache(DID)).toBeUndefined();
  });

  it('malformed JSON → representationNotSupported', async () => {
    const resolver = new WebDidResolver({
      http: clientOf(async () => ({ status: 200, headers: {}, body: '<html>not json</html>' })),
    });
    expect((await resolver.resolve(DID)).didResolutionMetadata.error).toBe('representationNotSupported');
  });

  it('JSON primitive / array body → representationNotSupported', async () => {
    const resolver = new WebDidResolver({
      http: clientOf(async () => jsonResponse(42)),
    });
    expect((await resolver.resolve(DID)).didResolutionMetadata.error).toBe('representationNotSupported');
  });

  it('oversized response → transport TOO_LARGE, deterministic failure', async () => {
    // The transport contract caps the body BEFORE it reaches the resolver —
    // mirroring NodeHttpsDidWebClient. A 1 MiB body against a 100-byte cap.
    const oversized = clientOf(async () => ({
      status: 200,
      headers: {},
      body: 'x'.repeat(1024 * 1024),
    }));
    const capped = clientOf(async () => ({ status: 200, headers: {}, body: 'x'.repeat(50) }));
    const resolver = new WebDidResolver({ http: oversized });
    void capped;
    // Direct transport-level check (the seam enforces maxBytes):
    const { DidWebTransportError } = await import('../src/index.js');
    const { NodeHttpsDidWebClient } = await import('../src/index.js');
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }],
      httpRequest: async () => ({
        status: 200,
        headers: { 'content-length': String(1024 * 1024) },
        streamBody: null,
      }),
    });
    await expect(
      client.get(new URL('https://public.example.com/did.json'), { timeoutMs: 1000, maxBytes: 100 }),
    ).rejects.toThrow(DidWebTransportError);
    // And the resolver maps the transport code to a deterministic failure.
    const cappedResolver = new WebDidResolver({
      http: {
        get: async () => {
          throw new (await import('../src/index.js')).DidWebTransportError('TOO_LARGE', 'response exceeds cap');
        },
      },
    });
    const r = await cappedResolver.resolve(DID);
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.message).toContain('size limit');
  });

  it('HTTP/transport failure → fail (fresh cache serves, stale fails closed — see cache suite)', async () => {
    const resolver = new WebDidResolver({
      http: clientOf(async () => {
        throw new Error('ECONNREFUSED');
      }),
    });
    const r = await resolver.resolve(DID);
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('internalError');
  });

  it('timeout → deterministic failure', async () => {
    const resolver = new WebDidResolver({
      http: clientOf(async () => {
        throw new (await import('../src/index.js')).DidWebTransportError('TIMEOUT', 'timed out');
      }),
    });
    const r = await resolver.resolve(DID);
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.message).toContain('timeout');
  });

  it('redirect status (301/302/307/308) → rejected by redirect policy', async () => {
    for (const status of [301, 302, 307, 308]) {
      const resolver = new WebDidResolver({
        http: clientOf(async () => ({ status, headers: { location: 'https://internal.example/did.json' }, body: '' })),
      });
      const r = await resolver.resolve(DID);
      expect(r.didDocument).toBeNull();
      expect(r.didResolutionMetadata.message).toContain('redirect rejected');
    }
  });

  it('404 → notFound; other 4xx/5xx → fail', async () => {
    const notFound = new WebDidResolver({ http: clientOf(async () => jsonResponse({}, 404)) });
    expect((await notFound.resolve(DID)).didResolutionMetadata.error).toBe('notFound');
    const gone = new WebDidResolver({ http: clientOf(async () => jsonResponse({}, 410)) });
    expect((await gone.resolve(DID)).didResolutionMetadata.error).toBe('notFound');
    const boom = new WebDidResolver({ http: clientOf(async () => jsonResponse({}, 500)) });
    expect((await boom.resolve(DID)).didDocument).toBeNull();
    const denied = new WebDidResolver({ http: clientOf(async () => jsonResponse({}, 403)) });
    expect((await denied.resolve(DID)).didDocument).toBeNull();
  });

  it('IP-literal DID → invalidDid before any network activity', async () => {
    let called = false;
    const resolver = new WebDidResolver({
      http: clientOf(async () => {
        called = true;
        return jsonResponse(VALID_DOC);
      }),
    });
    const r = await resolver.resolve('did:web:127.0.0.1');
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(called).toBe(false);
  });

  it('malformed identifier → invalidDid, zero network calls', async () => {
    let calls = 0;
    const resolver = new WebDidResolver({
      http: clientOf(async () => {
        calls += 1;
        return jsonResponse(VALID_DOC);
      }),
    });
    for (const did of ['did:web:', 'did:web:example.com:..', 'did:web:example.com?x']) {
      const r = await resolver.resolve(did);
      expect(r.didResolutionMetadata.error).toBe('invalidDid');
    }
    expect(calls).toBe(0);
  });

  it('unknown DID method → methodUnsupported', async () => {
    const resolver = new WebDidResolver({ http: clientOf(async () => jsonResponse(VALID_DOC)) });
    const r = await resolver.resolve('did:unknown:whatever');
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('methodUnsupported');
  });

  it('private JWK in a served document → invalid and NOT cached (12N via resolver)', async () => {
    const doc = {
      id: DID,
      verificationMethod: [
        { id: `${DID}#key-1`, type: 'JsonWebKey2020', publicKeyJwk: { ...VALID_JWK, d: 'PRIVATE' } },
      ],
    };
    const resolver = new WebDidResolver({ http: clientOf(async () => jsonResponse(doc)) });
    const r = await resolver.resolve(DID);
    expect(r.didDocument).toBeNull();
    expect(resolver.peekCache(DID)).toBeUndefined();
  });

  it('unsupported key type in a served document → deterministic fail (12O via resolver)', async () => {
    const doc = {
      id: DID,
      verificationMethod: [
        { id: `${DID}#key-1`, type: 'JsonWebKey2020', publicKeyJwk: { kty: 'RSA', n: 'x', e: 'AQAB' } },
      ],
    };
    const resolver = new WebDidResolver({ http: clientOf(async () => jsonResponse(doc)) });
    const r = await resolver.resolve(DID);
    expect(r.didDocument).toBeNull();
  });
});

describe('host policy (12F) + NodeHttpsDidWebClient policy gate (12E/G)', () => {
  it('resolver honors an allowlist: disallowed host never reaches transport', async () => {
    let called = false;
    const resolver = new WebDidResolver({
      networkPolicy: { allowedHosts: ['trust.example.com'], blockPrivateNetworks: true },
      http: clientOf(async () => {
        called = true;
        return jsonResponse(VALID_DOC);
      }),
    });
    const r = await resolver.resolve('did:web:other.example:agents:support');
    expect(called).toBe(false);
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.message).toContain('not allowed by policy');
  });

  it('client enforces HTTPS-only at the transport layer', async () => {
    const { assertDestinationAllowed, DidWebTransportError } = await import('../src/index.js');
    expect(() => assertDestinationAllowed(new URL('http://example.com/.well-known/did.json'), { blockPrivateNetworks: true }))
      .toThrow(DidWebTransportError);
  });

  it('client literal-address gate rejects loopback literals', async () => {
    const { assertDestinationAllowed, DidWebTransportError } = await import('../src/index.js');
    expect(() => assertDestinationAllowed(new URL('https://127.0.0.1/did.json'), { blockPrivateNetworks: true }))
      .toThrow(DidWebTransportError);
  });
});

describe('DNS rebinding / TOCTOU (12H) — address-pinned transport', () => {
  it('resolves the hostname ONCE and classifies EVERY returned address', async () => {
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }],
      httpRequest: async () => {
        throw new Error('must never connect — address check fires first');
      },
    });
    await expect(
      client.get(new URL('https://public.example.com/.well-known/did.json'), { timeoutMs: 1000, maxBytes: 1024 }),
    ).rejects.toThrow(/metadata|link-local/i);
  });

  it('SIMULATED REBINDING: hostname looks valid but the selected address is private → DENY', async () => {
    // The attack: DNS first returns a public IP; the connection-time lookup
    // returns a private one. This transport PINS the validated address, so
    // the double looks like: single lookup returning the private address.
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '10.0.0.7', family: 4 }],
      httpRequest: async () => {
        throw new Error('must never connect');
      },
    });
    await expect(
      client.get(new URL('https://rebind.example.com/.well-known/did.json'), { timeoutMs: 1000, maxBytes: 1024 }),
    ).rejects.toThrow(/RFC1918|private/i);
  });

  it('connection is pinned to the validated address (lookup override receives it)', async () => {
    let connectionAddress: string | null = null;
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }],
      httpRequest: async (input) => {
        connectionAddress = input.connectionAddress;
        return { status: 200, headers: {}, streamBody: null };
      },
    });
    const res = await client.get(new URL('https://public.example.com/did.json'), { timeoutMs: 1000, maxBytes: 1024 });
    expect(res.status).toBe(200);
    expect(connectionAddress).toBe('93.184.216.34');
  });
});
