import { describe, expect, it } from 'vitest';

import {
  DidKeyResolver,
  MultiDidResolver,
  didKeyFromPublicKeyJwk,
  publicKeyJwkFromDidKey,
} from '../src/index.js';

describe('did:key P-256 roundtrip', () => {
  it('derives a did:key from a random P-256 JWK and resolves the same key back', async () => {
    const { LocalSigner } = await import('@agent-trust/crypto');
    const signer = LocalSigner.generate();
    const jwk = await signer.publicKey();
    const did = didKeyFromPublicKeyJwk(jwk);

    expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);

    const recovered = publicKeyJwkFromDidKey(did);
    expect(recovered).toEqual(jwk);
  });

  it('is deterministic: same key → same DID', async () => {
    const { LocalSigner } = await import('@agent-trust/crypto');
    const signer = LocalSigner.generate();
    const jwk = await signer.publicKey();
    expect(didKeyFromPublicKeyJwk(jwk)).toBe(didKeyFromPublicKeyJwk(jwk));
  });
});

describe('DidKeyResolver', () => {
  const resolver = new DidKeyResolver();

  it('resolves a document whose verification method matches the signer key', async () => {
    const { LocalSigner, jwkThumbprint } = await import('@agent-trust/crypto');
    const signer = LocalSigner.generate();
    const jwk = await signer.publicKey();
    const did = didKeyFromPublicKeyJwk(jwk);

    const result = await resolver.resolve(did);
    expect(result.didDocument?.id).toBe(did);

    const method = result.didDocument?.verificationMethod?.[0];
    expect(method?.publicKeyJwk).toEqual(jwk);
    expect(method?.id).toBe(`${did}#${jwkThumbprint(jwk)}`);

    // kid → verification-method resolution through the registry.
    const multi = new MultiDidResolver([resolver]);
    const resolved = await multi.resolveVerificationMethod(method!.id);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) {
      expect(resolved.method.publicKeyJwk).toEqual(jwk);
    }
  });

  it('rejects non-P-256 codecs (ed25519 multicodec 0xed)', async () => {
    const { base58btcEncode } = await import('../src/index.js');
    const payload = new Uint8Array(34);
    payload[0] = 0xed;
    payload[1] = 0x01;
    const did = `did:key:z${base58btcEncode(payload)}`;
    const result = await resolver.resolve(did);
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
  });

  it('returns methodUnsupported for other methods', async () => {
    const result = await resolver.resolve('did:web:example.com');
    expect(result.didResolutionMetadata.error).toBe('methodUnsupported');
  });
});

describe('MultiDidResolver', () => {
  it('answers methodUnsupported for unregistered methods', async () => {
    const { WebDidResolver } = await import('../src/index.js');
    const multi = new MultiDidResolver([new WebDidResolver()]);
    const result = await multi.resolve('did:key:zSomething');
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('methodUnsupported');
  });

  it('reports a missing verification method instead of throwing', async () => {
    const multi = new MultiDidResolver([new DidKeyResolver()]);
    const { LocalSigner } = await import('@agent-trust/crypto');
    const did = didKeyFromPublicKeyJwk(await LocalSigner.generate().publicKey());
    const resolved = await multi.resolveVerificationMethod(`${did}#does-not-exist`);
    expect(resolved.ok).toBe(false);
  });
});
