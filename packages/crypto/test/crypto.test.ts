import { describe, expect, it } from 'vitest';

import {
  LocalSigner,
  base64urlDecode,
  base64urlEncode,
  bytesEqual,
  canonicalJson,
  jwkThumbprint,
  sha256,
  sha256Hex,
  utf8,
  verifyEs256,
} from '../src/index.js';

describe('helpers', () => {
  it('sha256 of the empty string matches the known vector', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('canonicalJson is key-order independent (RFC 8785)', () => {
    const a = canonicalJson({ a: 1, b: { z: 1, y: [1, 2] } });
    const b = canonicalJson({ b: { y: [1, 2], z: 1 }, a: 1 });
    expect(a).toBe(b);
  });

  it('canonicalJson rejects non-finite numbers instead of producing garbage', () => {
    expect(() => canonicalJson({ n: Number.NaN })).toThrow();
  });

  it('base64url roundtrips bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(bytesEqual(base64urlDecode(base64urlEncode(bytes)), bytes)).toBe(true);
  });
});

describe('LocalSigner / verifyEs256', () => {
  it('signs and verifies a roundtrip', async () => {
    const signer = LocalSigner.generate();
    const data = utf8('refund:create 120 SAR');
    const signature = await signer.sign(data);
    expect(verifyEs256({ publicJwk: await signer.publicKey(), data, signature })).toBe(true);
  });

  it('rejects tampered data (forgery test)', async () => {
    const signer = LocalSigner.generate();
    const signature = await signer.sign(utf8('"maxAmount":500'));
    expect(
      verifyEs256({
        publicJwk: await signer.publicKey(),
        data: utf8('"maxAmount":50000'),
        signature,
      }),
    ).toBe(false);
  });

  it('rejects a signature verified with the wrong key (spoofing test)', async () => {
    const signer = LocalSigner.generate();
    const evil = LocalSigner.generate();
    const signature = await signer.sign(utf8('legitimate'));
    expect(
      verifyEs256({ publicJwk: await evil.publicKey(), data: utf8('legitimate'), signature }),
    ).toBe(false);
  });

  it('keyId embeds the DID and the RFC 7638 thumbprint', async () => {
    const signer = LocalSigner.generate({ did: 'did:key:zTest' });
    const jwk = await signer.publicKey();
    const kid = await signer.keyId();
    expect(kid).toBe(`did:key:zTest#${jwkThumbprint(jwk)}`);
    // Thumbprint is stable for the same key material.
    expect(jwkThumbprint(jwk)).toBe(jwkThumbprint({ ...jwk }));
  });

  it('different keys produce different thumbprints', async () => {
    const a = await LocalSigner.generate().publicKey();
    const b = await LocalSigner.generate().publicKey();
    expect(jwkThumbprint(a)).not.toBe(jwkThumbprint(b));
  });

  it('sha256 returns 32 bytes', () => {
    expect(sha256('x').length).toBe(32);
  });
});
