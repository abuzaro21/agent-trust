import { describe, expect, it } from 'vitest';

import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

import { LocalSigner, ecdsaDerToRaw, ecdsaRawToDer, verifyEs256 } from '../src/index.js';
import type { PublicJwk } from '../src/index.js';

/**
 * DER ↔ raw-P1363 conversion is validated against a SECOND, independent
 * implementation (WebCrypto emits/accepts raw R||S; node:crypto emits/accepts
 * DER). A conversion bug would fail these cross-checks even if a naive
 * roundtrip test passed.
 */

function subtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('WebCrypto unavailable');
  return s;
}

describe('ecdsa DER ↔ raw conversion', () => {
  it('roundtrips node DER signatures through raw and back', async () => {
    const signer = LocalSigner.generate();
    for (let i = 0; i < 20; i++) {
      const der = await signer.sign(new TextEncoder().encode(`payload ${i}`));
      const raw = ecdsaDerToRaw(der);
      expect(raw.length).toBe(64);
      expect(Array.from(ecdsaRawToDer(raw))).toEqual(Array.from(der));
    }
  });

  it('rejects malformed DER', () => {
    expect(() => ecdsaDerToRaw(new Uint8Array([0x31, 0x02]))).toThrow(TypeError);
    expect(() => ecdsaDerToRaw(new Uint8Array([0x30, 0x80, 0x02, 0x01, 0x01]))).toThrow(TypeError);
    expect(() => ecdsaRawToDer(new Uint8Array(63))).toThrow(TypeError);
  });

  it('cross-checks with WebCrypto: node DER → raw → WebCrypto verifies', async () => {
    // WebCrypto keypair (extractable so node can import the private half).
    const keyPair = await subtle().generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const publicJwk = await subtle().exportKey('jwk', keyPair.publicKey);
    const privateJwk = await subtle().exportKey('jwk', keyPair.privateKey);
    const data = new TextEncoder().encode('cross-implementation check');

    // Sign with node (DER) using the imported private key...
    const der = new Uint8Array(
      nodeSign(
        'SHA256',
        data,
        createPrivateKey({ key: privateJwk as never, format: 'jwk' }),
      ),
    );
    // ...convert to raw R||S, and verify with WebCrypto (raw consumer).
    const raw = ecdsaDerToRaw(der);
    const ok = await subtle().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      await subtle().importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'verify',
      ]),
      raw,
      data,
    );
    expect(ok).toBe(true);
  });

  it('cross-checks with WebCrypto: WebCrypto raw → DER → node verifies', async () => {
    const keyPair = await subtle().generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const jwkRaw = (await subtle().exportKey('jwk', keyPair.publicKey)) as {
      x: string;
      y: string;
    };
    const jwk: PublicJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: jwkRaw.x,
      y: jwkRaw.y,
    };
    const data = new TextEncoder().encode('cross-implementation check 2');

    // Sign with WebCrypto (raw R||S), convert to DER, verify with node.
    const raw = new Uint8Array(
      await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, data),
    );
    expect(raw.length).toBe(64);
    const der = ecdsaRawToDer(raw);
    // PublicJwk is structurally a JWK but carries no index signature, so
    // node's JsonWebKey input needs the cast at this boundary.
    const keyObject = createPublicKey({ key: jwk as never, format: 'jwk' });
    expect(nodeVerify('SHA256', data, keyObject, der)).toBe(true);
    // And the converted DER also verifies through our own verifyEs256 seam.
    expect(verifyEs256({ publicJwk: jwk, data, signature: der })).toBe(true);
  });
});
