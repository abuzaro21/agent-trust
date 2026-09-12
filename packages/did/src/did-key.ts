import {
  type PublicJwk,
  base64urlDecode,
  jwkThumbprint,
} from '@agent-trust/crypto';

import { base58btcDecode, base58btcEncode, varintDecode, varintEncode } from './multibase.js';
import type { DidDocument, DidResolutionResult, DidResolver } from './types.js';

/**
 * did:key fixture profile for P-256 (multicodec p256-pub = 0x1200, multibase
 * base58btc, 33-byte compressed SEC1 point — the did:key spec encoding).
 * The implementation supports exactly the curve our ES256 stack uses and
 * rejects every other codec — the resolver's job is a strict allowlist,
 * not generality (threat model: DID resolution abuse).
 *
 * Fragment convention: did:key:<z> # <RFC 7638 JWK thumbprint>, matching
 * LocalSigner.keyId() so kid → verificationMethod.id resolution is stable.
 */

const MULTICODEC_P256_PUB = 0x1200;
const PREFIX = 'did:key:z';
const CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/jws-2020/v1',
];

// NIST P-256 domain parameters — needed to recover y from the compressed
// point when resolving a DID string that carries only 33 bytes.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function bigintTo32Bytes(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bytes32ToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const byte of bytes) v = (v << 8n) | BigInt(byte);
  return v;
}

/** 33-byte compressed SEC1 point (0x02|0x03 prefix + 32-byte x). */
function compressedPointFromJwk(jwk: PublicJwk): Uint8Array {
  const x = base64urlDecode(jwk.x);
  const y = base64urlDecode(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new TypeError('did:key P-256 keys require 32-byte x and y coordinates');
  }
  const yBig = bytes32ToBigint(y);
  const prefix = (yBig & 1n) === 1n ? 0x03 : 0x02;
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(x, 1);
  return out;
}

function jwkFromCompressedPoint(point: Uint8Array): PublicJwk {
  const prefix = point[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new TypeError('did:key: compressed point must start with 0x02 or 0x03');
  }
  const x = bytes32ToBigint(point.slice(1, 33));
  // y² = x³ − 3x + b (mod p); p ≡ 3 (mod 4) so sqrt is rhs^((p+1)/4).
  const rhs = (((x * x) % P) * x - 3n * x + B) % P;
  let y = modPow(((rhs % P) + P) % P, (P + 1n) / 4n, P);
  if ((y * y) % P !== ((rhs % P) + P) % P) {
    throw new TypeError('did:key: point is not on the P-256 curve');
  }
  const oddPrefix = prefix === 0x03;
  if ((y & 1n) === 1n !== oddPrefix) {
    y = P - y;
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(bigintTo32Bytes(x)).toString('base64url'),
    y: Buffer.from(bigintTo32Bytes(y)).toString('base64url'),
  };
}

export function didKeyFromPublicKeyJwk(jwk: PublicJwk): string {
  const point = compressedPointFromJwk(jwk);
  const prefixed = new Uint8Array(2 + point.length);
  prefixed.set(varintEncode(MULTICODEC_P256_PUB), 0);
  prefixed.set(point, 2);
  return `${PREFIX}${base58btcEncode(prefixed)}`;
}

export function publicKeyJwkFromDidKey(did: string): PublicJwk {
  if (!did.startsWith(PREFIX)) {
    throw new TypeError('not a did:key (base58btc) identifier');
  }
  let bytes: Uint8Array;
  try {
    bytes = base58btcDecode(did.slice(PREFIX.length));
  } catch (e) {
    throw new TypeError(`did:key: invalid base58btc payload (${String(e)})`);
  }
  const { value: codec, next } = varintDecode(bytes);
  if (codec !== MULTICODEC_P256_PUB) {
    throw new TypeError(
      `did:key: unsupported multicodec 0x${codec.toString(16)} (p256-pub / 0x1200 only)`,
    );
  }
  const point = bytes.slice(next);
  if (point.length !== 33) {
    throw new TypeError('did:key: expected a 33-byte compressed SEC1 point');
  }
  return jwkFromCompressedPoint(point);
}

export function didKeyDocument(did: string): DidDocument {
  const jwk = publicKeyJwkFromDidKey(did);
  return {
    '@context': CONTEXT,
    id: did,
    verificationMethod: [
      {
        id: `${did}#${jwkThumbprint(jwk)}`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: jwk,
      },
    ],
    authentication: [`${did}#${jwkThumbprint(jwk)}`],
  };
}

export class DidKeyResolver implements DidResolver {
  supports(did: string): boolean {
    return did.startsWith('did:key:');
  }

  async resolve(did: string): Promise<DidResolutionResult> {
    if (!this.supports(did)) {
      return { didDocument: null, didResolutionMetadata: { error: 'methodUnsupported' } };
    }
    try {
      return {
        didDocument: didKeyDocument(did),
        didResolutionMetadata: { contentType: 'application/did+json' },
      };
    } catch (e) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'invalidDid', message: String(e) },
      };
    }
  }
}
