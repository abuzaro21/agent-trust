import {
  type KeyObject,
  generateKeyPairSync,
  sign as nodeSign,
} from 'node:crypto';

import { base64urlEncode, canonicalJson, sha256, utf8 } from './helpers.js';
import type { PublicJwk, Signer } from './types.js';

/**
 * RFC 7638 JWK thumbprint over the required P-256 members — the stable
 * identity of a public key. Used as the DID verification-method fragment.
 */
export function jwkThumbprint(jwk: PublicJwk): string {
  const required = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return base64urlEncode(sha256(canonicalJson(required)));
}

/**
 * P0 signer: an in-process ES256 (P-256) keypair.
 *
 * - Tests and local fixtures: `LocalSigner.generate()` with no DID.
 * - Demo/protected deployment: `LocalSigner.generate({ did })` — the DID
 *   only affects the reported keyId, never key handling.
 * - Production hardening (P1): a CloudKmsSigner implements the same
 *   interface; nothing above this class may touch private material.
 */
export class LocalSigner implements Signer {
  readonly #privateKey: KeyObject;
  readonly #publicJwk: PublicJwk;
  readonly #thumbprint: string;
  readonly #did: string | undefined;

  private constructor(privateKey: KeyObject, publicJwk: PublicJwk, did?: string) {
    this.#privateKey = privateKey;
    this.#publicJwk = publicJwk;
    this.#thumbprint = jwkThumbprint(publicJwk);
    this.#did = did;
  }

  static generate(opts: { did?: string } = {}): LocalSigner {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as PublicJwk;
    return new LocalSigner(privateKey, jwk, opts.did);
  }

  async keyId(): Promise<string> {
    return this.#did ? `${this.#did}#${this.#thumbprint}` : this.#thumbprint;
  }

  async publicKey(): Promise<PublicJwk> {
    return { ...this.#publicJwk };
  }

  /** Full verification-method id without needing the DID at signing time. */
  thumbprint(): string {
    return this.#thumbprint;
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(nodeSign('SHA256', Buffer.from(data), this.#privateKey));
  }

  /** Canonical-bytes digest helper (used by proof bindings and receipts). */
  async signCanonical(value: unknown): Promise<Uint8Array> {
    return this.sign(utf8(canonicalJson(value)));
  }
}
