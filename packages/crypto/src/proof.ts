import type { AgentProof } from '@agent-trust/schemas';

import {
  base64urlDecode,
  base64urlEncode,
  canonicalJson,
  sha256,
  utf8,
} from './helpers.js';
import type { PublicJwk, Signer } from './types.js';
import { verifyEs256 } from './verify.js';

/**
 * What a proof signs — DPoP-style binding (RFC 9449 semantics, ADR-0003):
 *
 *  - htu               the target endpoint — a captured proof is useless
 *                     against another service;
 *  - requestBodyDigest base64url(SHA-256(canonicalJson(request body))) —
 *                     the action cannot change after signing;
 *  - jti / iat / exp   replay protection window;
 *  - nonce            optional server-issued challenge.
 */
export interface ProofBinding {
  htu: string;
  requestBodyDigest: string;
  jti: string;
  iat: number;
  exp: number;
  nonce?: string;
}

export function canonicalProofBinding(binding: ProofBinding): string {
  const { nonce, ...rest } = binding;
  return canonicalJson(nonce === undefined ? rest : { ...rest, nonce });
}

/** base64url(SHA-256(canonicalJson(body))) — the digest every proof binds to. */
export function requestBodyDigestOf(body: unknown): string {
  return base64urlEncode(sha256(canonicalJson(body)));
}

export async function createProof(signer: Signer, binding: ProofBinding): Promise<AgentProof> {
  if (binding.exp <= binding.iat) {
    throw new RangeError('proof exp must be greater than iat');
  }
  const signature = await signer.sign(utf8(canonicalProofBinding(binding)));
  const proof: AgentProof = {
    kid: await signer.keyId(),
    jti: binding.jti,
    iat: binding.iat,
    exp: binding.exp,
    signature: base64urlEncode(signature),
  };
  if (binding.nonce !== undefined) proof.nonce = binding.nonce;
  return proof;
}

export type ProofFailure =
  | 'PROOF_SIGNATURE_INVALID'
  | 'PROOF_EXPIRED'
  | 'PROOF_NOT_YET_VALID';

export type ProofVerification =
  | { valid: true }
  | { valid: false; error: ProofFailure };

/**
 * Cryptographic + temporal verification of a proof against the JWK resolved
 * from its kid. jti uniqueness is the replay store's job (ADR-0003) —
 * this function only proves possession and freshness.
 */
export function verifyProof(input: {
  proof: AgentProof;
  publicJwk: PublicJwk;
  htu: string;
  requestBodyDigest: string;
  now?: number;
}): ProofVerification {
  const { proof, publicJwk, htu, requestBodyDigest } = input;
  const now = input.now ?? Math.floor(Date.now() / 1000);

  if (now >= proof.exp) return { valid: false, error: 'PROOF_EXPIRED' };
  if (now < proof.iat) return { valid: false, error: 'PROOF_NOT_YET_VALID' };

  const expectedBinding: ProofBinding = {
    htu,
    requestBodyDigest,
    jti: proof.jti,
    iat: proof.iat,
    exp: proof.exp,
    ...(proof.nonce !== undefined ? { nonce: proof.nonce } : {}),
  };
  const ok = verifyEs256({
    publicJwk,
    data: utf8(canonicalProofBinding(expectedBinding)),
    signature: base64urlDecode(proof.signature),
  });
  return ok ? { valid: true } : { valid: false, error: 'PROOF_SIGNATURE_INVALID' };
}
