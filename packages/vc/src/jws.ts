import {
  type Signer,
  base64urlDecode,
  base64urlEncode,
  ecdsaDerToRaw,
  ecdsaRawToDer,
  utf8,
  verifyEs256,
} from '@agent-trust/crypto';
import type { PublicJwk } from '@agent-trust/crypto';

/**
 * Compact JWS (RFC 7515) restricted to this fabric's profile:
 * alg=ES256, typ=JWT (optional but must be JWT if present), kid required,
 * crit forbidden (no unsupported extensions may sneak through).
 *
 * Signing goes through the Signer seam — private key material never
 * enters this module. node:crypto emits DER; JWS ES256 carries raw R||S,
 * so signatures cross the ecdsaDerToRaw/ecdsaRawToDer converters.
 */

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

export interface ParsedJws {
  protectedHeader: Record<string, unknown>;
  /** The exact received "header.payload" ASCII — verification input. */
  signingInput: string;
  headerB64url: string;
  payloadB64url: string;
  /** Raw 64-byte R||S signature. */
  signatureRaw: Uint8Array;
}

export class JwsFormatError extends Error {}

function requireB64url(part: string, name: string): Uint8Array {
  if (!B64URL_RE.test(part)) {
    throw new JwsFormatError(`JWS ${name} is not base64url`);
  }
  const bytes = base64urlDecode(part);
  // Re-encode equality catches trailing-bit abuse Buffer tolerates.
  if (base64urlEncode(bytes) !== part) {
    throw new JwsFormatError(`JWS ${name} is not canonical base64url`);
  }
  return bytes;
}

function parseJsonObject(bytes: Uint8Array, name: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    throw new JwsFormatError(`JWS ${name} is not valid JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new JwsFormatError(`JWS ${name} is not a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

export function parseCompactJws(jws: string): ParsedJws {
  const parts = jws.split('.');
  if (parts.length !== 3) {
    throw new JwsFormatError('compact JWS must have exactly three parts');
  }
  const [headerB64url = '', payloadB64url = '', signatureB64url = ''] = parts;
  if (headerB64url.length === 0 || payloadB64url.length === 0 || signatureB64url.length === 0) {
    throw new JwsFormatError('compact JWS parts must be non-empty');
  }

  const header = parseJsonObject(requireB64url(headerB64url, 'header'), 'header');
  if (header.alg !== 'ES256') {
    throw new JwsFormatError('only alg=ES256 is supported');
  }
  if (header.crit !== undefined) {
    throw new JwsFormatError('JWS crit extensions are not supported');
  }
  if (header.typ !== undefined && header.typ !== 'JWT') {
    throw new JwsFormatError('JWS typ must be JWT when present');
  }
  if (typeof header.kid !== 'string' || header.kid.length === 0) {
    throw new JwsFormatError('JWS kid is required');
  }

  parseJsonObject(requireB64url(payloadB64url, 'payload'), 'payload');
  const signatureRaw = requireB64url(signatureB64url, 'signature');
  if (signatureRaw.length !== 64) {
    throw new JwsFormatError('ES256 signatures are exactly 64 bytes');
  }

  return {
    protectedHeader: header,
    signingInput: `${headerB64url}.${payloadB64url}`,
    headerB64url,
    payloadB64url,
    signatureRaw,
  };
}

export function decodeJwsPayload(parsed: ParsedJws): Record<string, unknown> {
  return parseJsonObject(base64urlDecode(parsed.payloadB64url), 'payload');
}

export async function signCompactJws(
  signer: Signer,
  payload: Record<string, unknown>,
): Promise<string> {
  const kid = await signer.keyId();
  const header = { alg: 'ES256', typ: 'JWT', kid };
  const headerB64url = base64urlEncode(utf8(JSON.stringify(header)));
  const payloadB64url = base64urlEncode(utf8(JSON.stringify(payload)));
  const signingInput = `${headerB64url}.${payloadB64url}`;
  const derSignature = await signer.sign(utf8(signingInput));
  const signatureB64url = base64urlEncode(ecdsaDerToRaw(derSignature));
  return `${signingInput}.${signatureB64url}`;
}

/** Verify the JWS signature over the exact received bytes. */
export function verifyCompactJwsSignature(
  parsed: ParsedJws,
  publicJwk: PublicJwk,
): boolean {
  try {
    return verifyEs256({
      publicJwk,
      data: utf8(parsed.signingInput),
      signature: ecdsaRawToDer(parsed.signatureRaw),
    });
  } catch {
    return false;
  }
}
