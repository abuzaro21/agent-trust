import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

// canonicalize (RFC 8785 JCS) ships a CJS build whose ESM-style typings do
// not interop cleanly under NodeNext; createRequire returns the real export.
const requireCjs = createRequire(import.meta.url);
const canonicalize = requireCjs('canonicalize') as (value: unknown) => string | undefined;

/**
 * RFC 8785 (JSON Canonicalization Scheme). All signatures and hash-chain
 * inputs go through this — property order and formatting must be
 * deterministic or signatures break across processes.
 */
export function canonicalJson(value: unknown): string {
  const result = canonicalize(value);
  if (result === undefined) {
    throw new TypeError('canonicalJson: value is not canonicalizable (non-finite number?)');
  }
  return result;
}

export function utf8(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64urlDecode(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, 'base64url'));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Strip top-level undefined properties so canonicalJson is stable. */
export function stripUndefined<T extends Record<string, unknown>>(value: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    if (v !== undefined) out[k] = v;
  }
  return out as T;
}
