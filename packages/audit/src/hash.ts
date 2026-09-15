import { canonicalJson, sha256, utf8 } from '@agent-trust/crypto';

import type { ActionReceipt, ActionReceiptBody } from './types.js';

/**
 * Hash construction (Step 9D) — versioned and domain-separated:
 *
 *   eventHash = SHA-256(
 *     UTF8("agent-trust/action-receipt/v1\0")   ← 30-byte domain separator
 *     || previousHashBytes                       ← fixed 32 bytes (raw)
 *     || UTF8(canonicalJson(body))               ← RFC 8785
 *   )
 *
 * previousHash is the RAW 32-byte digest (never a variable-length string),
 * eliminating concatenation ambiguity. The stream's first event uses the
 * documented GENESIS previousHash: 32 zero bytes
 * (0000000000000000000000000000000000000000000000000000000000000000).
 *
 * Canonicalization is RFC 8785 via the existing crypto package — property
 * insertion order never affects the hash (tested explicitly).
 */
export const RECEIPT_HASH_DOMAIN = 'agent-trust/action-receipt/v1';
export const GENESIS_PREVIOUS_HASH = '0'.repeat(64);

export function hexToBytes32(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new TypeError('chain hash must be 64 lowercase hex chars (32 bytes)');
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)!;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function canonicalReceiptBytes(body: Omit<ActionReceiptBody, 'streamId' | 'sequence'> | ActionReceiptBody): Uint8Array {
  return utf8(canonicalJson(body));
}

export function computeEventHash(
  previousHash: string,
  body: Omit<ActionReceiptBody, 'streamId' | 'sequence'> | ActionReceiptBody,
): string {
  const domain = utf8(`${RECEIPT_HASH_DOMAIN}\0`);
  const prev = hexToBytes32(previousHash);
  const payload = canonicalReceiptBytes(body);
  const input = new Uint8Array(domain.length + prev.length + payload.length);
  input.set(domain, 0);
  input.set(prev, domain.length);
  input.set(payload, domain.length + prev.length);
  return bytesToHex(sha256(input));
}

/** Recompute an existing receipt's hash from its stored parts. */
export function receiptEventHash(receipt: ActionReceipt): string {
  return computeEventHash(receipt.previousHash, receipt.body);
}