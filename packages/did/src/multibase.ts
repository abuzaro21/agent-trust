/**
 * Minimal base58btc (Bitcoin alphabet) + varint encoding, enough for
 * did:key P-256 identifiers with zero external dependencies.
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = 58n;

export function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  let num = 0n;
  for (const b of bytes) num = (num << 8n) | BigInt(b);
  let encoded = '';
  while (num > 0n) {
    const rem = num % BASE;
    num = num / BASE;
    encoded = BASE58_ALPHABET[Number(rem)] + encoded;
  }
  // Leading zero bytes encode as leading '1's.
  for (const b of bytes) {
    if (b !== 0) break;
    encoded = `1${encoded}`;
  }
  return encoded;
}

export function base58btcDecode(encoded: string): Uint8Array {
  if (encoded.length === 0) return new Uint8Array(0);
  let num = 0n;
  for (const char of encoded) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new TypeError(`base58btcDecode: invalid character "${char}"`);
    }
    num = num * BASE + BigInt(index);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num = num >> 8n;
  }
  // Leading '1's decode as leading zero bytes.
  for (const char of encoded) {
    if (char !== '1') break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

/** Unsigned LEB128 varint (multicodec table keys). */
export function varintEncode(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError('varintEncode requires a non-negative integer');
  }
  const out: number[] = [];
  let v = value;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return new Uint8Array(out);
}

export function varintDecode(bytes: Uint8Array, offset = 0): { value: number; next: number } {
  let result = 0;
  let shift = 0;
  let i = offset;
  for (;;) {
    const byte = bytes[i];
    if (byte === undefined) {
      throw new RangeError('varintDecode: truncated input');
    }
    result += (byte & 0x7f) * 2 ** shift;
    i += 1;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > 63) throw new RangeError('varintDecode: varint too long');
  }
  return { value: result, next: i };
}
