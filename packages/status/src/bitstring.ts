import { base64urlDecode, base64urlEncode } from '@agent-trust/crypto';

/**
 * Minimal W3C Bitstring Status List bitstring (demo profile).
 *
 * Bit order follows the spec: for statusListIndex i, the bit lives in
 * byte i >> 3 at mask 0x80 >> (i & 7) — most-significant-bit first within
 * each byte. Encoding is plain base64url (the spec's full multibase 'u'
 * wrapper is omitted for the demo and noted as a deviation).
 *
 * Status lists here are small (default 1024 bits); the production minimum
 * (131072 bits) is a sizing concern, not a semantic one.
 */
export class StatusBitstring {
  readonly #bytes: Uint8Array;
  readonly #sizeBits: number;

  constructor(sizeBits: number) {
    if (!Number.isInteger(sizeBits) || sizeBits <= 0 || sizeBits % 8 !== 0) {
      throw new RangeError('sizeBits must be a positive multiple of 8');
    }
    this.#sizeBits = sizeBits;
    this.#bytes = new Uint8Array(sizeBits >> 3);
  }

  get sizeBits(): number {
    return this.#sizeBits;
  }

  #checkIndex(index: number): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.#sizeBits) {
      throw new RangeError(`status index ${index} out of range [0, ${this.#sizeBits})`);
    }
  }

  /** W3C bit convention: byte = i >> 3, mask = 0x80 >> (i & 7). */
  get(index: number): boolean {
    this.#checkIndex(index);
    return (this.#bytes[index >> 3]! & (0x80 >> (index & 7))) !== 0;
  }

  set(index: number, value = true): void {
    this.#checkIndex(index);
    const mask = 0x80 >> (index & 7);
    if (value) {
      this.#bytes[index >> 3]! |= mask;
    } else {
      this.#bytes[index >> 3]! &= ~mask & 0xff;
    }
  }

  /** First index whose bit is unset, or null when full. */
  firstUnset(): number | null {
    for (let i = 0; i < this.#sizeBits; i++) {
      if (!this.get(i)) return i;
    }
    return null;
  }

  toBase64Url(): string {
    return base64urlEncode(this.#bytes);
  }

  static fromBase64Url(encoded: string, expectedBits?: number): StatusBitstring {
    let bytes: Uint8Array;
    try {
      bytes = base64urlDecode(encoded);
    } catch {
      throw new TypeError('status bitstring is not valid base64url');
    }
    // Canonical re-encode: Buffer tolerates loose inputs; we do not.
    if (base64urlEncode(bytes) !== encoded) {
      throw new TypeError('status bitstring is not canonical base64url');
    }
    const bits = bytes.length << 3;
    if (expectedBits !== undefined && bits !== expectedBits) {
      throw new TypeError(`status bitstring is ${bits} bits, expected ${expectedBits}`);
    }
    const list = new StatusBitstring(bits);
    list.#bytes.set(bytes);
    return list;
  }

  /** Semantic (bit-level) equality, independent of encoding details. */
  equalsBits(other: StatusBitstring): boolean {
    return this.#sizeBits === other.#sizeBits && this.toBase64Url() === other.toBase64Url();
  }
}
