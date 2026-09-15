import { describe, expect, it } from 'vitest';

import { base64urlEncode } from '@agent-trust/crypto';

import { StatusBitstring } from '../src/bitstring.js';

describe('StatusBitstring — W3C bit order', () => {
  it('uses most-significant-bit-first within each byte (spec order)', () => {
    const bits = new StatusBitstring(16);
    bits.set(0);
    // index 0 → byte0 bit7 → [0x80, 0x00]
    expect(bits.toBase64Url()).toBe(base64urlEncode(new Uint8Array([0x80, 0x00])));
    bits.set(7);
    // index 7 → byte0 bit0 → [0x81, 0x00]
    expect(bits.toBase64Url()).toBe(base64urlEncode(new Uint8Array([0x81, 0x00])));
    bits.set(8);
    // index 8 → byte1 bit7 → [0x81, 0x80]
    expect(bits.toBase64Url()).toBe(base64urlEncode(new Uint8Array([0x81, 0x80])));
    bits.set(9);
    expect(bits.toBase64Url()).toBe(base64urlEncode(new Uint8Array([0x81, 0xc0])));
  });

  it('sets and clears boundary indexes without leaking to neighbors', () => {
    const bits = new StatusBitstring(64);
    for (const i of [0, 1, 7, 8, 9, 31, 32, 63]) {
      bits.set(i);
      expect(bits.get(i)).toBe(true);
      const neighbors = [i - 1, i + 1].filter((n) => n >= 0 && n < 64 && n !== i);
      for (const n of neighbors) {
        expect(bits.get(n)).toBe(false);
      }
      bits.set(i); // idempotent
      expect(bits.get(i)).toBe(true);
      bits.set(i, false);
      expect(bits.get(i)).toBe(false);
    }
  });

  it('rejects out-of-range and non-integer indexes', () => {
    const bits = new StatusBitstring(64);
    expect(() => bits.get(-1)).toThrow(RangeError);
    expect(() => bits.get(64)).toThrow(RangeError);
    expect(() => bits.set(1.5, true)).toThrow(RangeError);
    expect(() => bits.get(Number.NaN)).toThrow(RangeError);
  });

  it('rejects invalid sizes', () => {
    expect(() => new StatusBitstring(0)).toThrow(RangeError);
    expect(() => new StatusBitstring(12)).toThrow(RangeError); // not a byte multiple
  });
});

describe('StatusBitstring — encode/decode roundtrip', () => {
  it('roundtrips every bit position', () => {
    const bits = new StatusBitstring(128);
    for (let i = 0; i < 128; i += 3) bits.set(i);
    const decoded = StatusBitstring.fromBase64Url(bits.toBase64Url(), 128);
    for (let i = 0; i < 128; i++) {
      expect(decoded.get(i)).toBe(i % 3 === 0);
    }
    expect(decoded.equalsBits(bits)).toBe(true);
  });

  it('rejects non-canonical and malformed encodings', () => {
    expect(() => StatusBitstring.fromBase64Url('not+base64url!')).toThrow(TypeError);
    expect(() => StatusBitstring.fromBase64Url('AA==')).toThrow(TypeError); // padding is not base64url-canonical
    expect(() => StatusBitstring.fromBase64Url('', 8)).toThrow(TypeError); // 0 bits ≠ 8 expected
  });

  it('enforces the expected bit length when given', () => {
    const bits = new StatusBitstring(64);
    expect(() => StatusBitstring.fromBase64Url(bits.toBase64Url(), 128)).toThrow(TypeError);
    expect(() => StatusBitstring.fromBase64Url(bits.toBase64Url(), 64)).not.toThrow();
  });

  it('firstUnset scans from index 0', () => {
    const bits = new StatusBitstring(16);
    expect(bits.firstUnset()).toBe(0);
    bits.set(0);
    expect(bits.firstUnset()).toBe(1);
    for (let i = 0; i < 16; i++) bits.set(i);
    expect(bits.firstUnset()).toBeNull();
  });
});
