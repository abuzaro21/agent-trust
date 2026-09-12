import { describe, expect, it } from 'vitest';

import {
  base58btcDecode,
  base58btcEncode,
  varintDecode,
  varintEncode,
} from '../src/index.js';

describe('base58btc', () => {
  it('encodes the canonical test vector', () => {
    expect(base58btcEncode(new TextEncoder().encode('hello world'))).toBe(
      'StV1DL6CwTryKyV',
    );
  });

  it('handles leading zero bytes', () => {
    expect(base58btcEncode(new Uint8Array([0, 0, 1]))).toBe('112');
    const round = base58btcDecode('112');
    expect(Array.from(round)).toEqual([0, 0, 1]);
  });

  it('roundtrips a 68-byte payload (varint + SEC1 point size)', () => {
    const bytes = new Uint8Array(68);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7) % 256;
    expect(Array.from(base58btcDecode(base58btcEncode(bytes)))).toEqual(Array.from(bytes));
  });

  it('rejects invalid characters', () => {
    expect(() => base58btcDecode('0OIl')).toThrow(TypeError);
  });
});

describe('varint', () => {
  it('encodes the P-256 multicodec 0x1200 as [0x80, 0x24]', () => {
    expect(Array.from(varintEncode(0x1200))).toEqual([0x80, 0x24]);
  });

  it('encodes multi-byte LEB128 correctly (0x8024 → 3 bytes)', () => {
    expect(Array.from(varintEncode(0x8024))).toEqual([0xa4, 0x80, 0x02]);
  });

  it('roundtrips small and large values', () => {
    for (const v of [0, 1, 127, 128, 300, 0x8024, 0x120000]) {
      expect(varintDecode(varintEncode(v)).value).toBe(v);
    }
  });

  it('rejects truncated varints', () => {
    expect(() => varintDecode(new Uint8Array([0x84, 0x80]))).toThrow(RangeError);
  });
});
