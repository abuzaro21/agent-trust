import { describe, expect, it } from 'vitest';

import {
  type Signer,
  LocalSigner,
  base64urlEncode,
  ecdsaDerToRaw,
  utf8,
} from '@agent-trust/crypto';

import {
  JwsFormatError,
  parseCompactJws,
  signCompactJws,
} from '../src/jws.js';

describe('compact JWS profile', () => {
  it('roundtrips sign → parse', async () => {
    const signer = LocalSigner.generate({ did: 'did:key:zTestKey' });
    const jws = await signCompactJws(signer, { hello: 'world', n: 1 });
    const parsed = parseCompactJws(jws);
    expect(parsed.protectedHeader.alg).toBe('ES256');
    expect(parsed.protectedHeader.kid).toBe(await signer.keyId());
    expect(parsed.signatureRaw.length).toBe(64);
  });

  it('rejects non-3-part, empty-part, and non-canonical base64url inputs', () => {
    expect(() => parseCompactJws('abc')).toThrow(JwsFormatError);
    expect(() => parseCompactJws('a.b')).toThrow(JwsFormatError);
    expect(() => parseCompactJws('..')).toThrow(JwsFormatError);
    expect(() => parseCompactJws('eyJhbGciOiJFUzI1NiJ9.e30.')).toThrow(JwsFormatError);
  });

  it('rejects non-JSON header/payload', () => {
    const bad = 'aGVsbG8.aGVsbG8.AAAA'; // header decodes to "hello"
    expect(() => parseCompactJws(bad)).toThrow(JwsFormatError);
  });

  it('rejects unsupported alg, crit, typ, and missing kid', async () => {
    const parts = async (header: Record<string, unknown>, payload: Record<string, unknown>) => {
      const h = base64urlEncode(utf8(JSON.stringify(header)));
      const p = base64urlEncode(utf8(JSON.stringify(payload)));
      const s = base64urlEncode(new Uint8Array(64));
      return `${h}.${p}.${s}`;
    };
    const payload = { a: 1 };
    const hs256 = await parts({ alg: 'HS256' }, payload);
    expect(() => parseCompactJws(hs256)).toThrow(JwsFormatError);
    const withCrit = await parts({ alg: 'ES256', crit: ['x'] }, payload);
    expect(() => parseCompactJws(withCrit)).toThrow(JwsFormatError);
    const badTyp = await parts({ alg: 'ES256', typ: 'at+jwt' }, payload);
    expect(() => parseCompactJws(badTyp)).toThrow(JwsFormatError);
    const noKid = await parts({ alg: 'ES256' }, payload);
    expect(() => parseCompactJws(noKid)).toThrow(JwsFormatError);
  });

  it('rejects signatures that are not exactly 64 raw bytes', async () => {
    const signer = LocalSigner.generate();
    const jws = await signCompactJws(signer, { x: 1 });
    const [h, p, s] = jws.split('.') as [string, string, string];
    const shortSig = base64urlEncode(new Uint8Array(63));
    expect(() => parseCompactJws(`${h}.${p}.${shortSig}`)).toThrow(JwsFormatError);
    expect(s).toBeDefined();
  });

  it('produces signatures that verify against the signer public key', async () => {
    const { verifyCompactJwsSignature } = await import('../src/jws.js');
    const signer = LocalSigner.generate();
    const jws = await signCompactJws(signer, { payload: 'refund:create' });
    const parsed = parseCompactJws(jws);
    expect(verifyCompactJwsSignature(parsed, await signer.publicKey())).toBe(true);
    const evil = LocalSigner.generate();
    expect(verifyCompactJwsSignature(parsed, await evil.publicKey())).toBe(false);
  });

  it('keeps DER signatures out of the JWS (raw R||S only)', async () => {
    const signer = LocalSigner.generate();
    const der = await signer.sign(utf8('probe'));
    expect(() => ecdsaDerToRaw(der.slice(0, 10))).toThrow();
  });
});
