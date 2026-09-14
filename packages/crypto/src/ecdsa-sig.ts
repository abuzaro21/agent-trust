/**
 * ECDSA signature format conversion between node:crypto (DER SEQUENCE of
 * two INTEGERs) and JWS ES256 (RFC 7518 §3.4: fixed-width 64-byte R||S,
 * a.k.a. P1363). This is pure ASN.1/encoding work — no curve mathematics.
 */

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function readDerInteger(bytes: Uint8Array, offset: number): { value: Uint8Array; next: number } {
  const tag = bytes[offset];
  if (tag !== 0x02) {
    throw new TypeError(`ecdsa: expected INTEGER tag at offset ${offset}`);
  }
  const len = bytes[offset + 1];
  if (len === undefined) {
    throw new TypeError('ecdsa: truncated INTEGER length');
  }
  if ((len & 0x80) !== 0) {
    throw new TypeError('ecdsa: long-form DER lengths unsupported (P-256 never needs them)');
  }
  const start = offset + 2;
  const end = start + len;
  if (end > bytes.length) {
    throw new TypeError('ecdsa: INTEGER overruns buffer');
  }
  return { value: bytes.slice(start, end), next: end };
}

/** Left-align-stripped integer bytes, right-aligned into exactly 32 bytes. */
function toFixed32(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length && value[start] === 0) start++;
  const stripped = value.slice(start);
  if (stripped.length > 32) {
    throw new TypeError('ecdsa: integer exceeds 32 bytes (not a P-256 value)');
  }
  const out = new Uint8Array(32);
  out.set(stripped, 32 - stripped.length);
  return out;
}

/** DER → 64-byte R||S. */
export function ecdsaDerToRaw(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) {
    throw new TypeError('ecdsa: not a DER SEQUENCE');
  }
  const seqLen = der[1];
  if (seqLen === undefined || (seqLen & 0x80) !== 0) {
    throw new TypeError('ecdsa: unsupported DER SEQUENCE length');
  }
  const r = readDerInteger(der, 2);
  const s = readDerInteger(der, r.next);
  if (s.next !== der.length) {
    throw new TypeError('ecdsa: trailing bytes after signature');
  }
  return concat(toFixed32(r.value), toFixed32(s.value));
}

function derIntegerFrom32(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < 32 && value[start] === 0) start++;
  const stripped = value.slice(start);
  // INTEGER 0 encodes as a single 0x00 byte.
  const body = stripped.length === 0 ? new Uint8Array([0]) : stripped;
  // DER integers are two's complement: prepend 0x00 when the high bit is set.
  const padded = (body[0] ?? 0) & 0x80 ? concat(new Uint8Array([0]), body) : body;
  if (padded.length > 127) {
    throw new TypeError('ecdsa: integer too long for short-form DER');
  }
  return concat(new Uint8Array([0x02, padded.length]), padded);
}

/** 64-byte R||S → DER. */
export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) {
    throw new TypeError('ecdsa: raw P-256 signatures are exactly 64 bytes');
  }
  const body = concat(
    derIntegerFrom32(raw.slice(0, 32)),
    derIntegerFrom32(raw.slice(32, 64)),
  );
  return concat(new Uint8Array([0x30, body.length]), body);
}
