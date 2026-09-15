import type { DidDocument, DidResolutionResult, DidResolver, VerificationMethod } from './types.js';
import {
  DidWebTransportError,
  NodeHttpsDidWebClient,
  assertDestinationAllowed,
  type DidWebHttpClient,
  type DidWebHttpResponse,
  type DidWebNetworkPolicy,
} from './did-web-transport.js';

/**
 * did:web resolver (Step 12) — W3C DID Core data model resolved through
 * the Web DID Method specification (an independent W3C DID Method spec,
 * distinct from the DID Core Recommendation).
 *
 * Resolution contract implemented here:
 *
 *  1. STRICT method-specific-id parsing (12C): host[:path-segments],
 *     percent-decoded port only, no query/fragment, no IP literals,
 *     no traversal — malformed identifiers are invalidDid, and WHATWG
 *     URL normalization never rescues an invalid DID.
 *  2. HTTPS URL derivation (12B): root → /.well-known/did.json,
 *     path DID → <path>/did.json, %3A port decoding.
 *  3. Network (12D–12J): HTTPS-only, no redirects, allowlist-capable
 *     policy, private-address blocking, DNS-rebinding-pinned transport,
 *     hard timeout, hard size cap.
 *  4. Document validation (12L–12P): strict JSON object, EXACT document
 *     id binding (did:web spec requirement), structural verification
 *     methods, absolute DID-URL method ids, P-256/ES256-only public JWKs
 *     with no private key material.
 *  5. Cache (12Q–12T): keyed by exact DID, validated documents only,
 *     injected clock, Cache-Control max-age capped by maxCacheTtl,
 *     noCache/forceRefresh, fresh-cache-on-network-failure allowed,
 *     stale-cache fail-closed.
 *
 * did:web inherits its trust from DNS + HTTPS + the hosting domain.
 * This resolver makes that dependency explicit and bounded; it does not
 * pretend the method is decentralized from those systems (ADR-0004).
 */

export interface DidWebCacheEntry {
  document: DidDocument;
  fetchedAt: number;
  expiresAt: number;
}

export interface DidWebResolverOptions {
  /** The ONLY network path. Default: NodeHttpsDidWebClient. */
  http?: DidWebHttpClient;
  /** Host/port/private-IP policy. Default: blockPrivateNetworks only. */
  networkPolicy?: DidWebNetworkPolicy;
  /** Hard request timeout. Default 5_000 ms. */
  timeoutMs?: number;
  /** Hard response-size cap. Default 256 KiB. */
  maxBytes?: number;
  /** Upper bound on cache lifetime regardless of server headers. Default 1h. */
  maxCacheTtlMs?: number;
  /** Cache lifetime when the server sends no usable max-age. Default 5 min. */
  defaultCacheTtlMs?: number;
  /** Injected clock (unix ms) for deterministic cache tests. */
  clock?: () => number;
}

export type ResolveOptions = {
  /** Bypass a cached entry and fetch fresh (key rotation, incident response). */
  noCache?: boolean;
};

const DID_WEB_PREFIX = 'did:web:';
/** DID documents hold a handful of keys; 64 KiB is a generous ceiling. */
const MAX_DOCUMENT_JSON_BYTES = 64 * 1024;
const MAX_DID_LENGTH = 256;
const MAX_PATH_SEGMENTS = 16;
const MAX_SEGMENT_LENGTH = 128;

// ------------------------------------------------------------ strict parser

export interface ParsedDidWeb {
  host: string;
  port: number | null;
  pathSegments: string[];
}

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Strict did:web method-specific identifier parser (Step 12C).
 * Deterministic: every rejection is a rejection — no URL normalization
 * can turn an invalid DID into a different valid target.
 */
export function parseDidWebIdentifier(did: string): ParsedDidWeb {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new SyntaxError('not a did:web identifier');
  }
  const msi = did.slice(DID_WEB_PREFIX.length);
  if (msi.length === 0) throw new SyntaxError('empty method-specific identifier');
  if (msi.length > MAX_DID_LENGTH) throw new SyntaxError('DID exceeds maximum length');
  // denoc-control: control characters are rejected, not normalized.
  if (/\p{Cc}/u.test(msi)) throw new SyntaxError('control characters are not permitted');
  if (msi.includes('\\')) throw new SyntaxError('backslashes are not permitted');
  if (msi.includes('?')) throw new SyntaxError('query components are not permitted');
  if (msi.includes('#')) throw new SyntaxError('fragments are not permitted in the base DID');
  if (msi.includes('%') && !/%[0-9A-Fa-f]{2}/.test(msi)) {
    throw new SyntaxError('invalid percent-encoding');
  }
  if (msi.includes('@') || msi.includes('/') || msi.includes('//')) {
    throw new SyntaxError('userinfo or path characters are not permitted in the identifier');
  }

  const rawParts = msi.split(':');
  if (rawParts.length - 1 > MAX_PATH_SEGMENTS) throw new SyntaxError('too many path segments');

  // Host (first segment): optional %3A-encoded port, then strict hostname.
  const hostPart = rawParts[0]!;
  if (hostPart.length === 0) throw new SyntaxError('empty host');
  let hostToken = hostPart;
  let port: number | null = null;
  const portIndex = hostPart.toUpperCase().lastIndexOf('%3A');
  if (portIndex !== -1) {
    hostToken = hostPart.slice(0, portIndex);
    const portToken = hostPart.slice(portIndex + 3);
    if (!/^\d{1,5}$/.test(portToken)) throw new SyntaxError('invalid encoded port');
    port = Number(portToken);
    if (port < 1 || port > 65_535) throw new SyntaxError('encoded port out of range');
  }
  if (hostToken.length === 0) throw new SyntaxError('empty host');
  if (hostToken.includes('%')) throw new SyntaxError('unexpected percent-encoding in host');
  const host = hostToken.toLowerCase();
  if (host.includes('..')) throw new SyntaxError('empty host label');
  // IP literals are not valid did:web hosts (method spec: domain/host only).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) throw new SyntaxError('IP-literal hosts are not permitted');
  if (host.startsWith('[') || host.includes(':')) throw new SyntaxError('IP-literal hosts are not permitted');
  for (const label of host.split('.')) {
    if (!LABEL.test(label)) {
      throw new SyntaxError(`invalid hostname label: ${label}`);
    }
  }

  // Path segments: decoded strictly, then re-validated (decoding must not
  // create traversal or separators).
  const pathSegments: string[] = [];
  for (const raw of rawParts.slice(1)) {
    if (raw.length === 0) throw new SyntaxError('empty path segment');
    if (raw.length > MAX_SEGMENT_LENGTH) throw new SyntaxError('path segment exceeds maximum length');
    const decoded = safeDecode(raw);
    if (decoded.includes('/') || decoded.includes('\\')) {
      throw new SyntaxError('encoded path separators are not permitted');
    }
    if (decoded === '.' || decoded === '..') {
      throw new SyntaxError('dot segments are not permitted');
    }
    if (/\p{Cc}/u.test(decoded)) throw new SyntaxError('control characters in path segment');
    if (!/^[A-Za-z0-9._~-]+$/.test(decoded)) {
      throw new SyntaxError(`invalid path segment characters: ${decoded}`);
    }
    pathSegments.push(decoded);
  }

  return { host, port, pathSegments };
}

function safeDecode(token: string): string {
  try {
    return decodeURIComponent(token);
  } catch {
    throw new SyntaxError('invalid percent-encoding');
  }
}

/** did:web → HTTPS URL (Step 12B). Throws on malformed identifiers. */
export function didWebToUrl(did: string): URL {
  const parsed = parseDidWebIdentifier(did);
  const hostPort = parsed.port === null ? parsed.host : `${parsed.host}:${parsed.port}`;
  const path =
    parsed.pathSegments.length === 0
      ? '.well-known/did.json'
      : `${parsed.pathSegments.join('/')}/did.json`;
  const url = new URL(`https://${hostPort}/${path}`);
  // The URL constructor could normalize in surprising ways for odd hosts —
  // assert the derivation stayed exactly as computed.
  assertDestinationAllowed(url, { blockPrivateNetworks: true });
  return url;
}

// ------------------------------------------------------------ document validation

const PRIVATE_JWK_FIELDS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv', 'privateKey']);

export type DocumentValidation =
  | { ok: true; document: DidDocument }
  | { ok: false; reason: string };

/**
 * Validate a retrieved DID document (Step 12L–12P): exact id binding,
 * structural verification methods, absolute method ids owned by THIS
 * document's DID, P-256 public JWKs only, no private key material.
 * `expectedKid`, when provided, requires that exact method to exist
 * (Step 12O: never silently fall back to an arbitrary other key).
 */
export function validateDidWebDocument(
  body: unknown,
  expectedDid: string,
  opts: { expectedKid?: string } = {},
): DocumentValidation {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { ok: false, reason: 'document is not a JSON object' };
  }
  const doc = body as Record<string, unknown>;

  if (typeof doc.id !== 'string' || doc.id.length === 0) {
    return { ok: false, reason: 'document.id missing' };
  }
  // did:web spec: the returned document id MUST match the requested DID.
  if (doc.id !== expectedDid) {
    return { ok: false, reason: `document.id mismatch: ${doc.id}` };
  }

  const methodsRaw = doc.verificationMethod;
  if (methodsRaw === undefined) {
    return { ok: false, reason: 'no verificationMethod present' };
  }
  if (!Array.isArray(methodsRaw) || methodsRaw.length === 0) {
    return { ok: false, reason: 'verificationMethod must be a non-empty array' };
  }
  if (methodsRaw.length > 16) {
    return { ok: false, reason: 'too many verification methods' };
  }

  const methods: VerificationMethod[] = [];
  for (const m of methodsRaw) {
    if (typeof m !== 'object' || m === null || Array.isArray(m)) {
      return { ok: false, reason: 'verification method is not an object' };
    }
    const method = m as Record<string, unknown>;
    if (typeof method.id !== 'string' || method.id.length === 0) {
      return { ok: false, reason: 'verification method id missing' };
    }
    // Method ids must be absolute DID URLs anchored at THIS document's DID
    // (kid ownership, Step 12P) — a relative id or a foreign DID fails.
    if (!method.id.startsWith(`${expectedDid}#`)) {
      return { ok: false, reason: `verification method id is not owned by ${expectedDid}: ${method.id}` };
    }
    if (method.controller !== undefined && method.controller !== expectedDid) {
      return { ok: false, reason: 'verification method controller mismatch' };
    }
    if (typeof method.type !== 'string') {
      return { ok: false, reason: 'verification method type missing' };
    }

    const jwk = method.publicKeyJwk;
    if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
      return { ok: false, reason: 'publicKeyJwk missing' };
    }
    const jwkCheck = validatePublicJwk(jwk as Record<string, unknown>);
    if (!jwkCheck.ok) return { ok: false, reason: jwkCheck.reason };

    methods.push({
      id: method.id,
      type: method.type,
      controller: expectedDid,
      publicKeyJwk: jwkCheck.jwk,
    });
  }

  if (opts.expectedKid !== undefined) {
    const requested = methods.find((m) => m.id === opts.expectedKid);
    if (requested === undefined) {
      return {
        ok: false,
        reason: `requested kid not present in document (key rotation or forgery): ${opts.expectedKid}`,
      };
    }
  }

  return {
    ok: true,
    document: {
      id: expectedDid,
      verificationMethod: methods,
      ...(Array.isArray(doc.authentication) || typeof doc.authentication === 'string'
        ? { authentication: doc.authentication as DidDocument['authentication'] }
        : {}),
    },
  };
}

/** P-256 EC public JWK only (Step 12O) — no private material (Step 12N). */
export function validatePublicJwk(
  jwk: Record<string, unknown>,
): { ok: true; jwk: import('@agent-trust/crypto').PublicJwk } | { ok: false; reason: string } {
  for (const field of PRIVATE_JWK_FIELDS) {
    if (field in jwk) {
      return { ok: false, reason: `private JWK field present: ${field}` };
    }
  }
  if (jwk.kty !== 'EC') return { ok: false, reason: `unsupported kty: ${String(jwk.kty)}` };
  if (jwk.crv !== 'P-256') return { ok: false, reason: `unsupported curve: ${String(jwk.crv)}` };
  if (typeof jwk.x !== 'string' || jwk.x.length === 0) return { ok: false, reason: 'x coordinate missing' };
  if (typeof jwk.y !== 'string' || jwk.y.length === 0) return { ok: false, reason: 'y coordinate missing' };
  // Base64url shape check (deterministic rejection of garbage coordinates).
  if (!/^[A-Za-z0-9_-]+$/.test(jwk.x) || !/^[A-Za-z0-9_-]+$/.test(jwk.y)) {
    return { ok: false, reason: 'malformed coordinate encoding' };
  }
  return { ok: true, jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
}

// ------------------------------------------------------------ cache TTL parsing

/** Cache-Control max-age (seconds), when safely parseable. */
export function cacheMaxAgeSeconds(headers: Record<string, string>): number | null {
  const cc = headers['cache-control'] ?? headers['Cache-Control'];
  if (cc === undefined) return null;
  const m = /(?:^|,)\s*max-age\s*=\s*(\d{1,9})\s*(?:,|$)/i.exec(cc);
  if (!m) return null;
  const value = Number(m[1]);
  return Number.isFinite(value) ? value : null;
}

// ------------------------------------------------------------ resolver

export class WebDidResolver implements DidResolver {
  readonly #http: DidWebHttpClient;
  readonly #policy: DidWebNetworkPolicy;
  readonly #timeoutMs: number;
  readonly #maxBytes: number;
  readonly #maxCacheTtlMs: number;
  readonly #defaultCacheTtlMs: number;
  readonly #clock: () => number;
  readonly #cache = new Map<string, DidWebCacheEntry>();

  constructor(opts: DidWebResolverOptions = {}) {
    this.#policy = opts.networkPolicy ?? { blockPrivateNetworks: true };
    // The default transport mirrors the resolver's network policy so a
    // local-test override can never bypass the resolver-level check.
    this.#http =
      opts.http ??
      new NodeHttpsDidWebClient({ allowPrivateNetworks: !this.#policy.blockPrivateNetworks });
    this.#timeoutMs = opts.timeoutMs ?? 5_000;
    this.#maxBytes = opts.maxBytes ?? 256 * 1024;
    this.#maxCacheTtlMs = opts.maxCacheTtlMs ?? 3_600_000;
    this.#defaultCacheTtlMs = opts.defaultCacheTtlMs ?? 300_000;
    this.#clock = opts.clock ?? (() => Date.now());
  }

  supports(did: string): boolean {
    return did.startsWith(DID_WEB_PREFIX);
  }

  /** Cache introspection for demos/tests (never a trust decision input). */
  peekCache(did: string): DidWebCacheEntry | undefined {
    return this.#cache.get(did);
  }

  async resolve(did: string, options?: ResolveOptions): Promise<DidResolutionResult> {
    if (!this.supports(did)) {
      return { didDocument: null, didResolutionMetadata: { error: 'methodUnsupported' } };
    }

    // Parse FIRST (12C) — malformed identifiers never touch cache or net.
    let url: URL;
    try {
      url = didWebToUrl(did);
    } catch (e) {
      return { didDocument: null, didResolutionMetadata: { error: 'invalidDid', message: String(e) } };
    }
    // Host policy applies to the derived destination even before fetch.
    try {
      assertDestinationAllowed(url, this.#policy);
    } catch (e) {
      return { didDocument: null, didResolutionMetadata: { error: 'internalError', message: String(e) } };
    }

    const now = this.#clock();
    const cached = this.#cache.get(did);
    const hasFreshCache = cached !== undefined && cached.expiresAt > now;

    if (cached !== undefined && hasFreshCache && !options?.noCache) {
      return {
        didDocument: cached.document,
        didResolutionMetadata: { contentType: 'application/did+json' },
      };
    }

    let response: DidWebHttpResponse;
    try {
      response = await this.#http.get(url, { timeoutMs: this.#timeoutMs, maxBytes: this.#maxBytes });
    } catch (e) {
      // 12T: fresh cache MAY serve during network failure; stale fails closed.
      if (e instanceof DidWebTransportError && e.code === 'TIMEOUT') {
        return this.#fail(did, hasFreshCache, cached, 'resolution timeout');
      }
      if (e instanceof DidWebTransportError && e.code === 'TOO_LARGE') {
        return this.#fail(did, hasFreshCache, cached, 'response exceeded size limit');
      }
      return this.#fail(did, hasFreshCache, cached, `network failure: ${String(e)}`);
    }

    // 12K: deterministic status handling. Redirects are REJECTED (12I).
    if (response.status === 404 || response.status === 410) {
      return { didDocument: null, didResolutionMetadata: { error: 'notFound' } };
    }
    if (response.status >= 300 && response.status < 400) {
      return {
        didDocument: null,
        didResolutionMetadata: {
          error: 'internalError',
          message: `redirect rejected by policy (HTTP ${response.status})`,
        },
      };
    }
    if (response.status !== 200) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'internalError', message: `HTTP ${response.status}` },
      };
    }

    // 12L: strict JSON, object only, bounded.
    if (Buffer.byteLength(response.body, 'utf8') > MAX_DOCUMENT_JSON_BYTES) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'representationNotSupported', message: 'document exceeds maximum size' },
      };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body);
    } catch {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'representationNotSupported', message: 'body is not valid JSON' },
      };
    }

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'representationNotSupported', message: 'document is not a JSON object' },
      };
    }
    const validation = validateDidWebDocument(parsed, did);
    if (!validation.ok) {
      // 12Q: invalid documents are NEVER cached.
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'invalidDid', message: `DID document invalid: ${validation.reason}` },
      };
    }

    // 12R/13-prestep: TTL = min(server max-age, maxCacheTtl); bounded default
    // only when the server sends NO usable lifetime. An explicit max-age=0
    // means the representation is IMMEDIATELY STALE — the entry is not
    // installed as fresh (during key compromise the server must win: the
    // next resolution always re-fetches). The configured defaultCacheTtl
    // applies ONLY to the no-header case and is deliberately documented
    // (ADR-0004).
    const maxAge = cacheMaxAgeSeconds(response.headers);
    if (maxAge === 0) {
      return {
        didDocument: validation.document,
        didResolutionMetadata: {
          contentType: 'application/did+json',
          message: 'served without caching (Cache-Control: max-age=0)',
        },
      };
    }
    const ttlMs =
      maxAge === null
        ? this.#defaultCacheTtlMs
        : Math.min(maxAge * 1000, this.#maxCacheTtlMs);
    this.#cache.set(did, {
      document: validation.document,
      fetchedAt: now,
      expiresAt: now + Math.max(ttlMs, 1),
    });

    return {
      didDocument: validation.document,
      didResolutionMetadata: { contentType: 'application/did+json' },
    };
  }

  #fail(
    _did: string,
    hasFreshCache: boolean,
    cached: DidWebCacheEntry | undefined,
    detail: string,
  ): DidResolutionResult {
    if (hasFreshCache && cached !== undefined) {
      // Documented P0 semantics: a FRESH validated document may serve
      // through a transient network failure (12T). This branch only fires
      // while expiresAt > now; a stale entry falls through to fail-closed.
      return {
        didDocument: cached.document,
        didResolutionMetadata: {
          contentType: 'application/did+json',
          message: `served from fresh cache during network failure: ${detail}`,
        },
      };
    }
    return {
      didDocument: null,
      didResolutionMetadata: {
        error: 'internalError',
        message: `${detail}${cached !== undefined ? ' (stale cache present — fail closed)' : ''}`,
      },
    };
  }
}
