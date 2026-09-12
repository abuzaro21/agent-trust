import type { DidResolutionResult, DidResolver } from './types.js';

/**
 * did:web resolver (ADR-0001: the P0 live-demo method).
 *
 * did:web:example.com               → https://example.com/.well-known/did.json
 * did:web:example.com:agents:ref-1  → https://example.com/agents/ref-1/did.json
 * did:web:example.com%3A8443        → https://example.com:8443/.well-known/did.json
 *
 * Threat model (DID resolution abuse): fetch is injectable for tests,
 * requests carry a hard timeout, and query/fragment characters in the DID
 * are rejected — the DID itself is the allowlist of what we will fetch.
 */

const DID_WEB_PREFIX = 'did:web:';

export function didWebToUrl(did: string): URL {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new TypeError('not a did:web identifier');
  }
  if (did.includes('?') || did.includes('#')) {
    throw new TypeError('did:web identifiers must not contain query or fragment parts');
  }
  const parts = did.slice(DID_WEB_PREFIX.length).split(':');
  if (parts.length === 0 || parts.some((p) => p.length === 0)) {
    throw new TypeError('did:web identifier has empty path components');
  }
  const domain = decodeURIComponent(parts[0]!).toLowerCase();
  const pathSegments = parts.slice(1).map((p) => decodeURIComponent(p));
  const url =
    `https://${domain}/` +
    (pathSegments.length === 0
      ? '.well-known/did.json'
      : `${pathSegments.join('/')}/did.json`);
  return new URL(url);
}

export interface DidWebResolverOptions {
  /** Injectable for tests — defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Hard per-request timeout. Default 5s. */
  timeoutMs?: number;
}

export class DidWebResolver implements DidResolver {
  readonly #fetchImpl: typeof fetch;
  readonly #timeoutMs: number;

  constructor(opts: DidWebResolverOptions = {}) {
    this.#fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = opts.timeoutMs ?? 5_000;
  }

  supports(did: string): boolean {
    return did.startsWith('did:web:');
  }

  async resolve(did: string): Promise<DidResolutionResult> {
    if (!this.supports(did)) {
      return { didDocument: null, didResolutionMetadata: { error: 'methodUnsupported' } };
    }
    let url: URL;
    try {
      url = didWebToUrl(did);
    } catch (e) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'invalidDid', message: String(e) },
      };
    }

    let response: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
      try {
        response = await this.#fetchImpl(url.toString(), {
          signal: controller.signal,
          headers: { accept: 'application/did+json, application/json' },
        });
      } finally {
        clearTimeout(timer);
      }
    } catch (e) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'internalError', message: `fetch failed: ${String(e)}` },
      };
    }

    if (response.status === 404) {
      return { didDocument: null, didResolutionMetadata: { error: 'notFound' } };
    }
    if (!response.ok) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'internalError', message: `HTTP ${response.status}` },
      };
    }

    let doc: unknown;
    try {
      doc = await response.json();
    } catch {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'representationNotSupported' },
      };
    }

    if (
      typeof doc !== 'object' ||
      doc === null ||
      typeof (doc as { id?: unknown }).id !== 'string'
    ) {
      return {
        didDocument: null,
        didResolutionMetadata: { error: 'representationNotSupported' },
      };
    }
    return {
      didDocument: doc as { id: string },
      didResolutionMetadata: { contentType: 'application/did+json' },
    } as DidResolutionResult;
  }
}
