import { isIP } from 'node:net';

/**
 * did:web transport layer (Step 12E–12J).
 *
 * The resolver derives a network destination from EXTERNALLY SUPPLIED
 * identity data, so outbound fetching is an SSRF boundary. This module
 * centralizes ALL outbound-network security for did:web resolution:
 *
 *  - HTTPS only, by construction (URLs are built with the https scheme;
 *    the client refuses anything else).
 *  - No redirects are followed (Step 12I) — the client performs exactly
 *    one request and hands the raw status to the caller.
 *  - A configurable network policy (host allowlist, port allowlist).
 *  - Address-safety classification: loopback, RFC1918, link-local,
 *    multicast, unspecified, CGNAT, ULA, IPv4-mapped and NAT64 forms are
 *    rejected before any connection when blockPrivateNetworks is set.
 *  - DNS-rebinding protection (Step 12H): the hostname is resolved ONCE,
 *    EVERY returned address is classified, and the connection is pinned
 *    to the validated address via a custom `lookup` — the address that is
 *    validated is the address used for the connection. There is no second
 *    resolution a rebinding attacker could race.
 *  - Hard timeout and a hard response-size cap (Step 12J); the body is
 *    streamed and truncated-connection aborted, never read unbounded.
 *
 * Tests inject either a full DidWebHttpClient double or (for the real
 * client) an injectable dnsLookup/httpRequest pair — production code
 * paths are exercised with controlled network data, never real private
 * infrastructure.
 */

export type DidWebTransportErrorCode = 'TIMEOUT' | 'NETWORK' | 'TOO_LARGE' | 'POLICY';

export class DidWebTransportError extends Error {
  readonly code: DidWebTransportErrorCode;
  constructor(code: DidWebTransportErrorCode, message: string) {
    super(message);
    this.name = 'DidWebTransportError';
    this.code = code;
  }
}

export interface DidWebFetchOptions {
  /** Hard total-time budget for the request. */
  timeoutMs: number;
  /** Hard cap on response body bytes. */
  maxBytes: number;
}

export interface DidWebHttpResponse {
  status: number;
  headers: Record<string, string>;
  /** Response body as UTF-8 text, already size-capped by the transport. */
  body: string;
}

/** The ONLY way did:web resolution touches the network. */
export interface DidWebHttpClient {
  get(url: URL, options: DidWebFetchOptions): Promise<DidWebHttpResponse>;
}

export interface DidWebNetworkPolicy {
  /**
   * When set, the resolved hostname must match one of these entries
   * (case-insensitive; an entry matches itself and its subdomains).
   * The public demo pins its single DID domain here.
   */
  allowedHosts?: readonly string[];
  /** When set, the (explicit or implicit) port must be one of these. */
  allowedPorts?: readonly number[];
  /** Reject destinations whose connection address is not public internet. */
  blockPrivateNetworks: boolean;
}

// ------------------------------------------------------------ addresses

export type AddressVerdict = { safe: true } | { safe: false; reason: string };

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const v = Number(part);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function inCidr4(n: number, base: number, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((n >>> 0) & mask) === (base & mask);
}

/** True when the address embeds an IPv4 address (v4-mapped or NAT64 form). */
function extractEmbeddedV4(groups: number[]): number | null {
  if (groups.length !== 8) return null;
  const embedded = ((groups[6]! << 16) | groups[7]!) >>> 0;
  const isMapped =
    groups[0] === 0 && groups[1] === 0 && groups[2] === 0 &&
    groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
  const isNat64 =
    groups[0] === 0x0064 && groups[1] === 0xff9b &&
    groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0;
  if (!isMapped && !isNat64) return null;
  return embedded;
}

/** Parse a textual IPv6 address into 8 16-bit groups, or null. */
export function parseIpv6(ip: string): number[] | null {
  const compressed = ip.includes('::');
  const halves = compressed ? ip.split('::') : [ip, ''];
  if (compressed && (halves.length !== 2 || ip.split('::').length !== 2)) return null;
  const headText = halves[0]!;
  const tailText = halves[1]!;

  // Parse a colon-group run; an IPv4 literal is legal only as its FINAL
  // part and contributes two groups (::ffff:10.0.0.1 → 0xffff, 0x0a00_0001
  // split as 0x0a00,0x0001).
  const parseRun = (text: string): { groups: number[]; endsWithV4: boolean } | null => {
    if (text === '') return { groups: [], endsWithV4: false };
    const parts = text.split(':');
    const groups: number[] = [];
    let endsWithV4 = false;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]!;
      if (part.includes('.')) {
        if (i !== parts.length - 1) return null;
        const v4 = ipv4ToInt(part);
        if (v4 === null) return null;
        groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
        endsWithV4 = true;
        break;
      }
      if (!/^[0-9A-Fa-f]{1,4}$/.test(part)) return null;
      groups.push(parseInt(part, 16));
    }
    return { groups, endsWithV4 };
  };

  const head = parseRun(headText);
  if (head === null) return null;
  const tail = parseRun(tailText);
  if (tail === null) return null;

  const headGroups = head.groups;
  const tailGroups = tail.groups;
  if (compressed) {
    const fill = 8 - (headGroups.length + tailGroups.length);
    if (fill < 1) return null;
    return [...headGroups, ...Array<number>(fill).fill(0), ...tailGroups];
  }
  // Uncompressed: an IPv4 tail implies 6 hex groups + 2 = 8.
  if (headGroups.length + tailGroups.length !== 8) return null;
  return [...headGroups, ...tailGroups];
}

/**
 * Classify one textual IP address. Anything that is not clearly a public
 * unicast address is unsafe — deny by default (Step 12G).
 */
export function classifyAddress(ip: string): AddressVerdict {
  const v = isIP(ip);
  if (v === 4) {
    const n = ipv4ToInt(ip);
    if (n === null) return { safe: false, reason: 'unparseable IPv4' };
    const checks: [number, number, string][] = [
      [0x00000000, 8, 'unspecified (0.0.0.0/8)'],
      [0x0a000000, 8, 'private RFC1918 (10.0.0.0/8)'],
      [0x64400000, 10, 'shared address space (100.64.0.0/10)'],
      [0x7f000000, 8, 'loopback (127.0.0.0/8)'],
      [0xa9fe0000, 16, 'link-local / cloud metadata (169.254.0.0/16)'],
      [0xac100000, 12, 'private RFC1918 (172.16.0.0/12)'],
      [0xc0a80000, 16, 'private RFC1918 (192.168.0.0/16)'],
      [0xc6120000, 15, 'benchmarking (198.18.0.0/15)'],
      [0xe0000000, 4, 'multicast (224.0.0.0/4)'],
      [0xf0000000, 4, 'reserved (240.0.0.0/4)'],
    ];
    for (const [base, bits, reason] of checks) {
      if (inCidr4(n, base, bits)) return { safe: false, reason };
    }
    return { safe: true };
  }
  if (v === 6) {
    const groups = parseIpv6(ip);
    if (groups === null) return { safe: false, reason: 'unparseable IPv6' };
    const allZero = groups.every((g) => g === 0);
    if (allZero) return { safe: false, reason: 'unspecified (::)' };
    if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) {
      return { safe: false, reason: 'IPv6 loopback (::1)' };
    }
    const top = groups[0]!;
    if ((top & 0xffc0) === 0xfe80) return { safe: false, reason: 'IPv6 link-local (fe80::/10)' };
    if ((top & 0xfe00) === 0xfc00) return { safe: false, reason: 'IPv6 unique-local (fc00::/7)' };
    if ((top & 0xff00) === 0xff00) return { safe: false, reason: 'IPv6 multicast (ff00::/8)' };
    if (top === 0x0100 && groups[1] === 0) {
      return { safe: false, reason: 'discard-only (100::/64)' };
    }
    const embedded = extractEmbeddedV4(groups);
    if (embedded !== null) {
      const inner = classifyAddress(
        `${(embedded >>> 24) & 0xff}.${(embedded >>> 16) & 0xff}.${(embedded >>> 8) & 0xff}.${embedded & 0xff}`,
      );
      if (!inner.safe) return { safe: false, reason: `IPv4-mapped/translated: ${inner.reason}` };
      // Mapped/translated forms resolve to v4 infrastructure — the v4
      // classification already ran; public mapped addresses are still
      // unusual for did:web but not inherently internal.
    }
    return { safe: true };
  }
  return { safe: false, reason: 'not an IP address' };
}

// ------------------------------------------------------------ host/port policy

function hostMatches(entry: string, host: string): boolean {
  const e = entry.toLowerCase();
  return host === e || host.endsWith(`.${e}`);
}

export function assertDestinationAllowed(url: URL, policy: DidWebNetworkPolicy): void {
  if (url.protocol !== 'https:') {
    throw new DidWebTransportError('POLICY', 'did:web resolution is HTTPS-only');
  }
  const host = url.hostname.toLowerCase();
  if (policy.allowedHosts !== undefined && !policy.allowedHosts.some((e) => hostMatches(e, host))) {
    throw new DidWebTransportError('POLICY', `host not allowed by policy: ${host}`);
  }
  const port = url.port === '' ? 443 : Number(url.port);
  if (policy.allowedPorts !== undefined && !policy.allowedPorts.includes(port)) {
    throw new DidWebTransportError('POLICY', `port not allowed by policy: ${port}`);
  }
  if (policy.blockPrivateNetworks) {
    // Defense in depth: an IP-LITERAL destination is classified directly.
    // A hostname is NOT classified here — it goes through DNS + per-address
    // classification in the client (hostnames are not IP addresses).
    const literal = host.replace(/^\[|\]$/g, '');
    if (isIpLiteral(literal)) {
      const verdict = classifyAddress(literal);
      if (!verdict.safe) {
        throw new DidWebTransportError('POLICY', `literal destination rejected: ${verdict.reason}`);
      }
    }
  }
}

/** Minimal IPv4/IPv6 literal test without importing node:net here. */
function isIpLiteral(text: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(text) || /^[0-9A-Fa-f:]+$/.test(text) && text.includes(':');
}

// ------------------------------------------------------------ real client

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export type DidWebDnsLookup = (hostname: string) => Promise<ResolvedAddress[]>;

export interface NodeHttpsClientOptions {
  /** Injectable DNS for tests (defaults to node:dns lookup all/verbatim). */
  dnsLookup?: DidWebDnsLookup;
  /**
   * LOCAL-TEST ONLY escape hatch: skip private-address classification.
   * Never set in production wiring; defaults to false. Host allowlisting,
   * HTTPS-only, size caps, and address pinning remain in force.
   */
  allowPrivateNetworks?: boolean;
  /**
   * Injectable request primitive for tests. Receives the PINNED connection
   * target plus request options; returns status/headers/body-text.
   */
  httpRequest?: (input: {
    /** The validated address the connection will be made to. */
    connectionAddress: string;
    family: 4 | 6;
    host: string;
    port: number;
    path: string;
    timeoutMs: number;
  }) => Promise<{ status: number; headers: Record<string, string>; streamBody: AsyncIterable<Uint8Array> | null }>;
}

const dnsLookupDefault: DidWebDnsLookup = (hostname) =>
  import('node:dns').then((dns) => dns.promises.lookup(hostname, { all: true, verbatim: true }) as never);

/**
 * Production did:web HTTP client (node:https). Implements the exact
 * semantics the SSRF boundary requires — see the module docblock.
 */
export class NodeHttpsDidWebClient implements DidWebClientShape {
  readonly #dnsLookup: DidWebDnsLookup;
  readonly #httpRequest: NonNullable<NodeHttpsClientOptions['httpRequest']>;
  readonly #allowPrivate: boolean;

  constructor(opts: NodeHttpsClientOptions = {}) {
    this.#dnsLookup = opts.dnsLookup ?? dnsLookupDefault;
    this.#allowPrivate = opts.allowPrivateNetworks ?? false;
    this.#httpRequest =
      opts.httpRequest ??
      (async (input) => {
        const https = await import('node:https');
        return new Promise((resolve, reject) => {
          const req = https.get(
            {
              host: input.connectionAddress,
              servername: input.host,
              port: input.port,
              path: input.path,
              method: 'GET',
              timeout: input.timeoutMs,
              headers: {
                accept: 'application/did+json, application/json',
                host: input.port === 443 ? input.host : `${input.host}:${input.port}`,
              },
              lookup: ((_hostname: string, o: unknown, cb: (err: NodeJS.ErrnoException | null, address?: string, family?: number) => void) => cb(null, input.connectionAddress, input.family)) as import('node:net').LookupFunction,
            },
            (res) => {
              resolve({
                status: res.statusCode ?? 0,
                headers: res.headers as Record<string, string>,
                streamBody: res,
              });
            },
          );
          req.on('timeout', () => req.destroy(new Error('socket timeout')));
          req.on('error', reject);
        });
      });
  }

  async get(url: URL, options: DidWebFetchOptions): Promise<DidWebHttpResponse> {
    assertDestinationAllowed(url, { blockPrivateNetworks: !this.#allowPrivate });
    const host = url.hostname.toLowerCase();
    const port = url.port === '' ? 443 : Number(url.port);

    // ONE resolution; EVERY address is classified; the connection is
    // pinned to a validated address (no second lookup to race).
    let addresses: ResolvedAddress[];
    try {
      addresses = await this.#dnsLookup(host);
    } catch (e) {
      throw new DidWebTransportError('NETWORK', `DNS resolution failed: ${String(e)}`);
    }
    if (addresses.length === 0) {
      throw new DidWebTransportError('NETWORK', 'DNS returned no addresses');
    }
    if (!this.#allowPrivate) {
      for (const a of addresses) {
        const verdict = classifyAddress(a.address);
        if (!verdict.safe) {
          throw new DidWebTransportError('POLICY', `resolved address rejected: ${a.address} (${verdict.reason})`);
        }
      }
    }
    const pinned = addresses[0]!;

    const deadline = Date.now() + options.timeoutMs;
    let response: { status: number; headers: Record<string, string>; streamBody: AsyncIterable<Uint8Array> | null };
    try {
      response = await this.#httpRequest({
        connectionAddress: pinned.address,
        family: pinned.family,
        host,
        port,
        path: `${url.pathname}${url.search}`,
        timeoutMs: options.timeoutMs,
      });
    } catch (e) {
      throw new DidWebTransportError('NETWORK', `request failed: ${String(e)}`);
    }

    const bytes: Uint8Array[] = [];
    let total = 0;
    const contentLength = response.headers['content-length'];
    if (contentLength !== undefined && Number(contentLength) > options.maxBytes) {
      throw new DidWebTransportError('TOO_LARGE', `content-length ${contentLength} exceeds cap ${options.maxBytes}`);
    }
    if (response.streamBody !== null) {
      for await (const chunk of response.streamBody) {
        total += chunk.byteLength;
        if (total > options.maxBytes) {
          throw new DidWebTransportError('TOO_LARGE', `response exceeds cap ${options.maxBytes} bytes`);
        }
        if (Date.now() > deadline) {
          throw new DidWebTransportError('TIMEOUT', 'response exceeded the total time budget');
        }
        bytes.push(chunk);
      }
    }
    const body = Buffer.concat(bytes).toString('utf8');
    return { status: response.status, headers: response.headers, body };
  }
}

// structural alias so the class name reads well in exports
type DidWebClientShape = DidWebHttpClient;
