import type { AttackScenario } from './types.js';
import { HOST, buildAttackWorld } from './world.js';

/**
 * Step 13L — did:web attacks. All transports are controlled doubles —
 * no real requests against private or internal systems.
 */

const DID = `did:web:${HOST}:agents:support`;
const JWK = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) };
const GOOD_DOC = {
  id: DID,
  verificationMethod: [{ id: `${DID}#key-1`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: JWK }],
};

async function resolverWith(respond: (url: URL) => Promise<{ status: number; headers: Record<string, string>; body: string }>) {
  const { WebDidResolver } = await import('@agent-trust/did');
  return new WebDidResolver({ http: { get: async (url) => respond(url) }, clock: () => 1_000_000 });
}

export const DIDWEB_001: AttackScenario = {
  id: 'DIDWEB-001',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'document.id mismatch (server serves a different identity)',
  expected: { outcome: 'resolution fails; nothing cached' },
  async run() {
    const resolver = await resolverWith(async () => ({
      status: 200, headers: {}, body: JSON.stringify({ ...GOOD_DOC, id: 'did:web:evil.example' }),
    }));
    const r = await resolver.resolve(DID);
    return {
      outcome: r.didDocument === null ? `rejected (${r.didResolutionMetadata.message})` : 'UNDETECTED',
      reasonCodes: [],
      invariants: { notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

export const DIDWEB_002: AttackScenario = {
  id: 'DIDWEB-002',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Private IP target (DNS → RFC1918) — denied before connect',
  expected: { outcome: 'connection refused by network policy' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '10.1.2.3', family: 4 }],
      httpRequest: async () => { throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/agents/support/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', reasonCodes: [], invariants: {} };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `blocked pre-connect (${e.message})` : String(e),
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY' },
      };
    }
  },
};

export const DIDWEB_003: AttackScenario = {
  id: 'DIDWEB-003',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Loopback target (DNS → 127.0.0.1)',
  expected: { outcome: 'connection refused by network policy' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }],
      httpRequest: async () => { throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', reasonCodes: [], invariants: {} };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `blocked pre-connect (${e.message})` : String(e),
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY' },
      };
    }
  },
};

export const DIDWEB_004: AttackScenario = {
  id: 'DIDWEB-004',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Cloud metadata / link-local target (DNS → 169.254.169.254)',
  expected: { outcome: 'connection refused by network policy' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }],
      httpRequest: async () => { throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', reasonCodes: [], invariants: {} };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `blocked pre-connect (${e.message})` : String(e),
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY' },
      };
    }
  },
};

export const DIDWEB_005: AttackScenario = {
  id: 'DIDWEB-005',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'DNS rebinding: validated hostname, connection address turns private',
  expected: { outcome: 'address-pinned transport blocks the rebinding' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    // Single lookup returning the private address = the rebinding end-state;
    // the transport classifies EVERY address it will connect to.
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '192.168.0.7', family: 4 }],
      httpRequest: async () => { throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', reasonCodes: [], invariants: {} };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `rebinding blocked (${e.message})` : String(e),
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY' },
      };
    }
  },
};

export const DIDWEB_006: AttackScenario = {
  id: 'DIDWEB-006',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Redirect to an internal target',
  expected: { outcome: 'redirect rejected by policy' },
  async run() {
    const resolver = await resolverWith(async () => ({
      status: 302, headers: { location: 'https://internal-service.local/did.json' }, body: '',
    }));
    const r = await resolver.resolve(DID);
    return {
      outcome: r.didDocument === null ? `redirect rejected (${r.didResolutionMetadata.message})` : 'UNDETECTED',
      reasonCodes: [],
      invariants: { notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

export const DIDWEB_007: AttackScenario = {
  id: 'DIDWEB-007',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Oversized document response',
  expected: { outcome: 'transport TOO_LARGE, deterministic failure' },
  async run() {
    const { WebDidResolver, DidWebTransportError } = await import('@agent-trust/did');
    const resolver = new WebDidResolver({
      clock: () => 1_000_000,
      http: {
        get: async () => {
          throw new DidWebTransportError('TOO_LARGE', 'response exceeds cap 262144 bytes');
        },
      },
    });
    const r = await resolver.resolve(DID);
    return {
      outcome: r.didDocument === null ? `size-capped (${r.didResolutionMetadata.message})` : 'UNDETECTED',
      reasonCodes: [],
      invariants: { notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

export const DIDWEB_008: AttackScenario = {
  id: 'DIDWEB-008',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Private key material in the served document (JWK with d)',
  expected: { outcome: 'document rejected; never cached' },
  async run() {
    const resolver = await resolverWith(async () => ({
      status: 200, headers: {}, body: JSON.stringify({
        id: DID,
        verificationMethod: [{ id: `${DID}#key-1`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: { ...JWK, d: 'LEAKED-PRIVATE-SCALAR' } }],
      }),
    }));
    const r = await resolver.resolve(DID);
    return {
      outcome: r.didDocument === null ? `rejected (${r.didResolutionMetadata.message})` : 'UNDETECTED — private material accepted',
      reasonCodes: [],
      invariants: { notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

export const DIDWEB_009: AttackScenario = {
  id: 'DIDWEB-009',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Foreign kid: verification method owned by another DID',
  expected: { outcome: 'kid-ownership binding fails' },
  async run() {
    const resolver = await resolverWith(async () => ({
      status: 200, headers: {}, body: JSON.stringify({
        id: DID,
        verificationMethod: [{ id: 'did:web:evil.example:agent#key-1', type: 'JsonWebKey2020', controller: 'did:web:evil.example:agent', publicKeyJwk: JWK }],
      }),
    }));
    const r = await resolver.resolve(DID);
    return {
      outcome: r.didDocument === null ? `foreign kid rejected (${r.didResolutionMetadata.message})` : 'UNDETECTED',
      reasonCodes: [],
      invariants: { notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

export const DIDWEB_010: AttackScenario = {
  id: 'DIDWEB-010',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Cache poisoning: invalid document served first, valid second',
  expected: { outcome: 'invalid never cached; valid second resolution succeeds' },
  async run() {
    let evil = true;
    const resolver = await resolverWith(async () => ({
      status: 200, headers: { 'cache-control': 'max-age=60' },
      body: JSON.stringify(evil ? { ...GOOD_DOC, id: 'did:web:evil.example' } : GOOD_DOC),
    }));
    const r1 = await resolver.resolve(DID);
    evil = false;
    const r2 = await resolver.resolve(DID);
    return {
      outcome: r1.didDocument === null && r2.didDocument?.id === DID
        ? 'poisoned response rejected; subsequent valid resolution succeeded'
        : 'UNEXPECTED cache state',
      reasonCodes: [],
      invariants: { firstFailed: r1.didDocument === null, secondSucceeded: r2.didDocument !== null },
    };
  },
};

export const DIDWEB_011: AttackScenario = {
  id: 'DIDWEB-011',
  category: 'DID_WEB',
  kind: 'FAILURE_DEMO',
  title: 'Emergency key rotation with max-age=0 (post-compromise publish)',
  expected: { outcome: 'old key never survives a max-age=0 publish; every resolution re-fetches' },
  async run() {
    const { WebDidResolver } = await import('@agent-trust/did');
    const KEY_B = { kty: 'EC', crv: 'P-256', x: 'C'.repeat(43), y: 'D'.repeat(43) };
    let rotated = false;
    let calls = 0;
    const resolver = new WebDidResolver({
      clock: () => 1_000_000, // frozen clock: any freshness shortcut shows here
      http: {
        get: async () => {
          calls += 1;
          const jwk = rotated ? KEY_B : JWK;
          return {
            status: 200,
            headers: { 'cache-control': 'max-age=0' }, // emergency: always revalidate
            body: JSON.stringify({
              id: DID,
              verificationMethod: [{ id: `${DID}#key-1`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: jwk }],
            }),
          };
        },
      },
    });
    const v1 = await resolver.resolve(DID);
    const keyBefore = v1.didDocument?.verificationMethod?.[0]?.publicKeyJwk;
    rotated = true; // operator publishes key B with max-age=0
    const v2 = await resolver.resolve(DID);
    const keyAfter = v2.didDocument?.verificationMethod?.[0]?.publicKeyJwk;
    return {
      outcome:
        keyBefore !== undefined && keyAfter !== undefined && keyBefore !== keyAfter
          ? `rotation observed immediately (${calls} fetches for 2 resolutions — max-age=0 honored)`
          : 'STALE KEY SURVIVED (bug)',
      reasonCodes: [],
      invariants: { refetchedEveryResolve: calls === 2, keyRotated: keyBefore !== keyAfter },
    };
  },
};

export const DIDWEB_SCENARIOS = [
  DIDWEB_001, DIDWEB_002, DIDWEB_003, DIDWEB_004, DIDWEB_005,
  DIDWEB_006, DIDWEB_007, DIDWEB_008, DIDWEB_009, DIDWEB_010, DIDWEB_011,
];
