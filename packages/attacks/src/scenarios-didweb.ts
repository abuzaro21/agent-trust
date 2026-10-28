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

/** Control: the SAME transport serving the well-formed document resolves to it. A refusal is only meaningful if this holds. */
async function controlResolves(status = 200, headers: Record<string, string> = {}): Promise<boolean> {
  const resolver = await resolverWith(async () => ({ status, headers, body: JSON.stringify(GOOD_DOC) }));
  const r = await resolver.resolve(DID);
  return r.didDocument !== null && r.didDocument.id === DID;
}

export const DIDWEB_001: AttackScenario = {
  id: 'DIDWEB-001',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'document.id mismatch (server serves a different identity)',
  expected: { verdict: 'REFUSED', outcome: 'resolution fails; nothing cached', noReasonCode: 'the did:web resolver reports a DID-Core didResolutionMetadata.error, not a gateway ReasonCode' },
  async run() {
    const resolver = await resolverWith(async () => ({
      status: 200, headers: {}, body: JSON.stringify({ ...GOOD_DOC, id: 'did:web:evil.example' }),
    }));
    const r = await resolver.resolve(DID);
    return {
      outcome: r.didDocument === null ? `rejected (${r.didResolutionMetadata.message})` : 'UNDETECTED',
      verdict: r.didDocument === null ? 'REFUSED' : 'BREACHED',
      reasonCodes: [],
      invariants: { controlResolves: await controlResolves(), resolutionError: r.didResolutionMetadata.error ?? null, notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

/**
 * Control for the SSRF scenarios: the same transport, same request, but DNS answering a PUBLIC address, DOES reach the
 * connection stage. Without this, "blocked before connect" could just mean "this transport never connects".
 */
async function publicAddressConnects(): Promise<boolean> {
  const { NodeHttpsDidWebClient } = await import('@agent-trust/did');
  let attempts = 0;
  const client = new NodeHttpsDidWebClient({
    dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }],
    httpRequest: async () => { attempts += 1; throw new Error('control connect reached'); },
  });
  try {
    await client.get(new URL(`https://${HOST}/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
  } catch {
    // the control transport double always throws once it is reached; only the attempt count matters
  }
  return attempts === 1;
}

export const DIDWEB_002: AttackScenario = {
  id: 'DIDWEB-002',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Private IP target (DNS → RFC1918) — denied before connect',
  expected: { verdict: 'REFUSED', outcome: 'connection refused by network policy before any connect', noReasonCode: 'the transport reports a typed DidWebTransportError(POLICY), not a gateway ReasonCode' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    let connectAttempts = 0;
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '10.1.2.3', family: 4 }],
      httpRequest: async () => { connectAttempts += 1; throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/agents/support/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', verdict: 'BREACHED', reasonCodes: [], invariants: { blockedPreConnect: false, connectAttempts, controlPublicAddressConnects: false } };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `blocked pre-connect (${e.message})` : String(e),
        verdict: e instanceof DidWebTransportError && e.code === 'POLICY' ? 'REFUSED' : 'BREACHED',
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY', connectAttempts, controlPublicAddressConnects: await publicAddressConnects() },
      };
    }
  },
};

export const DIDWEB_003: AttackScenario = {
  id: 'DIDWEB-003',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Loopback target (DNS → 127.0.0.1)',
  expected: { verdict: 'REFUSED', outcome: 'connection refused by network policy before any connect', noReasonCode: 'the transport reports a typed DidWebTransportError(POLICY), not a gateway ReasonCode' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    let connectAttempts = 0;
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }],
      httpRequest: async () => { connectAttempts += 1; throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', verdict: 'BREACHED', reasonCodes: [], invariants: { blockedPreConnect: false, connectAttempts, controlPublicAddressConnects: false } };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `blocked pre-connect (${e.message})` : String(e),
        verdict: e instanceof DidWebTransportError && e.code === 'POLICY' ? 'REFUSED' : 'BREACHED',
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY', connectAttempts, controlPublicAddressConnects: await publicAddressConnects() },
      };
    }
  },
};

export const DIDWEB_004: AttackScenario = {
  id: 'DIDWEB-004',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Cloud metadata / link-local target (DNS → 169.254.169.254)',
  expected: { verdict: 'REFUSED', outcome: 'connection refused by network policy before any connect', noReasonCode: 'the transport reports a typed DidWebTransportError(POLICY), not a gateway ReasonCode' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    let connectAttempts = 0;
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }],
      httpRequest: async () => { connectAttempts += 1; throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', verdict: 'BREACHED', reasonCodes: [], invariants: { blockedPreConnect: false, connectAttempts, controlPublicAddressConnects: false } };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `blocked pre-connect (${e.message})` : String(e),
        verdict: e instanceof DidWebTransportError && e.code === 'POLICY' ? 'REFUSED' : 'BREACHED',
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY', connectAttempts, controlPublicAddressConnects: await publicAddressConnects() },
      };
    }
  },
};

export const DIDWEB_005: AttackScenario = {
  id: 'DIDWEB-005',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'DNS rebinding: validated hostname, connection address turns private',
  expected: { verdict: 'REFUSED', outcome: 'address-pinned transport blocks the rebinding before any connect', noReasonCode: 'the transport reports a typed DidWebTransportError(POLICY), not a gateway ReasonCode' },
  async run() {
    const { NodeHttpsDidWebClient, DidWebTransportError } = await import('@agent-trust/did');
    // Single lookup returning the private address = the rebinding end-state;
    // the transport classifies EVERY address it will connect to.
    let connectAttempts = 0;
    const client = new NodeHttpsDidWebClient({
      dnsLookup: async () => [{ address: '192.168.0.7', family: 4 }],
      httpRequest: async () => { connectAttempts += 1; throw new Error('MUST NOT CONNECT'); },
    });
    try {
      await client.get(new URL(`https://${HOST}/did.json`), { timeoutMs: 1000, maxBytes: 1024 });
      return { outcome: 'UNDETECTED — connected', verdict: 'BREACHED', reasonCodes: [], invariants: { blockedPreConnect: false, connectAttempts, controlPublicAddressConnects: false } };
    } catch (e) {
      return {
        outcome: e instanceof DidWebTransportError && e.code === 'POLICY' ? `rebinding blocked (${e.message})` : String(e),
        verdict: e instanceof DidWebTransportError && e.code === 'POLICY' ? 'REFUSED' : 'BREACHED',
        reasonCodes: [],
        invariants: { blockedPreConnect: e instanceof DidWebTransportError && e.code === 'POLICY', connectAttempts, controlPublicAddressConnects: await publicAddressConnects() },
      };
    }
  },
};

export const DIDWEB_006: AttackScenario = {
  id: 'DIDWEB-006',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Redirect to an internal target',
  expected: { verdict: 'REFUSED', outcome: 'redirect rejected by policy', noReasonCode: 'the did:web resolver reports a DID-Core didResolutionMetadata.error, not a gateway ReasonCode' },
  async run() {
    const resolver = await resolverWith(async () => ({
      status: 302, headers: { location: 'https://internal-service.local/did.json' }, body: '',
    }));
    const r = await resolver.resolve(DID);
    return {
      outcome: r.didDocument === null ? `redirect rejected (${r.didResolutionMetadata.message})` : 'UNDETECTED',
      verdict: r.didDocument === null ? 'REFUSED' : 'BREACHED',
      reasonCodes: [],
      invariants: {
        controlResolves: await controlResolves(),
        resolutionError: r.didResolutionMetadata.error ?? null,
        // cause: the redirect itself was refused (not merely 'some non-200'); typed marker is the stable prefix
        redirectRefusedByPolicy: (r.didResolutionMetadata.message ?? '').startsWith('redirect rejected by policy'),
        notCached: resolver.peekCache(DID) === undefined,
      },
    };
  },
};

export const DIDWEB_007: AttackScenario = {
  id: 'DIDWEB-007',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Oversized document response',
  expected: { verdict: 'REFUSED', outcome: 'transport TOO_LARGE, deterministic failure', noReasonCode: 'the did:web resolver reports a DID-Core didResolutionMetadata.error, not a gateway ReasonCode' },
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
      verdict: r.didDocument === null ? 'REFUSED' : 'BREACHED',
      reasonCodes: [],
      invariants: { controlResolves: await controlResolves(), resolutionError: r.didResolutionMetadata.error ?? null, notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

export const DIDWEB_008: AttackScenario = {
  id: 'DIDWEB-008',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Private key material in the served document (JWK with d)',
  expected: { verdict: 'REFUSED', outcome: 'document rejected; never cached', noReasonCode: 'the did:web resolver reports a DID-Core didResolutionMetadata.error, not a gateway ReasonCode' },
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
      verdict: r.didDocument === null ? 'REFUSED' : 'BREACHED',
      reasonCodes: [],
      invariants: { controlResolves: await controlResolves(), resolutionError: r.didResolutionMetadata.error ?? null, notCached: resolver.peekCache(DID) === undefined },
    };
  },
};

export const DIDWEB_009: AttackScenario = {
  id: 'DIDWEB-009',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Foreign kid: verification method owned by another DID',
  expected: { verdict: 'REFUSED', outcome: 'kid-ownership binding fails', noReasonCode: 'the did:web resolver reports a DID-Core didResolutionMetadata.error, not a gateway ReasonCode' },
  async run() {
    const serve = async (method: Record<string, unknown>) => {
      const resolver = await resolverWith(async () => ({
        status: 200, headers: {}, body: JSON.stringify({ id: DID, verificationMethod: [method] }),
      }));
      const r = await resolver.resolve(DID);
      return { refused: r.didDocument === null, cached: resolver.peekCache(DID) !== undefined, error: r.didResolutionMetadata.error ?? null };
    };
    const foreign = 'did:web:evil.example:agent';
    // (a) foreign id AND foreign controller; (b) foreign id with the CORRECT controller — isolates the kid-ownership
    // check from the controller check; (c) own id with a foreign controller — isolates the controller check.
    const a = await serve({ id: `${foreign}#key-1`, type: 'JsonWebKey2020', controller: foreign, publicKeyJwk: JWK });
    const b = await serve({ id: `${foreign}#key-1`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: JWK });
    const c = await serve({ id: `${DID}#key-1`, type: 'JsonWebKey2020', controller: foreign, publicKeyJwk: JWK });
    const all = a.refused && b.refused && c.refused;
    return {
      outcome: all ? 'foreign kid and foreign controller rejected in every combination' : 'UNDETECTED',
      verdict: all ? 'REFUSED' : 'BREACHED',
      reasonCodes: [],
      invariants: {
        controlResolves: await controlResolves(),
        resolutionError: a.error,
        foreignIdAndControllerRefused: a.refused,
        foreignIdOwnControllerRefused: b.refused,
        ownIdForeignControllerRefused: c.refused,
        notCached: !a.cached && !b.cached && !c.cached,
      },
    };
  },
};

export const DIDWEB_010: AttackScenario = {
  id: 'DIDWEB-010',
  category: 'DID_WEB',
  kind: 'ATTACK',
  title: 'Cache poisoning: invalid document served first, valid second',
  expected: { verdict: 'CONTAINED', outcome: 'invalid never cached; valid second resolution succeeds', noReasonCode: 'the did:web resolver reports a DID-Core didResolutionMetadata.error, not a gateway ReasonCode' },
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
      verdict: r1.didDocument === null && r2.didDocument?.id === DID ? 'CONTAINED' : 'BREACHED',
      reasonCodes: [],
      invariants: { firstFailed: r1.didDocument === null, secondSucceeded: r2.didDocument !== null, secondResolvedToExpectedDid: r2.didDocument?.id === DID },
    };
  },
};

export const DIDWEB_011: AttackScenario = {
  id: 'DIDWEB-011',
  category: 'DID_WEB',
  kind: 'FAILURE_DEMO',
  title: 'Emergency key rotation with max-age=0 (post-compromise publish)',
  expected: { verdict: 'CONTAINED', outcome: 'old key never survives a max-age=0 publish; every resolution re-fetches', noReasonCode: 'a cache-freshness property: no resolution failure occurs, so there is no reason code' },
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
      verdict: keyBefore !== undefined && keyAfter !== undefined && JSON.stringify(keyBefore) !== JSON.stringify(keyAfter) ? 'CONTAINED' : 'BREACHED',
      reasonCodes: [],
      invariants: { refetchedEveryResolve: calls === 2, keyRotated: JSON.stringify(keyBefore) !== JSON.stringify(keyAfter), keyAfterIsRotatedKey: JSON.stringify(keyAfter) === JSON.stringify(KEY_B) },
    };
  },
};

export const DIDWEB_SCENARIOS = [
  DIDWEB_001, DIDWEB_002, DIDWEB_003, DIDWEB_004, DIDWEB_005,
  DIDWEB_006, DIDWEB_007, DIDWEB_008, DIDWEB_009, DIDWEB_010, DIDWEB_011,
];
