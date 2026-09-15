import { beforeEach, describe, expect, it } from 'vitest';

import { CredentialVerifier } from '@agent-trust/vc';

import { InMemoryAgentQuarantineStore } from '../src/quarantine.js';
import {
  AGENT_DID,
  NOW,
  type StatusWorld,
  buildWorld,
} from './fixture.js';

let world: StatusWorld;
let quarantine: InMemoryAgentQuarantineStore;
let verifier: CredentialVerifier;

beforeEach(async () => {
  world = await buildWorld();
  quarantine = new InMemoryAgentQuarantineStore();
  verifier = new CredentialVerifier({
    didResolver: world.resolver,
    trustStore: world.trustStore,
    quarantineStore: quarantine,
  });
});

async function issueCredentialForAgent(): Promise<string> {
  const { jws } = await world.issuer.issueMembership({
    subjectDid: AGENT_DID,
    validFrom: NOW - 100,
    validUntil: NOW + 3600,
  });
  return jws;
}

describe('InMemoryAgentQuarantineStore', () => {
  it('starts unquarantined, quarantines with a reason, and releases', async () => {
    const store = new InMemoryAgentQuarantineStore();
    expect(await store.isQuarantined(AGENT_DID)).toBe(false);
    store.quarantine(AGENT_DID, 'suspected key compromise');
    expect(await store.isQuarantined(AGENT_DID)).toBe(true);
    expect(store.reason(AGENT_DID)).toBe('suspected key compromise');
    store.release(AGENT_DID);
    expect(await store.isQuarantined(AGENT_DID)).toBe(false);
    expect(store.reason(AGENT_DID)).toBeUndefined();
  });

  it('quarantine is idempotent and release of an unknown agent is a no-op', () => {
    const store = new InMemoryAgentQuarantineStore();
    store.quarantine(AGENT_DID, 'a');
    store.quarantine(AGENT_DID, 'b');
    expect(store.reason(AGENT_DID)).toBe('b');
    expect(() => store.release('did:key:zNeverSeen')).not.toThrow();
  });
});

describe('quarantine integration with the verifier', () => {
  it('12. quarantined agent with an otherwise valid credential → DENY AGENT_QUARANTINED', async () => {
    const jws = await issueCredentialForAgent();
    expect((await verifier.verify(jws, { now: NOW })).valid).toBe(true);
    quarantine.quarantine(AGENT_DID, 'incident IR-42');
    const result = await verifier.verify(jws, { now: NOW });
    expect(result).toEqual({ valid: false, reasonCodes: ['AGENT_QUARANTINED'] });
  });

  it('13. released quarantine → normal verification resumes', async () => {
    const jws = await issueCredentialForAgent();
    quarantine.quarantine(AGENT_DID, 'incident IR-42');
    expect((await verifier.verify(jws, { now: NOW })).valid).toBe(false);
    quarantine.release(AGENT_DID);
    expect((await verifier.verify(jws, { now: NOW })).valid).toBe(true);
  });

  it('quarantine only blocks the quarantined agent, not other subjects', async () => {
    const other = 'did:key:zOtherAgent';
    const { jws } = await world.issuer.issueMembership({
      subjectDid: other,
      validFrom: NOW - 100,
      validUntil: NOW + 3600,
    });
    quarantine.quarantine(AGENT_DID, 'incident IR-42');
    expect((await verifier.verify(jws, { now: NOW })).valid).toBe(true);
  });
});
