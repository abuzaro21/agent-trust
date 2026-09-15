import { beforeEach, describe, expect, it } from 'vitest';

import { LocalSigner } from '@agent-trust/crypto';
import { CredentialVerifier, type VcVerification } from '@agent-trust/vc';

import {
  BitstringStatusChecker,
  InMemoryAgentQuarantineStore,
  InMemoryStatusListStore,
  StatusListError,
  StatusListManager,
  signStatusListCredential,
} from '../src/index.js';
import {
  AGENT_DID,
  EVIL_DID,
  LIST_BITS,
  NOW,
  ORG_DID,
  REV_LIST,
  SUS_LIST,
  TICK,
  buildWorld,
  statusEntry,
  type StatusWorld,
} from './fixture.js';

let world: StatusWorld;
let store: InMemoryStatusListStore;
let manager: StatusListManager;
let clock: { now: number };
let verifier: CredentialVerifier;
let quarantine: InMemoryAgentQuarantineStore;

beforeEach(async () => {
  world = await buildWorld();
  store = new InMemoryStatusListStore();
  clock = { now: NOW };
  manager = new StatusListManager(store, { clock: () => clock.now });
  await manager.createList({
    id: REV_LIST,
    purpose: 'revocation',
    controllerDid: ORG_DID,
    sizeBits: LIST_BITS,
  });
  await manager.createList({
    id: SUS_LIST,
    purpose: 'suspension',
    controllerDid: ORG_DID,
    sizeBits: LIST_BITS,
  });
  quarantine = new InMemoryAgentQuarantineStore();
  verifier = new CredentialVerifier({
    didResolver: world.resolver,
    trustStore: world.trustStore,
    statusChecker: new BitstringStatusChecker({ kind: 'store', store }),
    quarantineStore: quarantine,
  });
});

async function issueWithStatus(purpose: 'revocation' | 'suspension', listId: string, index?: number) {
  const i = index ?? (await manager.assignIndex(listId));
  const { jws, claims } = await world.issuer.issueDelegation({
    subjectDid: AGENT_DID,
    authority: {
      actions: ['refund:create'],
      resources: ['tenant:acme'],
      limits: { amount: 500, currency: 'SAR' },
      delegationDepth: 0,
    },
    validFrom: NOW - 100,
    validUntil: NOW + 3600,
    credentialStatus: statusEntry({ purpose, listId, index: i }),
  });
  return { jws, claims, index: i };
}

const denyCode = (result: VcVerification): string[] =>
  result.valid ? [] : result.reasonCodes;

describe('credential lifecycle through the verifier', () => {
  it('1. active credential → ACCEPT', async () => {
    const { jws } = await issueWithStatus('revocation', REV_LIST);
    const result = await verifier.verify(jws, { now: NOW });
    expect(result.valid).toBe(true);
  });

  it('2. revoked credential → DENY CREDENTIAL_REVOKED', async () => {
    const { jws, index } = await issueWithStatus('revocation', REV_LIST);
    clock.now += TICK;
    await manager.revoke(REV_LIST, index);
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_REVOKED']);
  });

  it('3. suspended credential → DENY CREDENTIAL_SUSPENDED', async () => {
    const { jws, index } = await issueWithStatus('suspension', SUS_LIST);
    clock.now += TICK;
    await manager.suspend(SUS_LIST, index);
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_SUSPENDED']);
  });

  it('4. suspended then unsuspended → ACCEPT again', async () => {
    const { jws, index } = await issueWithStatus('suspension', SUS_LIST);
    await manager.suspend(SUS_LIST, index);
    clock.now += TICK;
    await manager.unsuspend(SUS_LIST, index);
    const result = await verifier.verify(jws, { now: NOW });
    expect(result.valid).toBe(true);
  });

  it('5. revoked then attempted restore → REMAINS REVOKED', async () => {
    const { jws, index } = await issueWithStatus('revocation', REV_LIST);
    await manager.revoke(REV_LIST, index);
    // Every restore-shaped operation is rejected on a revocation list…
    await expect(manager.unsuspend(REV_LIST, index)).rejects.toMatchObject({
      code: 'PURPOSE_MISMATCH',
    });
    await expect(manager.suspend(REV_LIST, index)).rejects.toMatchObject({
      code: 'PURPOSE_MISMATCH',
    });
    // …and the bit is still set.
    const { set } = await manager.readStatus(REV_LIST, index);
    expect(set).toBe(true);
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_REVOKED']);
  });

  it('6. unknown status-list index (beyond the list) → DENY', async () => {
    const { jws } = await issueWithStatus('revocation', REV_LIST, 999_999);
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('7. missing status list → fail closed', async () => {
    const ghost = 'https://acme.example/status/ghost/1';
    const { jws } = await issueWithStatus('revocation', ghost, 0);
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('8. malformed status list encoding → fail closed', async () => {
    const { jws } = await issueWithStatus('revocation', REV_LIST);
    const corrupt = await store.get(REV_LIST);
    expect(corrupt).not.toBeNull();
    await store.put({ ...corrupt!, encodedList: '%%%not-base64url%%%' });
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('9. wrong status purpose (suspension entry against revocation list) → fail closed', async () => {
    const { jws } = await issueWithStatus('suspension', REV_LIST, 3);
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('10. another issuer\'s status list → fail closed', async () => {
    await manager.createList({
      id: 'https://evil.example/status/rev/1',
      purpose: 'revocation',
      controllerDid: EVIL_DID,
      sizeBits: LIST_BITS,
    });
    const { jws } = await issueWithStatus('revocation', 'https://evil.example/status/rev/1', 0);
    const result = await verifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('14. credential without credentialStatus → existing behavior preserved', async () => {
    const { jws } = await world.issuer.issueMembership({
      subjectDid: AGENT_DID,
      validFrom: NOW - 100,
      validUntil: NOW + 3600,
    });
    // With the full verifier (status checker attached)…
    expect((await verifier.verify(jws, { now: NOW })).valid).toBe(true);
    // …and with a bare verifier that has no status/quarantine deps at all.
    const bare = new CredentialVerifier({
      didResolver: world.resolver,
      trustStore: world.trustStore,
    });
    expect((await bare.verify(jws, { now: NOW })).valid).toBe(true);
  });

  it('declared status with no statusChecker wired → fail closed', async () => {
    const { jws } = await issueWithStatus('revocation', REV_LIST);
    const noChecker = new CredentialVerifier({
      didResolver: world.resolver,
      trustStore: world.trustStore,
    });
    const result = await noChecker.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });
});

describe('isolation and independence (positive)', () => {
  it('revoking credential A does not revoke credential B', async () => {
    const a = await issueWithStatus('revocation', REV_LIST);
    const b = await issueWithStatus('revocation', REV_LIST);
    expect(a.index).not.toBe(b.index);
    await manager.revoke(REV_LIST, a.index);
    expect(denyCode(await verifier.verify(a.jws, { now: NOW }))).toEqual(['CREDENTIAL_REVOKED']);
    expect((await verifier.verify(b.jws, { now: NOW })).valid).toBe(true);
  });

  it('multiple status lists remain independent', async () => {
    const a = await issueWithStatus('revocation', REV_LIST);
    const b = await issueWithStatus('suspension', SUS_LIST);
    await manager.revoke(REV_LIST, a.index);
    await manager.suspend(SUS_LIST, b.index);
    expect(denyCode(await verifier.verify(a.jws, { now: NOW }))).toEqual(['CREDENTIAL_REVOKED']);
    expect(denyCode(await verifier.verify(b.jws, { now: NOW }))).toEqual(['CREDENTIAL_SUSPENDED']);
  });

  it('every mutation bumps version and updatedAt deterministically', async () => {
    const { index } = await issueWithStatus('suspension', SUS_LIST);
    const v1 = await store.get(SUS_LIST);
    clock.now += TICK;
    await manager.suspend(SUS_LIST, index);
    const v2 = await store.get(SUS_LIST);
    clock.now += TICK;
    await manager.unsuspend(SUS_LIST, index);
    const v3 = await store.get(SUS_LIST);
    expect(v1!.version).toBe(1);
    expect(v2!.version).toBe(2);
    expect(v2!.updatedAt).toBe(NOW + TICK);
    expect(v3!.version).toBe(3);
    expect(v3!.updatedAt).toBe(NOW + 2 * TICK);
  });

  it('manager errors are deterministic typed failures', async () => {
    await expect(manager.revoke('https://missing.example/1', 0)).rejects.toBeInstanceOf(
      StatusListError,
    );
    await expect(manager.revoke(REV_LIST, LIST_BITS)).rejects.toMatchObject({
      code: 'INDEX_OUT_OF_RANGE',
    });
    await expect(
      manager.createList({ id: 'x', purpose: 'revocation', controllerDid: ORG_DID, sizeBits: 7 }),
    ).rejects.toMatchObject({ code: 'SIZE_INVALID' });
  });
});

describe('signed status-list mode (6E integrity)', () => {
  class MemSignedStore {
    readonly #maps = new Map<string, string>();
    async get(ref: string): Promise<string | null> {
      return this.#maps.get(ref) ?? null;
    }
    async put(ref: string, jws: string): Promise<void> {
      this.#maps.set(ref, jws);
    }
  }

  let signed: MemSignedStore;
  let signedVerifier: CredentialVerifier;

  beforeEach(() => {
    signed = new MemSignedStore();
    signedVerifier = new CredentialVerifier({
      didResolver: world.resolver,
      trustStore: world.trustStore,
      statusChecker: new BitstringStatusChecker({
        kind: 'signed',
        lists: signed,
        didResolver: world.resolver,
      }),
    });
  });

  async function publishList(): Promise<void> {
    const list = await store.get(REV_LIST);
    expect(list).not.toBeNull();
    const jws = await signStatusListCredential(list!, world.orgSigner, {
      now: NOW,
      issuerDid: ORG_DID,
    });
    await signed.put(REV_LIST, jws);
  }

  it('active and revoked credentials verify correctly against a signed list', async () => {
    const revoked = await issueWithStatus('revocation', REV_LIST);
    const active = await issueWithStatus('revocation', REV_LIST); // different index
    await manager.revoke(REV_LIST, revoked.index);
    await publishList(); // snapshot with the revoked bit set, signed by the org
    const revokedResult = await signedVerifier.verify(revoked.jws, { now: NOW });
    expect(denyCode(revokedResult)).toEqual(['CREDENTIAL_REVOKED']);
    const activeResult = await signedVerifier.verify(active.jws, { now: NOW });
    expect(activeResult.valid).toBe(true);
  });

  it('11a. tampered signed payload → fails verification', async () => {
    const { jws } = await issueWithStatus('revocation', REV_LIST);
    await publishList(); // signed list with the credential still ACTIVE
    // Attacker rewrites the signed payload to... anything (here: bump version).
    const stored = await signed.get(REV_LIST);
    const [h, p, s] = stored!.split('.') as [string, string, string];
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    payload.version = 999;
    const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
    await signed.put(REV_LIST, forged);
    const result = await signedVerifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('11b. tampered signature → fails verification', async () => {
    const { jws } = await issueWithStatus('revocation', REV_LIST);
    await publishList();
    const stored = await signed.get(REV_LIST);
    const [h, p] = stored!.split('.') as [string, string];
    const evilSigner = LocalSigner.generate();
    const { ecdsaDerToRaw, base64urlEncode, utf8 } = await import('@agent-trust/crypto');
    const evilSig = base64urlEncode(
      ecdsaDerToRaw(await evilSigner.sign(utf8(`${h}.${p}`))),
    );
    await signed.put(REV_LIST, `${h}.${p}.${evilSig}`);
    const result = await signedVerifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('11c. list signed by a different issuer than the credential → fail closed', async () => {
    const { jws, index } = await issueWithStatus('revocation', REV_LIST);
    await manager.revoke(REV_LIST, index);
    const list = await store.get(REV_LIST);
    const evilSigner = LocalSigner.generate();
    const { InMemoryDidResolver, didDocumentForJwk } = await import('@agent-trust/did');
    const { withDid } = await import('@agent-trust/crypto');
    // The evil issuer's list is perfectly signed and resolvable — but it is
    // not the credential's issuer, so its data must not be trusted.
    const evilResolver = new InMemoryDidResolver([
      didDocumentForJwk(EVIL_DID, await evilSigner.publicKey()),
    ]);
    const jwsList = await signStatusListCredential(list!, withDid(evilSigner, EVIL_DID), {
      now: NOW,
    });
    await signed.put(REV_LIST, jwsList);
    const evilChecker = new BitstringStatusChecker({
      kind: 'signed',
      lists: signed,
      didResolver: evilResolver,
    });
    const evilVerifier = new CredentialVerifier({
      didResolver: world.resolver,
      trustStore: world.trustStore,
      statusChecker: evilChecker,
    });
    const result = await evilVerifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });

  it('missing signed list → fail closed', async () => {
    const { jws } = await issueWithStatus('revocation', REV_LIST);
    const result = await signedVerifier.verify(jws, { now: NOW });
    expect(denyCode(result)).toEqual(['CREDENTIAL_STATUS_UNAVAILABLE']);
  });
});
