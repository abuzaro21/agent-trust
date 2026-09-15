import { describe, expect, it } from 'vitest';

import { LocalSigner, createProof, requestBodyDigestOf } from '@agent-trust/crypto';

import { InMemoryReplayStore } from '../src/memory-store.js';
import { ReplayProtector } from '../src/protector.js';
import { verifyProofWithReplay, type ProofWithReplayResult } from '../src/verify-with-replay.js';

const NOW = 1_757_800_000;
const HTU = 'https://gateway.example/v1/trust/evaluate';

async function setup() {
  const signer = LocalSigner.generate();
  const jwk = await signer.publicKey();
  const body = { actor: 'did:key:zAgent', action: 'refund:create', amount: 120 };
  const digest = requestBodyDigestOf(body);
  const protector = new ReplayProtector(new InMemoryReplayStore({ clock: () => NOW }));

  const makeProof = async (jti: string, evilSigner?: LocalSigner) =>
    createProof(evilSigner ?? signer, {
      htu: HTU,
      requestBodyDigest: digest,
      jti,
      iat: NOW - 5,
      exp: NOW + 300,
    });

  const attempt = async (proof: Awaited<ReturnType<typeof makeProof>>) =>
    verifyProofWithReplay(
      { proof, publicJwk: jwk, htu: HTU, requestBodyDigest: digest, now: NOW },
      protector,
    );

  return { signer, jwk, protector, makeProof, attempt, digest };
}

const isOk = (r: ProofWithReplayResult): r is Extract<ProofWithReplayResult, { ok: true }> =>
  r.ok === true;

describe('PoP + replay integration (7H)', () => {
  it('a valid signed authorization executes at most once', async () => {
    const { makeProof, attempt } = await setup();
    const first = await attempt(await makeProof('jti-once-012345678'));
    expect(isOk(first)).toBe(true);
    const second = await attempt(await makeProof('jti-once-012345678'));
    expect(second).toEqual({
      ok: false,
      stage: 'replay',
      reasonCode: 'REPLAY_DETECTED',
      replayChecked: true,
    });
  });

  it('7L poisoning: invalid signature cannot reserve a legitimate jti', async () => {
    const { makeProof, attempt } = await setup();
    // 1. Attacker sends jti = X signed with the WRONG key.
    const evilAttempt = await attempt(
      await makeProof('jti-poison-0123456', LocalSigner.generate()),
    );
    expect(evilAttempt).toEqual({
      ok: false,
      stage: 'crypto',
      error: 'PROOF_SIGNATURE_INVALID',
      reasonCodes: ['IDENTITY_PROOF_INVALID'],
    });
    // 2. Legitimate correctly-signed request with the SAME jti arrives…
    const legit = await attempt(await makeProof('jti-poison-0123456'));
    // 3. …and succeeds, because the claim only happens after crypto.
    expect(isOk(legit)).toBe(true);
  });

  it('tampered body → crypto rejection, replay store untouched', async () => {
    const { jwk, protector, makeProof, digest } = await setup();
    const proof = await makeProof('jti-tamper-01234567');
    const tamperedDigest = requestBodyDigestOf({ actor: 'did:key:zAgent', action: 'refund:create', amount: 50_000 });
    const result = await verifyProofWithReplay(
      { proof, publicJwk: jwk, htu: HTU, requestBodyDigest: tamperedDigest, now: NOW },
      protector,
    );
    expect(result).toEqual({
      ok: false,
      stage: 'crypto',
      error: 'PROOF_SIGNATURE_INVALID',
      reasonCodes: ['IDENTITY_PROOF_INVALID'],
    });
    void digest;
  });

  it('7M audience: wrong-audience proof is rejected before consuming the claim', async () => {
    const { signer, jwk, protector, makeProof } = await setup();
    const proof = await makeProof('jti-aud-01234567890');
    // Proof signed for HTU but verified against a DIFFERENT endpoint:
    // signature binding fails, claim untouched.
    const wrongAudience = await verifyProofWithReplay(
      { proof, publicJwk: jwk, htu: 'https://other.example/v1/evaluate', requestBodyDigest: requestBodyDigestOf({ a: 1 }), now: NOW },
      protector,
    );
    expect(wrongAudience).toEqual({
      ok: false,
      stage: 'crypto',
      error: 'PROOF_SIGNATURE_INVALID',
      reasonCodes: ['IDENTITY_PROOF_INVALID'],
    });
    // The same proof against its legitimate audience is still allowed once.
    const legit = await verifyProofWithReplay(
      { proof, publicJwk: jwk, htu: HTU, requestBodyDigest: requestBodyDigestOf({ actor: 'did:key:zAgent', action: 'refund:create', amount: 120 }), now: NOW },
      protector,
    );
    expect(isOk(legit)).toBe(true);
    void signer;
  });

  it('namespace isolation: same jti against different audiences claims independently', async () => {
    const signer = LocalSigner.generate();
    const jwk = await signer.publicKey();
    const digest = requestBodyDigestOf({ action: 'data:export' });
    const store = new InMemoryReplayStore({ clock: () => NOW });
    const protectorA = new ReplayProtector(store);
    const protectorB = new ReplayProtector(store);
    const proofA = await createProof(signer, { htu: 'https://a.example/eval', requestBodyDigest: digest, jti: 'jti-iso-0123456789', iat: NOW - 5, exp: NOW + 300 });
    const proofB = await createProof(signer, { htu: 'https://b.example/eval', requestBodyDigest: digest, jti: 'jti-iso-0123456789', iat: NOW - 5, exp: NOW + 300 });
    const ra = await verifyProofWithReplay({ proof: proofA, publicJwk: jwk, htu: 'https://a.example/eval', requestBodyDigest: digest, now: NOW }, protectorA);
    const rb = await verifyProofWithReplay({ proof: proofB, publicJwk: jwk, htu: 'https://b.example/eval', requestBodyDigest: digest, now: NOW }, protectorB);
    expect(isOk(ra)).toBe(true);
    expect(isOk(rb)).toBe(true);
  });

  it('7K outage: valid request + store failure → REPLAY_PROTECTION_UNAVAILABLE', async () => {
    const { jwk, makeProof } = await setup();
    const { ReplayStoreUnavailableError } = await import('../src/types.js');
    const failingProtector = new ReplayProtector({
      async claim() {
        throw new ReplayStoreUnavailableError(new Error('ECONNREFUSED'));
      },
    });
    const result = await verifyProofWithReplay(
      { proof: await makeProof('jti-outage-01234567'), publicJwk: jwk, htu: HTU, requestBodyDigest: requestBodyDigestOf({ actor: 'did:key:zAgent', action: 'refund:create', amount: 120 }), now: NOW },
      failingProtector,
    );
    expect(result).toEqual({
      ok: false,
      stage: 'replay',
      reasonCode: 'REPLAY_PROTECTION_UNAVAILABLE',
      replayChecked: true,
    });
  });
});
