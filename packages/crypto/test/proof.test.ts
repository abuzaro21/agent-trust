import { describe, expect, it } from 'vitest';

import {
  LocalSigner,
  createProof,
  requestBodyDigestOf,
  verifyProof,
} from '../src/index.js';

const NOW = 1_757_800_000;
const HTU = 'https://trust-gateway.internal/v1/trust/evaluate';

async function setup() {
  const signer = LocalSigner.generate();
  const body = { actor: 'did:key:agent-a', action: 'refund:create', amount: 120 };
  const digest = requestBodyDigestOf(body);
  const binding = {
    htu: HTU,
    requestBodyDigest: digest,
    jti: 'jti-0123456789abcdef',
    iat: NOW,
    exp: NOW + 300,
  };
  const proof = await createProof(signer, binding);
  return { signer, body, digest, binding, proof };
}

describe('proof of possession', () => {
  it('verifies a proof it just created', async () => {
    const { signer, digest, proof } = await setup();
    const result = verifyProof({
      proof,
      publicJwk: await signer.publicKey(),
      htu: HTU,
      requestBodyDigest: digest,
      now: NOW + 10,
    });
    expect(result).toEqual({ valid: true });
  });

  it('rejects a different request body (action changed after signing)', async () => {
    const { signer, proof } = await setup();
    const tamperedDigest = requestBodyDigestOf({ actor: 'did:key:agent-a', action: 'refund:create', amount: 50_000 });
    const result = verifyProof({
      proof,
      publicJwk: await signer.publicKey(),
      htu: HTU,
      requestBodyDigest: tamperedDigest,
      now: NOW + 10,
    });
    expect(result).toEqual({ valid: false, error: 'PROOF_SIGNATURE_INVALID' });
  });

  it('rejects a different target endpoint (audience/service binding)', async () => {
    const { signer, digest, proof } = await setup();
    const result = verifyProof({
      proof,
      publicJwk: await signer.publicKey(),
      htu: 'https://payments.example/other-endpoint',
      requestBodyDigest: digest,
      now: NOW + 10,
    });
    expect(result).toEqual({ valid: false, error: 'PROOF_SIGNATURE_INVALID' });
  });

  it('rejects an expired proof', async () => {
    const { signer, digest, proof } = await setup();
    const result = verifyProof({
      proof,
      publicJwk: await signer.publicKey(),
      htu: HTU,
      requestBodyDigest: digest,
      now: proof.exp + 1,
    });
    expect(result).toEqual({ valid: false, error: 'PROOF_EXPIRED' });
  });

  it('rejects a proof whose iat is in the future', async () => {
    const { signer, digest, proof } = await setup();
    const result = verifyProof({
      proof,
      publicJwk: await signer.publicKey(),
      htu: HTU,
      requestBodyDigest: digest,
      now: NOW - 1,
    });
    expect(result).toEqual({ valid: false, error: 'PROOF_NOT_YET_VALID' });
  });

  it('rejects a proof verified with someone else\'s key (spoofing test)', async () => {
    const { digest, proof } = await setup();
    const evil = LocalSigner.generate();
    const result = verifyProof({
      proof,
      publicJwk: await evil.publicKey(),
      htu: HTU,
      requestBodyDigest: digest,
      now: NOW + 10,
    });
    expect(result).toEqual({ valid: false, error: 'PROOF_SIGNATURE_INVALID' });
  });

  it('roundtrips a nonce through create/verify', async () => {
    const signer = LocalSigner.generate();
    const digest = requestBodyDigestOf({ a: 1 });
    const proof = await createProof(signer, {
      htu: HTU,
      requestBodyDigest: digest,
      jti: 'jti-nonce-01234567',
      iat: NOW,
      exp: NOW + 60,
      nonce: 'server-challenge-01',
    });
    expect(proof.nonce).toBe('server-challenge-01');
    expect(
      verifyProof({
        proof,
        publicJwk: await signer.publicKey(),
        htu: HTU,
        requestBodyDigest: digest,
        now: NOW + 1,
      }),
    ).toEqual({ valid: true });
  });

  it('refuses to create a proof with exp <= iat', async () => {
    const signer = LocalSigner.generate();
    await expect(
      createProof(signer, {
        htu: HTU,
        requestBodyDigest: 'x',
        jti: 'jti-0123456789abcdef',
        iat: NOW,
        exp: NOW,
      }),
    ).rejects.toThrow(RangeError);
  });
});
