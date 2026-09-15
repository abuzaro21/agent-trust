import { describe, expect, it } from 'vitest';

import { POST as evaluate } from '../src/app/api/trust/evaluate/route';
import { GET as getProfile } from '../src/app/api/agents/[did]/profile/route';
import { GET as getAudit } from '../src/app/api/audit/[streamId]/route';

/**
 * Step 14 — API adapter integration. The routes MUST preserve the exact
 * gateway semantics: same reasons, same stage gating, same receipts.
 */

async function post(preset: string) {
  const res = await evaluate(
    new Request('http://localhost/api/trust/evaluate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ preset }),
    }),
  );
  return { status: res.status, json: await res.json() };
}

async function postCustom(body: Record<string, unknown>) {
  const res = await evaluate(
    new Request('http://localhost/api/trust/evaluate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
  return { status: res.status, json: await res.json() };
}

describe('trust evaluate API (exact gateway semantics)', () => {
  it('120 SAR → ALLOW + SUCCEEDED with receipts', async () => {
    const { json } = await post('valid-120');
    expect(json.result.effect).toBe('ALLOW');
    expect(json.result.outcome).toBe('AUTHORIZED');
    expect(json.result.stages.execution).toBe('SUCCEEDED');
    expect(json.result.decisionReceiptId).toBeDefined();
    expect(json.result.executionReceiptId).toBeDefined();
    expect(json.runReceipts.length).toBeGreaterThanOrEqual(1);
  });

  it('5000 SAR → DENY AUTHORITY_LIMIT_EXCEEDED, execution NOT_RUN', async () => {
    const { json } = await post('over-5000');
    expect(json.result.effect).toBe('DENY');
    expect(json.result.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    expect(json.result.stages.identity).toBe('PASS');
    expect(json.result.stages.execution).toBe('NOT_RUN');
  });

  it('spoof preset → IDENTITY_PROOF_INVALID with zero victim attribution', async () => {
    const { json } = await post('spoof');
    expect(json.result.reasonCodes).toEqual(['IDENTITY_PROOF_INVALID']);
    expect(json.result.stages.policy).toBe('NOT_RUN');
    expect(json.runReceipts).toEqual([]);
  });

  it('revoked preset → CREDENTIAL_REVOKED, and the primary credential survives', async () => {
    const { json } = await post('revoked');
    expect(json.result.reasonCodes).toEqual(['CREDENTIAL_REVOKED']);
    // The primary demo delegation must still work afterwards (14W).
    const after = await post('valid-120');
    expect(after.json.result.effect).toBe('ALLOW');
  });

  it('replay preset → first AUTHORIZED, replay REPLAY_DETECTED', async () => {
    const { json } = await post('replay');
    expect(json.firstResult.outcome).toBe('AUTHORIZED');
    expect(json.result.reasonCodes).toEqual(['REPLAY_DETECTED']);
    expect(json.result.stages.replay).toBe('FAIL');
  });

  it('wrong-audience preset → AUDIENCE_MISMATCH at policy', async () => {
    const { json } = await post('wrong-audience');
    expect(json.result.reasonCodes).toEqual(['AUDIENCE_MISMATCH']);
  });

  it('tampered preset → denied at identity, policy never sees 5000', async () => {
    const { json } = await post('tampered');
    expect(json.result.reasonCodes).toEqual(['IDENTITY_PROOF_INVALID']);
    expect(json.result.stages.policy).toBe('NOT_RUN');
  });

  it('quarantine preset → AGENT_QUARANTINED then restored', async () => {
    const { json } = await post('quarantine');
    expect(json.result.reasonCodes).toEqual(['AGENT_QUARANTINED']);
    const ok = await post('valid-120');
    expect(ok.json.result.effect).toBe('ALLOW');
  });

  it('unknown preset → 400 REQUEST_MALFORMED', async () => {
    const { status, json } = await post('drop-database');
    expect(status).toBe(400);
    expect(json.error).toBe('REQUEST_MALFORMED');
  });

  it('trustScore injection cannot influence the decision', async () => {
    const { json } = await postCustom({ amount: 5000, trustScore: 100, reputation: 'excellent' });
    // Extra fields are ignored/stripped at the request-schema boundary —
    // the gateway still denies on amount.
    expect(json.result.effect).toBe('DENY');
    expect(json.result.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
    // And nothing in the response echoes or stores a score.
    expect(JSON.stringify(json)).not.toMatch(/trustScore|reputation/i);
  });
});

describe('profile + audit APIs', () => {
  it('profile for the demo agent: resolved, authority present, NO score anywhere', async () => {
    const res = await getProfile(new Request('http://localhost/api/agents/support/profile'), {
      params: Promise.resolve({ did: 'support' }),
    });
    const json = await res.json();
    expect(json.profile.identity.resolved).toBe(true);
    expect(json.profile.authority.active).toHaveLength(1);
    expect(json.profile.attestations.trusted.length).toBeGreaterThanOrEqual(1);
    expect(json.profile.attestations.rejected.length).toBeGreaterThanOrEqual(1);
    const serialized = JSON.stringify(json).toLowerCase();
    for (const banned of ['trustscore', 'reputationscore', 'riskscore', 'confidence', 'rating', 'stars']) {
      expect(serialized).not.toContain(banned);
    }
  });

  it('audit API returns verified chain + checkpoint status', async () => {
    const res = await getAudit(new Request('http://localhost/api/audit/acme-demo'), {
      params: Promise.resolve({ streamId: 'acme-demo' }),
    });
    const json = await res.json();
    expect(json.chain.valid).toBe(true);
    expect(json.checkpoint.signatureValid).toBe(true);
    expect(Array.isArray(json.receipts)).toBe(true);
  });
});
