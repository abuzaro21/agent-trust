import { beforeAll, describe, expect, it } from 'vitest';
import { join } from 'node:path';

import {
  InMemoryDidResolver,
  MultiDidResolver,
} from '@agent-trust/did';
import {
  CredentialIssuer,
  CredentialVerifier,
  InMemoryIssuerTrustStore,
} from '@agent-trust/vc';
import {
  InMemoryAgentQuarantineStore,
  InMemoryStatusListStore,
  StatusListManager,
} from '@agent-trust/status';
import { InMemoryReplayStore } from '@agent-trust/replay';
import { ReplayProtector, verifyProofWithReplay } from '@agent-trust/replay';
import {
  loadOpaWasmPolicyEngine,
  type OpaWasmPolicyEngine,
} from '../src/index.js';
import {
  loadPolicyArtifactsPaths,
  NOW_UNIX,
  ORG_DID,
  REFUND_AGENT_DID,
  SUPPORT_AGENT_DID,
  type TrustStackWorld,
} from './fixture.js';
import { buildTrustStackWorld } from './fixture.js';

/**
 * 8R — THE composition test: full trust stack end-to-end.
 *
 *   real keypair → real DID → real VC issuance → real verification
 *   → real status lists → real quarantine store → real replay claim
 *   → VerifiedFacts → embedded OPA Wasm policy
 *
 * Case A (120 SAR)  → ALLOW
 * Case B (5000 SAR) → DENY AUTHORITY_LIMIT_EXCEEDED, with every security
 *                     gate still green — proving "the agent is trusted,
 *                     but not for this action."
 */

const { WASM_PATH, MANIFEST_PATH } = loadPolicyArtifactsPaths(__dirname);

describe('full trust stack → policy decision (8R)', () => {
  let world: TrustStackWorld;
  let engine: OpaWasmPolicyEngine;

  beforeAll(async () => {
    world = await buildTrustStackWorld();
    const result = await loadOpaWasmPolicyEngine(WASM_PATH, MANIFEST_PATH);
    if (!result.ok) throw new Error(`engine failed to load: ${result.detail}`);
    engine = result.engine as OpaWasmPolicyEngine;
  });

  async function evaluateRequest(
    amount: number,
    currency: string,
  ): Promise<{ effect: string; reasonCodes: string[]; pipeline: Record<string, unknown> }> {
    // 1. Agent signs a request proof (PoP) bound to this exact body/htu.
    const body = {
      actor: SUPPORT_AGENT_DID,
      action: 'refund:create',
      resource: 'order:ORD-918',
      parameters: { amount, currency },
    };
    const htu = 'https://gateway.example/v1/trust/evaluate';
    const { proof, requestBodyDigest } = await world.agentKeys.supportAgent.createProofBundle(body, htu);

    // 2. Gateway resolves kid → JWK (real resolver path).
    const multi = new MultiDidResolver([world.resolver]);
    const resolved = await multi.resolveVerificationMethod(proof.kid);
    expect(resolved.ok).toBe(true);
    if (!resolved.ok || !resolved.method.publicKeyJwk) throw new Error('kid resolution failed');

    // 3. PoP + replay (crypto FIRST, claim SECOND — Step 7 ordering).
    const replayResult = await verifyProofWithReplay(
      {
        proof,
        publicJwk: resolved.method.publicKeyJwk,
        htu,
        requestBodyDigest,
        now: NOW_UNIX,
      },
      world.replay.protector,
    );
    expect(replayResult.ok).toBe(true);
    if (!replayResult.ok) throw new Error('replay gate failed');

    // 4. Credential verification (signature/trust/status/quarantine gates).
    const vcResult = await world.verifier.verify(world.delegationJws, {
      now: NOW_UNIX,
      expectedSubject: SUPPORT_AGENT_DID,
      expectedType: 'AgentDelegationCredential',
    });
    expect(vcResult.valid).toBe(true);
    if (!vcResult.valid) throw new Error('credential verification failed');

    // 5. Assemble VerifiedFacts from the verified artifacts only.
    const facts = {
      actor: { did: SUPPORT_AGENT_DID, controller: ORG_DID },
      request: {
        action: 'refund:create',
        resource: 'order:ORD-918',
        audience: REFUND_AGENT_DID,
        parameters: { amount, currency },
      },
      identity: { proofVerified: true },
      credential: {
        verified: true,
        issuer: ORG_DID,
        issuerTrusted: true,
        types: ['VerifiableCredential', 'AgentDelegationCredential'],
      },
      authority: {
        actions: vcResult.facts.authority!.actions,
        resources: vcResult.facts.authority!.resources,
        audience: vcResult.facts.authority!.audience,
        limits: vcResult.facts.authority!.limits,
      },
      status: { credentialActive: true, quarantined: false },
      replay: { checked: true, claimed: true },
      // Canonical UTC seconds — Date.toISOString() emits milliseconds,
      // which violates the schema's lexicographic-time contract.
      context: { now: new Date(NOW_UNIX * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') },
    } as const;

    // 6. Policy decides.
    const decision = await engine.evaluate(facts);
    return { ...decision, pipeline: { replay: replayResult } };
  }

  it('Case A: 120 SAR → ALLOW through every real gate', async () => {
    const decision = await evaluateRequest(120, 'SAR');
    expect(decision.effect).toBe('ALLOW');
    expect(decision.reasonCodes[0]).toBe('IDENTITY_VERIFIED');
  });

  it('Case B: 5000 SAR → DENY AUTHORITY_LIMIT_EXCEEDED with all gates still green', async () => {
    const decision = await evaluateRequest(5000, 'SAR');
    expect(decision.effect).toBe('DENY');
    expect(decision.reasonCodes).toEqual(['AUTHORITY_LIMIT_EXCEEDED']);
  });

  it('replay of the SAME consumed proof still denies at the replay gate', async () => {
    const body = { actor: SUPPORT_AGENT_DID, action: 'refund:create' };
    const htu = 'https://gateway.example/v1/trust/evaluate';
    const { proof, requestBodyDigest } = await world.agentKeys.supportAgent.createProofBundle(body, htu);
    const multi = new MultiDidResolver([world.resolver]);
    const resolved = await multi.resolveVerificationMethod(proof.kid);
    if (!resolved.ok || !resolved.method.publicKeyJwk) throw new Error('kid resolution failed');
    const input = {
      proof,
      publicJwk: resolved.method.publicKeyJwk,
      htu,
      requestBodyDigest,
      now: NOW_UNIX,
    };
    expect((await verifyProofWithReplay(input, world.replay.protector)).ok).toBe(true);
    const second = await verifyProofWithReplay(input, world.replay.protector);
    expect(second).toEqual({
      ok: false,
      stage: 'replay',
      reasonCode: 'REPLAY_DETECTED',
      replayChecked: true,
    });
  });

  it('quarantined agent is denied before policy regardless of authority', async () => {
    world.quarantine.quarantine(SUPPORT_AGENT_DID, 'drill');
    const vcResult = await world.verifier.verify(world.delegationJws, {
      now: NOW_UNIX,
      expectedSubject: SUPPORT_AGENT_DID,
    });
    expect(vcResult).toEqual({ valid: false, reasonCodes: ['AGENT_QUARANTINED'] });
    world.quarantine.release(SUPPORT_AGENT_DID);
  });

  it('revoked credential denies even with perfect authority and replay state', async () => {
    await world.status.manager.revoke(world.status.revListId, world.status.delegationIndex);
    const vcResult = await world.verifier.verify(world.delegationJws, {
      now: NOW_UNIX,
      expectedSubject: SUPPORT_AGENT_DID,
    });
    expect(vcResult).toEqual({ valid: false, reasonCodes: ['CREDENTIAL_REVOKED'] });
  });
});
