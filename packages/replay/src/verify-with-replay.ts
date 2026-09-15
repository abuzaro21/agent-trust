import type { PublicJwk } from '@agent-trust/crypto';
import type { AgentProof, ReasonCode } from '@agent-trust/schemas';
import { verifyProof, type ProofFailure } from '@agent-trust/crypto';

import { ReplayProtector } from './protector.js';
import type { ReplayProtectorOptions } from './protector.js';

/**
 * The safe high-level path (Step 7H): cryptographic PoP verification and
 * stateful anti-replay in one call, in the security-critical order —
 * signature → temporal validity → replay claim. Application callers who
 * use this function CANNOT accidentally skip replay protection for
 * protected writes, and invalid proofs can never claim (poison) a jti.
 */
export interface ProofWithReplayInput {
  proof: AgentProof;
  /** JWK resolved from the proof's kid (caller resolves via DidResolver). */
  publicJwk: PublicJwk;
  htu: string;
  requestBodyDigest: string;
  /** Verification clock (unix seconds). */
  now: number;
}

export type ProofWithReplayResult =
  | { ok: true; key: string; retentionSeconds: number; replayChecked: true; replayClaimed: true }
  | {
      ok: false;
      stage: 'crypto';
      error: ProofFailure;
      reasonCodes: ['IDENTITY_PROOF_INVALID'];
    }
  | {
      ok: false;
      stage: 'replay';
      reasonCode: Extract<
        ReasonCode,
        'REPLAY_DETECTED' | 'REPLAY_PROTECTION_UNAVAILABLE' | 'REQUEST_MALFORMED' | 'VC_EXPIRED'
      >;
      replayChecked: boolean;
    };

export async function verifyProofWithReplay(
  input: ProofWithReplayInput,
  protector: ReplayProtector,
): Promise<ProofWithReplayResult> {
  // Stage 1 — pure cryptography + temporal validity (stateless).
  const cryptoResult = verifyProof({
    proof: input.proof,
    publicJwk: input.publicJwk,
    htu: input.htu,
    requestBodyDigest: input.requestBodyDigest,
    now: input.now,
  });
  if (!cryptoResult.valid) {
    return { ok: false, stage: 'crypto', error: cryptoResult.error, reasonCodes: ['IDENTITY_PROOF_INVALID'] };
  }

  // Stage 2 — stateful anti-replay on the VERIFIED proof.
  const decision = await protector.verifyAndClaim({
    audience: input.htu,
    kid: input.proof.kid,
    jti: input.proof.jti,
    iat: input.proof.iat,
    exp: input.proof.exp,
    now: input.now,
  });
  if (decision.outcome === 'claimed') {
    return {
      ok: true,
      key: decision.key,
      retentionSeconds: decision.retentionSeconds,
      replayChecked: true,
      replayClaimed: true,
    };
  }
  return {
    ok: false,
    stage: 'replay',
    reasonCode: decision.reasonCode,
    replayChecked: decision.replayChecked,
  };
}

export { ReplayProtector, type ReplayProtectorOptions } from './protector.js';
