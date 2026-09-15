import { sha256Hex, utf8 } from '@agent-trust/crypto';

/**
 * Replay key design (Step 7D).
 *
 * The namespace binds audience (the exact htu the proof was verified
 * against) and the signer's kid. Two unrelated agents may coincidentally
 * pick the same jti without colliding; the same actor cannot replay a
 * proof against the same target; cross-audience replay is independently
 * prevented because the proof signature is bound to the htu.
 *
 * Raw namespace strings are NEVER used as keys directly — they are
 * canonicalized and hashed, so attacker-influenced content (kid, htu)
 * cannot abuse key structure:
 *
 *   replay:v1:<sha256(canonical namespace)>:<jti>
 *
 * The trailing jti is NOT attacker-free-form: it is validated against
 * JTI_PATTERN before ever reaching a store (Step 7N).
 */

/** Canonical namespace input: audience (htu) + verification-method id. */
export interface ReplayNamespaceParts {
  /** The exact htu the proof was cryptographically verified against. */
  audience: string;
  /** The proof's kid (DID URL of the signing verification method). */
  kid: string;
}

export function canonicalReplayNamespace(parts: ReplayNamespaceParts): string {
  // NUL separator prevents ambiguity from separator characters in inputs.
  return `${parts.audience}\u0000${parts.kid}`;
}

export function replayKey(namespace: string, jti: string): string {
  return `replay:v1:${sha256Hex(utf8(namespace))}:${jti}`;
}

/**
 * jti validation (Step 7N): non-empty, 8–128 chars, bounded charset.
 * Malformed jtis are rejected BEFORE any store is touched.
 */
export const JTI_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;

export function isValidJti(jti: string): boolean {
  return JTI_PATTERN.test(jti);
}
