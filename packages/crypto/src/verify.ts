import { createPublicKey, verify as nodeVerify } from 'node:crypto';

import type { PublicJwk } from './types.js';

/**
 * Verify an ES256 signature made by a LocalSigner (or any EC P-256 signer)
 * against a public JWK. Returns a boolean — callers map failures to their
 * own reason codes (IDENTITY_PROOF_INVALID / VC_SIGNATURE_INVALID).
 */
export function verifyEs256(input: {
  publicJwk: PublicJwk;
  data: Uint8Array;
  signature: Uint8Array;
}): boolean {
  let keyObject: ReturnType<typeof createPublicKey>;
  try {
    keyObject = createPublicKey({ key: input.publicJwk as never, format: 'jwk' });
  } catch {
    return false;
  }
  try {
    return nodeVerify(
      'SHA256',
      Buffer.from(input.data),
      keyObject,
      Buffer.from(input.signature),
    );
  } catch {
    return false;
  }
}
