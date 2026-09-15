import { LocalSigner, withDid } from '@agent-trust/crypto';
import { InMemoryDidResolver, didDocumentForJwk } from '@agent-trust/did';
import type { ReasonCode } from '@agent-trust/schemas';

import { buildReceiptBody } from '../src/index.js';
import type { ReceiptSecurityInput } from '../src/receipt-builder.js';
import type { ActionReceiptBody } from '../src/types.js';

export const NOW = '2026-09-15T12:00:00Z';
export const NOW_UNIX = 1_757_944_800;
export const STREAM_A = 'acme-demo';
export const STREAM_B = 'beta-demo';
export const ORG_DID = 'did:web:acme.example:org';
export const AUDITOR_DID = 'did:web:audit.acme.example:anchor';

export const SECURITY_OK: ReceiptSecurityInput = {
  proofVerified: true,
  credentialVerified: true,
  issuerTrusted: true,
  credentialActive: true,
  quarantined: false,
  replayChecked: true,
};

let counter = 0;

/** Deterministic receipt body factory for tests. */
export function makeBody(overrides: Partial<ActionReceiptBody> = {}): Omit<ActionReceiptBody, 'streamId' | 'sequence'> {
  counter += 1;
  return buildReceiptBody({
    receiptId: `rcpt_test_${String(counter).padStart(6, '0')}`,
    recordedAt: NOW,
    actor: { did: 'did:web:agents.acme.example:support-1', controller: ORG_DID },
    request: {
      action: 'refund:create',
      resource: 'order:ORD-918',
      audience: 'did:web:payments.example:refund-agent',
      parameters: { amount: 120, currency: 'SAR' },
    },
    authority: { credentialId: `vc_${String(counter).padStart(8, '0')}`, issuer: ORG_DID },
    security: SECURITY_OK,
    decision: {
      effect: 'ALLOW',
      reasonCodes: ['IDENTITY_VERIFIED', 'WITHIN_AMOUNT_LIMIT'],
      policy: { id: 'agent-trust-refund', version: '1.1.0', hash: `sha256:${'b'.repeat(64)}` },
    },
    ...overrides,
  }) as Omit<ActionReceiptBody, 'streamId' | 'sequence'>;
}

export function makeDenyBody(reasonCode: ReasonCode = 'AUTHORITY_LIMIT_EXCEEDED'): Omit<ActionReceiptBody, 'streamId' | 'sequence'> {
  return makeBody({
    request: {
      action: 'refund:create',
      resource: 'order:ORD-918',
      audience: 'did:web:payments.example:refund-agent',
      parameters: { amount: 5000, currency: 'SAR' },
    },
    decision: {
      effect: 'DENY',
      reasonCodes: [reasonCode],
      policy: { id: 'agent-trust-refund', version: '1.1.0', hash: `sha256:${'b'.repeat(64)}` },
    },
  });
}

export async function auditWorld() {
  const anchorSigner = withDid(LocalSigner.generate(), AUDITOR_DID);
  const evilSigner = withDid(LocalSigner.generate(), 'did:web:evil.example:anchor');
  const resolver = new InMemoryDidResolver([
    didDocumentForJwk(AUDITOR_DID, await anchorSigner.publicKey()),
    didDocumentForJwk('did:web:evil.example:anchor', await evilSigner.publicKey()),
  ]);
  return { anchorSigner, evilSigner, resolver };
}
