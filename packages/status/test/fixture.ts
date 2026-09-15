import { LocalSigner } from '@agent-trust/crypto';
import { InMemoryDidResolver, didDocumentForJwk } from '@agent-trust/did';
import { CredentialIssuer, InMemoryIssuerTrustStore } from '@agent-trust/vc';

/** Fixed clock — no wall-clock dependence anywhere in status tests. */
export const NOW = 1_757_800_000;
export const TICK = 60;

export const ORG_DID = 'did:web:acme.example:org';
export const EVIL_DID = 'did:web:evil.example:org';
export const AGENT_DID = 'did:key:zStatusAgent';

export const REV_LIST = 'https://acme.example/status/rev/1';
export const SUS_LIST = 'https://acme.example/status/susp/1';
export const LIST_BITS = 64;

export interface StatusWorld {
  orgSigner: ReturnType<typeof LocalSigner.generate>;
  issuer: CredentialIssuer;
  resolver: InMemoryDidResolver;
  trustStore: InMemoryIssuerTrustStore;
}

export async function buildWorld(): Promise<StatusWorld> {
  const orgSigner = LocalSigner.generate();
  const resolver = new InMemoryDidResolver([
    didDocumentForJwk(ORG_DID, await orgSigner.publicKey()),
  ]);
  const trustStore = new InMemoryIssuerTrustStore()
    .trust(ORG_DID, 'AgentMembershipCredential')
    .trust(ORG_DID, 'AgentDelegationCredential');
  const issuer = new CredentialIssuer(orgSigner, { issuerDid: ORG_DID });
  return { orgSigner, issuer, resolver, trustStore };
}

export function statusEntry(input: {
  purpose: 'revocation' | 'suspension';
  listId: string;
  index: number | string;
}): Record<string, unknown> {
  return {
    id: `${input.listId}#${input.index}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: input.purpose,
    statusListIndex: String(input.index),
    statusListCredential: input.listId,
  };
}
