import type { DidDocument, DidResolutionResult, DidResolver } from './types.js';
import { parseDidUrl } from './types.js';

/**
 * Method allowlist + dispatch. The trust-gateway is constructed with
 * exactly the resolvers the deployment supports (P0: did:key, did:web) —
 * resolution of any other method is methodUnsupported, never an error
 * thrown into the request path (threat model: DID resolution abuse).
 */
export class MultiDidResolver implements DidResolver {
  readonly #resolvers: readonly DidResolver[];

  constructor(resolvers: readonly DidResolver[]) {
    this.#resolvers = resolvers;
  }

  supports(did: string): boolean {
    return this.#resolvers.some((r) => r.supports(did));
  }

  async resolve(did: string): Promise<DidResolutionResult> {
    const resolver = this.#resolvers.find((r) => r.supports(did));
    if (!resolver) {
      return { didDocument: null, didResolutionMetadata: { error: 'methodUnsupported' } };
    }
    return resolver.resolve(did);
  }

  /** Resolve a kid (DID URL) to the exact verification method it names. */
  async resolveVerificationMethod(kid: string): Promise<
    | { ok: true; didDocument: DidDocument; method: NonNullable<DidDocument['verificationMethod']>[number] }
    | { ok: false; error: DidResolutionResult['didResolutionMetadata'] }
  > {
    const { did, fragment } = parseDidUrl(kid);
    const result = await this.resolve(did);
    if (!result.didDocument) {
      return { ok: false, error: result.didResolutionMetadata };
    }
    const methods = result.didDocument.verificationMethod ?? [];
    const method =
      fragment === undefined
        ? methods[0]
        : methods.find((m) => m.id === kid);
    if (!method) {
      return {
        ok: false,
        error: { error: 'invalidDid', message: `verification method not found: ${kid}` },
      };
    }
    return { ok: true, didDocument: result.didDocument, method };
  }
}
