import type { Signer } from '@agent-trust/crypto';
import { withDid } from '@agent-trust/crypto';
import { parseDidUrl } from '@agent-trust/did';
import {
  SCHEMA_ID_BITSTRING_STATUS_ENTRY,
  createValidator,
  type Validator,
} from '@agent-trust/schemas';
import {
  type CredentialStatusCheckInput,
  type CredentialStatusChecker,
  type CredentialStatusResult,
  decodeJwsPayload,
  parseCompactJws,
  signCompactJws,
  verifyCompactJwsSignature,
} from '@agent-trust/vc';
import type { DidResolver } from '@agent-trust/did';

import type { SignedStatusListStore, StatusList, StatusListStore } from './types.js';
import { StatusBitstring } from './bitstring.js';

/**
 * Status integrity (Step 6E): status data is NOT trusted arbitrary data.
 *
 * Two sources, both bound to the credential issuer:
 *
 *  - store mode: the checker reads the same trusted store the issuer's
 *    manager writes (one trust domain, e.g. an in-process deployment).
 *
 *  - signed mode: the checker holds ONLY signed status-list credentials
 *    (compact JWS). It verifies the signature against the RESOLVED key of
 *    the list issuer (kid ownership via the DidResolver) and then requires
 *    the list issuer to BE the credential issuer. Unsigned or attacker-
 *    controlled status data can therefore never flip revoked → active:
 *    every path either proves issuer control or returns UNKNOWN.
 *
 * UNKNOWN is deliberately fail-closed at the verifier: a status mechanism
 * that cannot prove "ACTIVE" denies the credential.
 */
export type StatusSource =
  | { kind: 'store'; store: StatusListStore }
  | { kind: 'signed'; lists: SignedStatusListStore; didResolver: DidResolver };

export class BitstringStatusChecker implements CredentialStatusChecker {
  readonly #source: StatusSource;
  readonly #validator: Validator;

  constructor(source: StatusSource) {
    this.#source = source;
    this.#validator = createValidator();
  }

  async check(input: CredentialStatusCheckInput): Promise<CredentialStatusResult> {
    const checkedAt = new Date(input.now * 1000).toISOString();
    const unknown = (detail: string): CredentialStatusResult => ({
      state: 'UNKNOWN',
      checkedAt,
      detail,
    });

    // The entry comes from signed-but-attacker-influencable claims —
    // validate its shape before trusting any field.
    const entryOk = this.#validator.validate(SCHEMA_ID_BITSTRING_STATUS_ENTRY, input.status);
    if (!entryOk.valid) return unknown(`malformed status entry: ${entryOk.errors.join('; ')}`);

    const entry = input.status as {
      statusPurpose: 'revocation' | 'suspension';
      statusListIndex: string;
      statusListCredential: string;
    };
    const index = Number(entry.statusListIndex);
    if (!Number.isInteger(index) || index < 0) {
      return unknown('statusListIndex is not a non-negative integer');
    }

    const listResult =
      this.#source.kind === 'store'
        ? await this.#fromStore(entry.statusListCredential, this.#source.store)
        : await this.#fromSigned(
            entry.statusListCredential,
            input.issuerDid,
            this.#source.lists,
            this.#source.didResolver,
          );
    if ('unknown' in listResult) return unknown(listResult.unknown);

    const list = listResult.list;

    // Trust binding: the list belongs to the credential issuer.
    if (list.controllerDid !== input.issuerDid) {
      return unknown(
        `status list ${list.id} is controlled by ${list.controllerDid}, not the credential issuer`,
      );
    }
    // Purpose binding: a suspension entry cannot read a revocation list.
    if (list.purpose !== entry.statusPurpose) {
      return unknown(`status purpose mismatch: entry=${entry.statusPurpose} list=${list.purpose}`);
    }

    let bits: StatusBitstring;
    try {
      bits = StatusBitstring.fromBase64Url(list.encodedList, list.sizeBits);
    } catch {
      return unknown('malformed status list encoding');
    }
    if (index >= bits.sizeBits) return unknown(`status index ${index} out of range`);

    const set = bits.get(index);
    const state = set ? (list.purpose === 'revocation' ? 'REVOKED' : 'SUSPENDED') : 'ACTIVE';
    return { state, checkedAt, source: list.id };
  }

  async #fromStore(
    listId: string,
    store: StatusListStore,
  ): Promise<{ list: StatusList } | { unknown: string }> {
    const list = await store.get(listId);
    if (!list) return { unknown: `status list ${listId} not found` };
    return { list };
  }

  async #fromSigned(
    ref: string,
    issuerDid: string,
    lists: SignedStatusListStore,
    didResolver: DidResolver,
  ): Promise<{ list: StatusList } | { unknown: string }> {
    const jws = await lists.get(ref);
    if (!jws) return { unknown: `signed status list ${ref} not found` };

    let parsed;
    try {
      parsed = parseCompactJws(jws);
    } catch {
      return { unknown: 'status list credential is malformed' };
    }
    const payload = decodeJwsPayload(parsed) as Partial<SignedStatusListPayload> | undefined;
    if (
      payload === undefined ||
      typeof payload.iss !== 'string' ||
      typeof payload.statusListId !== 'string' ||
      typeof payload.statusPurpose !== 'string' ||
      typeof payload.sizeBits !== 'number' ||
      typeof payload.encodedList !== 'string'
    ) {
      return { unknown: 'status list credential claims are malformed' };
    }

    // kid ownership + signature, via the SAME primitives as VC verification.
    const resolution = await didResolver.resolve(payload.iss);
    const kid = parsed.protectedHeader.kid;
    if (typeof kid !== 'string') return { unknown: 'status list kid missing' };
    if (parseDidUrl(kid).did !== payload.iss) {
      return { unknown: 'status list kid does not belong to the list issuer' };
    }
    const method = resolution.didDocument?.verificationMethod?.find((m) => m.id === kid);
    if (!method?.publicKeyJwk) return { unknown: 'status list issuer key not resolvable' };
    if (!verifyCompactJwsSignature(parsed, method.publicKeyJwk)) {
      return { unknown: 'status list signature invalid' };
    }

    // Trust binding: whoever signed the list must be the credential issuer.
    if (payload.iss !== issuerDid) {
      return {
        unknown: `status list issuer ${payload.iss} is not the credential issuer ${issuerDid}`,
      };
    }
    if (payload.statusListId !== ref) {
      return { unknown: 'status list credential does not match the referenced list' };
    }

    return {
      list: {
        id: payload.statusListId,
        purpose: payload.statusPurpose as StatusList['purpose'],
        controllerDid: payload.iss,
        sizeBits: payload.sizeBits,
        encodedList: payload.encodedList,
        version: payload.version ?? 0,
        updatedAt: payload.updatedAt ?? 0,
      },
    };
  }
}

export interface SignedStatusListPayload {
  iss: string;
  jti: string;
  iat: number;
  statusListId: string;
  statusPurpose: 'revocation' | 'suspension';
  sizeBits: number;
  encodedList: string;
  version: number;
  updatedAt: number;
}

/**
 * Publish a status list as a signed status-list credential using the
 * EXISTING VC signing primitives (no second crypto stack). Pass issuerDid
 * to label the signer — a bare LocalSigner's kid has no DID and would be
 * correctly rejected by the checker.
 */
export async function signStatusListCredential(
  list: StatusList,
  signer: Signer,
  opts: { now: number; issuerDid?: string },
): Promise<string> {
  const effective =
    opts.issuerDid !== undefined ? withDid(signer, opts.issuerDid) : signer;
  const kid = await effective.keyId();
  const payload: SignedStatusListPayload = {
    iss: parseDidUrl(kid).did,
    jti: list.id,
    iat: opts.now,
    statusListId: list.id,
    statusPurpose: list.purpose,
    sizeBits: list.sizeBits,
    encodedList: list.encodedList,
    version: list.version,
    updatedAt: list.updatedAt,
  };
  return signCompactJws(effective, payload as unknown as Record<string, unknown>);
}
