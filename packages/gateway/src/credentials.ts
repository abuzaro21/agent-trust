import type { DelegationParty } from '@agent-trust/delegation';
import type { Authority, ReasonCode } from '@agent-trust/schemas';
import { decodeJwsPayload, parseCompactJws } from '@agent-trust/vc';
import type { Validator } from '@agent-trust/schemas';

import type { VerifiedFacts } from './types.js';

/**
 * Credential selection (Step 10E) + delegation chain (Step 10F) +
 * VerifiedFacts construction (Step 10G).
 *
 * SELECTION operates on decoded (unverified) payload types only — it picks
 * WHICH credentials to verify, and every selected credential then goes
 * through the full verifier. Selection never authorizes.
 *
 * Strict P0 profile, fail-closed on ambiguity: all presented
 * AgentDelegationCredentials must form one attenuation chain ending at the
 * actor; zero delegation credentials is a malformed request.
 */
export interface SelectedCredentials {
  delegationJwsList: string[];
}

export type CredentialSelection =
  | { ok: true; selection: SelectedCredentials }
  | { ok: false; reasonCodes: ReasonCode[]; detail: string };

/** Decode payload types WITHOUT verification (selection only). */
function credentialTypes(jws: string): string[] | null {
  // parseCompactJws/decodeJwsPayload throw on structural garbage — a
  // malformed presented credential fails selection closed.
  try {
    const parsed = parseCompactJws(jws);
    const payload = decodeJwsPayload(parsed);
    const vc = payload['vc'] as { type?: unknown } | undefined;
    if (vc === undefined || !Array.isArray(vc.type)) return null;
    return vc.type as string[];
  } catch {
    return null;
  }
}

export function selectCredentials(input: {
  credentials: readonly string[];
}): CredentialSelection {
  const delegation: string[] = [];
  for (const jws of input.credentials) {
    const types = credentialTypes(jws);
    if (types === null) {
      return { ok: false, reasonCodes: ['VC_INVALID'], detail: 'presented credential is structurally invalid' };
    }
    if (types.includes('AgentDelegationCredential')) {
      delegation.push(jws);
    }
  }
  if (delegation.length === 0) {
    return { ok: false, reasonCodes: ['REQUEST_MALFORMED'], detail: 'no AgentDelegationCredential presented' };
  }
  return { ok: true, selection: { delegationJwsList: delegation } };
}

export type ChainBuildResult =
  | { ok: true; parties: DelegationParty[]; effectiveAuthority: DelegationParty }
  | { ok: false; reasonCodes: ReasonCode[]; detail: string };

/**
 * Build the delegation party list from VERIFIED delegation credentials
 * (claims already validated by CredentialVerifier). Order: issuer-of-next
 * must equal subject-of-previous; the LAST party must be the actor.
 */
export function buildDelegationChain(input: {
  verifiedDelegations: readonly {
    issuerDid: string;
    subjectDid: string;
    nbf: number;
    exp?: number;
    authority: import('@agent-trust/schemas').Authority;
  }[];
  actorDid: string;
}): ChainBuildResult {
  const { verifiedDelegations, actorDid } = input;
  if (verifiedDelegations.length === 0) {
    return { ok: false, reasonCodes: ['REQUEST_MALFORMED'], detail: 'no verified delegation credentials' };
  }
  // Link order: a credential issued BY the previous delegate comes next.
  const ordered: { issuerDid: string; subjectDid: string; nbf: number; exp?: number; authority: Authority }[] = [];
  let currentSubject: string | null = null;
  const pool: { issuerDid: string; subjectDid: string; nbf: number; exp?: number; authority: Authority }[] = [
    ...verifiedDelegations,
  ];
  while (pool.length > 0) {
    const pickIndex =
      currentSubject === null
        ? 0 // any root issuer (the organization) starts the chain
        : pool.findIndex((d) => d.issuerDid === currentSubject);
    if (pickIndex === -1) {
      return {
        ok: false,
        reasonCodes: ['DELEGATION_CYCLE'],
        detail: 'delegation credentials do not form a connected chain',
      };
    }
    const picked: {
      issuerDid: string;
      subjectDid: string;
      nbf: number;
      exp?: number;
      authority: Authority;
    } = pool.splice(pickIndex, 1)[0]!;
    ordered.push(picked);
    currentSubject = picked.subjectDid;
  }

  if (ordered[ordered.length - 1]!.subjectDid !== actorDid) {
    return {
      ok: false,
      reasonCodes: ['WRONG_SUBJECT'],
      detail: `delegation chain ends at ${ordered[ordered.length - 1]!.subjectDid}, not the authenticated actor ${actorDid}`,
    };
  }

  const parties: DelegationParty[] = ordered.map((d) => ({
    did: d.subjectDid,
    authority: d.authority,
    validFrom: d.nbf,
    validUntil: d.exp,
  }));
  return {
    ok: true,
    parties,
    effectiveAuthority: parties[parties.length - 1]!,
  };
}

/**
 * VerifiedFacts builder (Step 10G) — the single centralized constructor.
 * Input: outputs of VERIFIED stages only. Output: strict VerifiedFacts.
 * Controllers never assemble facts ad hoc.
 */
export function buildVerifiedFacts(input: {
  actorDid: string;
  controllerDid?: string;
  request: { action: string; resource: string; audience: string; parameters?: { amount?: number; currency?: string } };
  issuerDid: string;
  credentialTypes: string[];
  effectiveAuthority: DelegationParty['authority'];
  now: number;
}): VerifiedFacts {
  const canonicalNow = new Date(input.now * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return {
    actor: {
      did: input.actorDid,
      ...(input.controllerDid !== undefined ? { controller: input.controllerDid } : {}),
    },
    request: {
      action: input.request.action,
      resource: input.request.resource,
      audience: input.request.audience,
      ...(input.request.parameters !== undefined ? { parameters: input.request.parameters } : {}),
    },
    identity: { proofVerified: true },
    credential: {
      verified: true,
      issuer: input.issuerDid,
      issuerTrusted: true,
      types: input.credentialTypes,
    },
    authority: {
      actions: input.effectiveAuthority.actions,
      resources: input.effectiveAuthority.resources,
      ...(input.effectiveAuthority.audience !== undefined ? { audience: input.effectiveAuthority.audience } : {}),
      ...(input.effectiveAuthority.limits !== undefined ? { limits: input.effectiveAuthority.limits } : {}),
    },
    status: { credentialActive: true, quarantined: false },
    replay: { checked: true, claimed: true },
    context: { now: canonicalNow },
  };
}
