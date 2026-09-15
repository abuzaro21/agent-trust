import {
  SCHEMA_ID_POLICY_RESULT,
  SCHEMA_ID_VERIFIED_FACTS,
  type ReasonCode,
  type Validator,
  createValidator,
} from '@agent-trust/schemas';

import { loadBundle } from './manifest.js';
import type { LoadedBundle, BundleLoadFailure } from './manifest.js';
import type {
  PolicyDecision,
  PolicyEngine,
  PolicyLoadFailure,
  PolicyLoadResult,
} from './types.js';

/**
 * OPA Wasm SDK isolated here (Step 8G): nothing else in the application
 * imports @open-policy-agent/opa-wasm. The package ships dual ESM/CJS with
 * real typings; loadPolicySync instantiates the module once — the engine
 * then re-evaluates per request with NO recompilation (Step 8P).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OpaWasmModule = typeof import('@open-policy-agent/opa-wasm');

interface LoadedOpaPolicy {
  evaluate(input: unknown): unknown;
}

export interface OpaWasmEngineOptions {
  /**
   * Dependency injection for tests (failure simulation without the SDK).
   * Defaults to the real SDK import.
   */
  opaWasm?: OpaWasmModule;
}

/**
 * Embedded OPA Wasm policy engine (ADR-0002). Loading is fail-closed at
 * every step: read failures, invalid manifests, and hash mismatches refuse
 * to instantiate. Evaluation is fail-closed at every step: malformed
 * inputs, thrown evaluations, undefined/empty/malformed results, unknown
 * effects, and unknown reason codes all produce a DENY — never an allow.
 */
export async function loadOpaWasmPolicyEngine(
  wasmPath: string,
  manifestPath: string,
  opts: OpaWasmEngineOptions = {},
): Promise<PolicyLoadResult> {
  const bundle = await loadBundle(wasmPath, manifestPath);
  if (!bundle.ok) {
    return bundleLoadDenial(bundle);
  }
  let opa: OpaWasmModule;
  try {
    opa = opts.opaWasm ?? (await import('@open-policy-agent/opa-wasm'));
  } catch (e) {
    return { ok: false, reasonCode: 'POLICY_ENGINE_UNAVAILABLE', detail: `SDK import failed: ${String(e)}` };
  }

  let loaded: LoadedOpaPolicy;
  try {
    const policy = await opa.loadPolicy(bundle.wasm as unknown as Buffer);
    loaded = { evaluate: (input: unknown) => policy.evaluate(input) };
  } catch (e) {
    return { ok: false, reasonCode: 'POLICY_BUNDLE_INVALID', detail: `instantiation failed: ${String(e)}` };
  }

  const engine = new OpaWasmPolicyEngine(loaded, bundle);
  return { ok: true, engine, manifest: bundle.manifest, hash: bundle.actualHash };
}

function bundleLoadDenial(failure: BundleLoadFailure): PolicyLoadFailure {
  const reasonCode =
    failure.reason === 'read_failed'
      ? 'POLICY_ENGINE_UNAVAILABLE'
      : 'POLICY_BUNDLE_INVALID';
  return { ok: false, reasonCode, detail: `${failure.reason}: ${failure.detail}` };
}

const INFRA_DENY: PolicyDecision = {
  effect: 'DENY',
  reasonCodes: ['POLICY_EVALUATION_ERROR'],
  policy: { id: 'unknown', version: 'unknown', hash: 'unknown' },
};

export class OpaWasmPolicyEngine implements PolicyEngine {
  readonly #policy: LoadedOpaPolicy;
  readonly #bundle: LoadedBundle;
  readonly #validator: Validator;
  readonly #entrypoint: string;

  constructor(policy: LoadedOpaPolicy, bundle: LoadedBundle, validator?: Validator) {
    this.#policy = policy;
    this.#bundle = bundle;
    this.#validator = validator ?? createValidator();
    this.#entrypoint = bundle.manifest.entrypoint;
  }

  async evaluate(rawInput: unknown): Promise<PolicyDecision> {
    // Stage 0 — the input must be full VerifiedFacts. Failed verification
    // never reaches the PDP; partial facts are inexpressible (Step 8A/O).
    if (!this.#validator.validate(SCHEMA_ID_VERIFIED_FACTS, rawInput).valid) {
      return this.deny('REQUEST_MALFORMED');
    }

    // Stage 1 — Wasm evaluation. A throw is infrastructure failure.
    let rawResult: unknown;
    try {
      rawResult = this.#policy.evaluate(rawInput);
    } catch {
      return this.deny('POLICY_EVALUATION_ERROR');
    }

    // Stage 2 — normalize the SDK's result-set shape. loadPolicy().evaluate
    // returns [{ result: <entrypoint value> }] (OPA result-set format);
    // the native `opa eval` returns the bare value. The Wasm parity tests
    // pin this unwrapping. An empty result-set is NEVER allow (Step 8J).
    let result: unknown = rawResult;
    if (Array.isArray(rawResult)) {
      result = (rawResult as { result?: unknown }[])[0]?.result;
    }
    if (result === undefined || result === null) {
      return this.deny('POLICY_EVALUATION_ERROR');
    }

    // Stage 3 — the raw Rego result must exactly match the PolicyResult
    // contract (closed effect + closed reason codes).
    const check = this.#validator.validate(SCHEMA_ID_POLICY_RESULT, result);
    if (!check.valid) {
      return this.deny('POLICY_EVALUATION_ERROR');
    }

    const { effect, reasonCodes } = result as { effect: PolicyDecision['effect']; reasonCodes: ReasonCode[] };
    return {
      effect,
      // The engine's defensive order is already deterministic from Rego;
      // re-sorting would obscure the policy's chosen precedence.
      reasonCodes,
      policy: {
        id: this.#bundle.manifest.id,
        version: this.#bundle.manifest.version,
        hash: this.#bundle.actualHash,
      },
    };
  }

  deny(reasonCode: ReasonCode): PolicyDecision {
    return {
      effect: 'DENY',
      reasonCodes: [reasonCode],
      policy: {
        id: this.#bundle.manifest.id,
        version: this.#bundle.manifest.version,
        hash: this.#bundle.actualHash,
      },
    };
  }

  get entrypoint(): string {
    return this.#entrypoint;
  }

  static readonly INFRA_DENY = INFRA_DENY;
}
