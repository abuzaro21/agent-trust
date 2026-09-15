import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import type { PolicyManifest } from './types.js';

/**
 * Manifest handling (Step 8I). No nondeterministic fields — builtAt was
 * deliberately omitted; version + content hash identify a bundle exactly.
 */

/** Accepts 'sha256:<64hex>' (our manifest) or a bare 64-hex digest. */
export function normalizeSha256(value: string): string | null {
  const hex = value.startsWith('sha256:') ? value.slice(7) : value;
  return /^[a-f0-9]{64}$/.test(hex) ? `sha256:${hex}` : null;
}

export function sha256OfBytes(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function validateManifestShape(value: unknown): PolicyManifest | null {
  if (typeof value !== 'object' || value === null) return null;
  const m = value as Record<string, unknown>;
  if (
    typeof m.id !== 'string' || m.id.length === 0 ||
    typeof m.version !== 'string' || m.version.length === 0 ||
    typeof m.entrypoint !== 'string' || m.entrypoint.length === 0 ||
    typeof m.sha256 !== 'string' || normalizeSha256(m.sha256) === null ||
    typeof m.compiledBy !== 'string'
  ) {
    return null;
  }
  return {
    id: m.id,
    version: m.version,
    entrypoint: m.entrypoint,
    sha256: m.sha256,
    compiledBy: m.compiledBy,
  };
}

export interface LoadedBundle {
  ok: true;
  wasm: Uint8Array;
  manifest: PolicyManifest;
  /** sha256 of the wasm bytes, normalized. */
  actualHash: string;
}

export type BundleLoadFailure =
  | { ok: false; reason: 'read_failed'; detail: string }
  | { ok: false; reason: 'manifest_invalid'; detail: string }
  | { ok: false; reason: 'hash_mismatch'; detail: string };

/**
 * Load policy.wasm + manifest.json, compute the wasm digest, and compare
 * with the manifest. ANY mismatch fails closed before instantiation — a
 * modified Wasm policy must not silently execute (Step 8: hash integrity).
 */
export async function loadBundle(
  wasmPath: string,
  manifestPath: string,
): Promise<LoadedBundle | BundleLoadFailure> {
  let wasmBytes: Buffer;
  let manifestRaw: Buffer;
  try {
    [wasmBytes, manifestRaw] = await Promise.all([
      readFile(wasmPath),
      readFile(manifestPath),
    ]);
  } catch (e) {
    return { ok: false, reason: 'read_failed', detail: String(e) };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestRaw.toString('utf8'));
  } catch (e) {
    return { ok: false, reason: 'manifest_invalid', detail: `JSON parse: ${String(e)}` };
  }
  const manifest = validateManifestShape(parsed);
  if (!manifest) {
    return { ok: false, reason: 'manifest_invalid', detail: 'manifest shape rejected' };
  }

  const actualHash = sha256OfBytes(wasmBytes);
  const expectedHash = normalizeSha256(manifest.sha256);
  if (actualHash !== expectedHash) {
    return {
      ok: false,
      reason: 'hash_mismatch',
      detail: `expected ${expectedHash}, actual ${actualHash}`,
    };
  }
  return { ok: true, wasm: new Uint8Array(wasmBytes), manifest, actualHash };
}
