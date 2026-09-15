#!/usr/bin/env node
/**
 * Build the policy bundle deterministically (Step 8H/8I):
 *
 *   opa fmt --fail → opa check → opa test → opa build -t wasm
 *   → extract policy.wasm → SHA-256 → write manifest.json (no volatile fields)
 *
 * Uses the OPA binary from PATH, or tools/bin/opa(.exe) on Windows.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const POLICY_DIR = join(ROOT, 'policies', 'agent-trust');
const ARTIFACTS = join(ROOT, 'artifacts', 'policy');
const POLICY_VERSION = '1.1.0';

function findOpa() {
  const bin = process.platform === 'win32' ? 'opa.exe' : 'opa';
  const local = join(ROOT, 'tools', 'bin', bin);
  if (existsSync(local)) return local;
  return 'opa'; // from PATH (CI installs it)
}

const opa = findOpa();
const run = (args, opts = {}) => {
  execFileSync(opa, args, { stdio: 'inherit', cwd: ROOT, ...opts });
};

run(['fmt', '--fail', 'policies/']);
run(['check', 'policies/']);
run(['test', '--fail-on-empty', 'policies/']);

const tmp = mkdtempSync(join(tmpdir(), 'policy-build-'));
const bundle = join(tmp, 'bundle.tar.gz');
run(['build', '-t', 'wasm', '-e', 'agenttrust/decision', '-o', bundle, join(POLICY_DIR, 'decision.rego')]);

// OPA's Wasm output is deterministic PER PLATFORM but differs between
// platforms (Windows vs Linux toolchains). The manifest therefore records
// BOTH the built-wasm hash (artifact integrity) and the Rego source hash
// (platform-independent source binding); CI verifies both instead of
// recompiling. Behavioral equivalence is enforced by the wasm-parity tests.
const { gunzipSync } = await import('node:zlib');
const raw = gunzipSync(readFileSync(bundle));
const HEADER = 512;
let offset = 0;
let wasmBytes = null;
while (offset + HEADER <= raw.length) {
  const header = raw.subarray(offset, offset + HEADER);
  if (header.every((b) => b === 0)) break; // end-of-archive
  const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
  const sizeStr = header.subarray(124, 136).toString('utf8').replace(/[\0 ]/g, '');
  const size = parseInt(sizeStr, 8);
  if (Number.isNaN(size)) throw new Error(`tar parse: bad size for member ${name}`);
  const dataStart = offset + HEADER;
  if (name === 'policy.wasm' || name === '/policy.wasm') {
    wasmBytes = raw.subarray(dataStart, dataStart + size);
    break;
  }
  offset = dataStart + Math.ceil(size / HEADER) * HEADER;
}
if (!wasmBytes) throw new Error('policy.wasm member not found in OPA bundle');
const regoSource = readFileSync(join(POLICY_DIR, 'decision.rego'));
const regoHash = `sha256:${createHash('sha256').update(regoSource).digest('hex')}`;
const hash = `sha256:${createHash('sha256').update(wasmBytes).digest('hex')}`;

mkdirSync(ARTIFACTS, { recursive: true });
writeFileSync(join(ARTIFACTS, 'policy.wasm'), wasmBytes);
writeFileSync(
  join(ARTIFACTS, 'manifest.json'),
  `${JSON.stringify(
    {
      id: 'agent-trust-refund',
      version: POLICY_VERSION,
      entrypoint: 'agenttrust/decision',
      sha256: hash,
      regoSha256: regoHash,
      compiledBy: 'opa v1.20.2 -t wasm -e agenttrust/decision',
    },
    null,
    2,
  )}\n`,
);
rmSync(tmp, { recursive: true, force: true });
console.log(`policy built: ${hash}`);
console.log(`rego source:  ${regoHash}`);
