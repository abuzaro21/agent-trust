/**
 * Shared helpers for the did:web demo identity tooling (Step 12X–12Z).
 *
 * Identity INITIALIZATION is separated from demo EXECUTION: keys are
 * generated ONCE into .local/demo-keys/ (gitignored) and reused, so the
 * public DID is stable across demo restarts. Private key material NEVER
 * leaves that directory; the published did.json files contain public keys
 * only. Deployed/live signing can supply the key from an environment
 * secret (DEMO_AGENT_KEY_JSON) instead — the Signer seam is unchanged.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { LocalSigner } from '@agent-trust/crypto';

export const ROOT = join(import.meta.dirname, '..');
export const KEY_DIR = join(ROOT, '.local', 'demo-keys');
export const DID_OUT_DIR = join(ROOT, '.local', 'did-host');

/** The two demo identities — each gets its OWN key. */
export const DEMO_AGENTS = [
  { name: 'org', path: 'org' },
  { name: 'support', path: 'agents/support' },
  { name: 'refund', path: 'agents/refund' },
];

export function requireEnv(name) {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    console.error(`missing required environment variable: ${name}`);
    if (name === 'DEMO_DID_DOMAIN') {
      console.error('public hosting is deployment-gated: set DEMO_DID_DOMAIN to your DID host');
      console.error('(e.g. DEMO_DID_DOMAIN=trust.example.com) and publish the generated did.json there.');
    }
    process.exit(2);
  }
  return value.trim();
}

/** 'agents/support' → ['agents','support'] (percent-encoded per method spec). */
export function pathToSegments(demoPath) {
  return demoPath
    .split('/')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => encodeURIComponent(s));
}

/** domain (may contain %3A-encoded port) + segments → did:web string. */
export function didFor(domain, segments) {
  const host = domain.includes('%') ? domain : domain.replace(/:(?=\d)/g, '%3A');
  return `did:web:${host}${segments.length > 0 ? `:${segments.join(':')}` : ''}`;
}

/** The resolution URL for a did:web identifier (mirrors the resolver). */
export function urlFor(did) {
  const msi = did.slice('did:web:'.length);
  const parts = msi.split(':');
  const host = decodeURIComponent(parts[0]);
  const path =
    parts.length === 1 ? '.well-known/did.json' : `${parts.slice(1).map(decodeURIComponent).join('/')}/did.json`;
  return `https://${host}/${path}`;
}

/**
 * Load the agent's key from the gitignored local dir, or the
 * DEMO_AGENT_KEY_JSON env override (deployment path); create on first run
 * only when persistence mode allows. Returns { signer, created }.
 */
export function loadOrCreateAgentKey(name, did, opts = { allowCreate: true }) {
  const envKey = process.env.DEMO_AGENT_KEY_JSON;
  if (envKey !== undefined && envKey !== '') {
    // Deployment: key material from the environment secret. One key per
    // invocation agent — the runner sets the env per agent.
    return { signer: LocalSigner.fromPrivateJwk(JSON.parse(envKey), { did }), created: false };
  }
  const file = join(KEY_DIR, `${name}.key.json`);
  if (existsSync(file)) {
    return { signer: LocalSigner.fromPrivateJwk(JSON.parse(readFileSync(file, 'utf8')), { did }), created: false };
  }
  if (!opts.allowCreate) {
    return null; // execution mode must not silently mint a new identity
  }
  mkdirSync(KEY_DIR, { recursive: true });
  const signer = LocalSigner.generate({ did });
  writeFileSync(file, JSON.stringify(signer.exportPrivateJwk(), null, 2), { mode: 0o600 });
  return { signer, created: true };
}

/** Deterministic demo clock used by all web demos. */
export const NOW_UNIX = 1_789_473_600; // 2026-09-15T12:00:00Z
export function canonicalNow(unix = NOW_UNIX) {
  return new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}
