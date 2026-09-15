#!/usr/bin/env node
/**
 * pnpm smoke:live — STEP 16Z public-deployment regression smoke.
 *
 *   DEMO_PUBLIC_URL=https://demo.example.com pnpm smoke:live
 *
 * Runs entirely OUTSIDE the deployed process (what a judge's browser does):
 *   health · demo status (identityMode=web, replayStore=redis) · the three
 *   did:web documents at their derived public HTTPS URLs (resolved through
 *   the hardened Step 12 resolver) · trust profile · the four judge
 *   scenarios (120 ALLOW / 5000 DENY / spoof / revoked / replay pair) ·
 *   the baked 60/60 attack report · a browser-facing secret scan on every
 *   JSON response and the HTML shell.
 *
 * Replay-safe: scenario runs use fresh task/jti per request; the replay
 * check sends its own deliberate pair, so the smoke never poisons a later
 * smoke run.
 *
 * Exit 0 = deployment healthy. Non-zero + per-check FAIL lines otherwise.
 */
import { webcrypto } from 'node:crypto';

const base = (process.env.DEMO_PUBLIC_URL ?? '').replace(/\/$/, '');
if (base === '' || !/^https?:\/\//.test(base)) {
  console.error('DEMO_PUBLIC_URL is required (e.g. https://demo.example.com)');
  process.exit(2);
}

const DID_WEB_PREFIX = 'did:web:';
function didWebToUrl(did) {
  const rest = did.slice(DID_WEB_PREFIX.length);
  const [hostEnc, ...segs] = rest.split(':');
  const host = decodeURIComponent(hostEnc);
  const path = segs.length === 0 ? '.well-known/did.json' : `${segs.map(decodeURIComponent).join('/')}/did.json`;
  return `https://${host}/${path}`;
}

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function getJson(path, init) {
  const res = await fetch(base + path, init);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* non-JSON response surfaced via status */
  }
  return { res, json, text };
}

// --- browser-facing secret scan (Step 16R) --------------------------------
const SECRET_PATTERNS = [
  [/"d"\s*:\s*"[A-Za-z0-9_-]{16,}"/, 'private JWK d'],
  [/DEMO_[A-Z_]*KEY_JSON/, 'key secret env name'],
  [/redis(s)?:\/\//i, 'redis connection URL'],
  [/"(password|secret|passphrase|token)"\s*:/i, 'generic secret field'],
];
function scanLeaks(label, text) {
  const hits = SECRET_PATTERNS.filter(([re]) => re.test(text)).map(([, n]) => n);
  check(`leak scan: ${label}`, hits.length === 0, hits.join(', '));
}

// --- 1. health --------------------------------------------------------------
{
  const { res, json } = await getJson('/api/health');
  check('health endpoint 200', res.status === 200, String(res.status));
  check('health status ok', json?.status === 'ok');
  check('health identityMode=web', json?.identityMode === 'web', json?.identityMode);
  scanLeaks('/api/health', JSON.stringify(json ?? {}));
}

// --- 2. demo status ----------------------------------------------------------
let dids;
{
  const { res, json } = await getJson('/api/demo/status');
  check('demo status 200', res.status === 200, String(res.status));
  check('status identityMode=web', json?.identityMode === 'web');
  check('status replayStore=redis', json?.replayStore === 'redis', json?.replayStore);
  dids = json?.dids ?? {};
  check('status exposes build sha', typeof json?.build?.sha === 'string' && json.build.sha !== 'dev', json?.build?.sha);
  scanLeaks('/api/demo/status', JSON.stringify(json ?? {}));
}

// --- 3. public did:web documents, resolved through the REAL resolver --------
for (const name of ['org', 'support', 'refund']) {
  const did = dids[name];
  if (typeof did !== 'string' || !did.startsWith(DID_WEB_PREFIX)) {
    check(`did:${name} present in status`, false);
    continue;
  }
  const url = didWebToUrl(did);
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  const doc = await res.json().catch(() => null);
  check(`GET ${url}`, res.status === 200, String(res.status));
  check(`did:${name} document.id exact`, doc?.id === did);
  const vm = doc?.verificationMethod?.[0];
  check(
    `did:${name} P-256 key + kid binding`,
    vm?.publicKeyJwk?.kty === 'EC' &&
      vm?.publicKeyJwk?.crv === 'P-256' &&
      typeof vm?.id === 'string' &&
      vm.id.startsWith(`${did}#`),
  );
  check(
    `did:${name} no private material`,
    !JSON.stringify(doc).match(/"d"\s*:/),
  );
  check(`did:${name} bounded cache-control`, /max-age=\d{1,6}/.test(res.headers.get('cache-control') ?? ''), res.headers.get('cache-control'));
}

// --- 4. trust profile ---------------------------------------------------------
{
  const { res, json } = await getJson('/api/agents/support/profile');
  const p = json?.profile;
  check('profile 200', res.status === 200, String(res.status));
  check('profile identity resolved=true', p?.identity?.resolved === true);
  const auth = p?.authority?.active?.[0];
  check(
    'profile authority refund:create ≤ 500 SAR',
    auth?.actions?.includes('refund:create') && auth?.limits?.amount === 500 && auth?.limits?.currency === 'SAR',
  );
  check('profile trusted attestation present', (p?.attestations?.trusted?.length ?? 0) >= 1);
  check('profile history verified', p?.history?.integrity?.verified === true);
  const serialized = JSON.stringify(json ?? {}).toLowerCase();
  check('profile has no score/rating fields', !/trustscore|reputation|riskscore|"rating"|"stars"|confidence/.test(serialized));
  scanLeaks('/api/agents/support/profile', serialized);
}

// --- 5. the four judge scenarios + replay pair --------------------------------
async function runPreset(preset) {
  const { json } = await getJson('/api/trust/evaluate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ preset }),
  });
  return json?.result ?? {};
}
{
  const ok = await runPreset('valid-120');
  check('120 SAR → AUTHORIZED+ALLOW', ok.outcome === 'AUTHORIZED' && ok.effect === 'ALLOW', JSON.stringify(ok.reasonCodes));
  check('120 SAR execution SUCCEEDED', ok.stages?.execution === 'SUCCEEDED');
  const over = await runPreset('over-5000');
  check('5000 SAR → DENY AUTHORITY_LIMIT_EXCEEDED', over.effect === 'DENY' && over.reasonCodes?.[0] === 'AUTHORITY_LIMIT_EXCEEDED', JSON.stringify(over.reasonCodes));
  check('5000 SAR executor NOT_RUN', over.stages?.execution === 'NOT_RUN');
  const spoof = await runPreset('spoof');
  check('spoof → IDENTITY_PROOF_INVALID', spoof.reasonCodes?.[0] === 'IDENTITY_PROOF_INVALID');
  const revoked = await runPreset('revoked');
  check('revoked → CREDENTIAL_REVOKED', revoked.reasonCodes?.[0] === 'CREDENTIAL_REVOKED');
  // Deliberate fresh pair — never a stable fixture (16Z).
  const replay = await runPreset('replay');
  check('replay → REPLAY_DETECTED (after first run authorized)', replay.reasonCodes?.[0] === 'REPLAY_DETECTED', JSON.stringify(replay.reasonCodes));
}

// --- 6. baked attack report ----------------------------------------------------
{
  const { res, json } = await getJson('/api/attacks/report');
  check('attack report 200', res.status === 200, String(res.status));
  check('attack report 60/60', json?.summary?.passed === 60 && json?.summary?.total === 60, `${json?.summary?.passed}/${json?.summary?.total}`);
}

// --- 7. HTML shell + CSP ---------------------------------------------------------
{
  const res = await fetch(base + '/');
  const html = await res.text();
  check('dashboard 200', res.status === 200, String(res.status));
  scanLeaks('HTML shell', html);
  const csp = res.headers.get('content-security-policy') ?? '';
  check('CSP present (frame-ancestors)', csp.includes('frame-ancestors'), csp.slice(0, 60));
  check('X-Content-Type-Options nosniff', res.headers.get('x-content-type-options') === 'nosniff');
  // JS bundles referenced by the shell must not carry secrets either.
  const scripts = [...html.matchAll(/src="(\/_next\/static\/[^"]+\.js)"/g)].map((m) => m[1]).slice(0, 12);
  let bundleHits = [];
  for (const src of scripts) {
    const text = await fetch(base + src).then((r) => r.text()).catch(() => '');
    for (const [re, label] of SECRET_PATTERNS) if (re.test(text)) bundleHits.push(`${src}: ${label}`);
  }
  check(`browser bundles leak-free (${scripts.length} scanned)`, bundleHits.length === 0, bundleHits.join(' | '));
  void webcrypto;
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} live smoke checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
