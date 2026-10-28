#!/usr/bin/env node
/**
 * pnpm ui:check — browser-automation checks of the REAL running UI.
 *
 *   UI_URL=http://localhost:3300 pnpm ui:check
 *
 * Covers: responsive layout (no horizontal overflow at 1920/1440/768/390),
 * the decision stage in the first screen, the empty state before any request,
 * the grant limit read from the backend, light-default + dark theme, landmarks
 * and heading order, keyboard operation, ALLOW/DENY rendering, authorization
 * vs execution, the real gateway step order, the side-by-side comparison
 * (derived from the two real responses), the primary and disclosed failure
 * cases, evidence disclosure, mobile "verdict into view" without moving focus,
 * loading / error / retry / validation states, reduced motion, and "no
 * frontend-derived decisions" (exactly one evaluate request per click).
 * Exit code 1 on any failed assertion. Run against a LOCAL or staging
 * instance — it clicks the real demo buttons.
 */
import puppeteer from 'puppeteer-core';

if (!process.env.UI_URL) {
  console.error('UI_URL is required (e.g. UI_URL=http://localhost:3300). It clicks the real demo buttons, so it never defaults to a port that may belong to another service.');
  process.exit(2);
}
const base = process.env.UI_URL.replace(/\/$/, '');
const CHROME = process.env.CHROME_PATH ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const EXPECTED_STEPS = [
  'Identity',
  'Replay claim',
  'Credentials & status',
  'Delegation chain verified',
  'Policy decision',
  'Decision receipt',
  'Execution (simulated)',
  'Outcome receipt',
];

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok) });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === '' ? '' : ` — ${detail}`}`);
}

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--hide-scrollbars'] });

async function open(width, height, { reducedMotion = false, intercept, path = '/', ready = /may refund up to/ } = {}) {
  const page = await browser.newPage();
  await page.setViewport({ width, height, deviceScaleFactor: 1, isMobile: width < 500, hasTouch: width < 800 });
  if (reducedMotion) await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
  page._errors = [];
  page._evaluateRequests = 0;
  page.on('pageerror', (e) => page._errors.push(String(e)));
  page.on('console', (m) => m.type() === 'error' && page._errors.push(m.text()));
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    if (req.method() === 'POST' && req.url().endsWith('/api/trust/evaluate')) page._evaluateRequests += 1;
    if (intercept !== undefined && intercept(req)) return;
    req.continue();
  });
  await page.goto(base + path, { waitUntil: 'networkidle0' });
  await page.waitForFunction((s) => new RegExp(s).test(document.body.innerText), { timeout: 30000 }, ready.source);
  return page;
}

const buttonByText = (page, source) =>
  page.evaluateHandle((src) => [...document.querySelectorAll('button')].find((b) => new RegExp(src, 'i').test(b.innerText.trim())) ?? null, source).then((h) => h.asElement());
const verdictText = (page) => page.evaluate(() => document.getElementById('verdict-anchor')?.innerText ?? '');
const waitVerdict = (page, re) => page.waitForFunction((s) => new RegExp(s).test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 }, re);
const luminance = (page) =>
  page.evaluate(() => {
    const [r, g, b] = getComputedStyle(document.body).backgroundColor.match(/\d+/g).map(Number);
    return (r + g + b) / 3;
  });

// the backend's own profile: what the page must show
const profileJson = await (await fetch(base + '/api/agents/support/profile')).json();
const backendLimit = profileJson.profile.authority.active[0].limits.amount;

// ---------------------------------------------------------------- layout
for (const [w, h] of [[1920, 1080], [1440, 900], [768, 1024], [390, 844]]) {
  const page = await open(w, h);
  const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
  check(`${w}px: no horizontal overflow (scrollWidth ${m.sw} <= ${m.cw})`, m.sw <= m.cw + 1);
  const wide = await page.evaluate(() => [...document.querySelectorAll('main *')].filter((e) => e.getBoundingClientRect().right > document.documentElement.clientWidth + 1).slice(0, 3).map((e) => e.tagName + '.' + e.className));
  check(`${w}px: no element extends past the viewport`, wide.length === 0, wide.join(', '));
  if (w === 1440) {
    const s = await page.evaluate(() => {
      const levels = [...document.querySelectorAll('h1,h2,h3,h4')].map((e) => Number(e.tagName[1]));
      let skip = false;
      for (let i = 1; i < levels.length; i++) if (levels[i] - levels[i - 1] > 1) skip = true;
      const stage = document.getElementById('demo').getBoundingClientRect();
      const asks = [...document.querySelectorAll('.ask button')].map((b) => b.getBoundingClientRect().bottom);
      return {
        h1: document.querySelectorAll('h1').length,
        skip,
        main: document.querySelectorAll('main').length,
        header: document.querySelectorAll('header').length,
        footer: document.querySelectorAll('footer').length,
        nav: document.querySelectorAll('nav[aria-label]').length,
        lang: document.documentElement.lang,
        h1Text: document.querySelector('h1')?.textContent,
        firstFocus: (() => { document.querySelector('.skip-link')?.focus(); return document.activeElement?.className ?? ''; })(),
        unlabeledButtons: [...document.querySelectorAll('button')].filter((b) => b.textContent.trim() === '' && !b.getAttribute('aria-label')).length,
        unlabeledInputs: [...document.querySelectorAll('input')].filter((i) => !i.labels?.length && !i.getAttribute('aria-label')).length,
        simulatedLabel: document.body.innerText.includes('Simulated refund executor'),
        noScoreWords: /trust score of|reputation score of|\bscore: \d/i.test(document.body.innerText),
        stageVisible: stage.top >= 0 && asks.length === 2 && asks.every((b) => b < innerHeight),
        verdictAnchorTop: document.getElementById('verdict-anchor').getBoundingClientRect().top,
        stageText: document.getElementById('demo').innerText,
        grant: document.querySelector('.grant-line .g-main')?.textContent ?? '',
        hasCompare: !!document.querySelector('.compare'),
        hasVerdict: !!document.querySelector('.verdict'),
        navLinks: [...document.querySelectorAll('nav[aria-label="Sections"] a')].length,
        primaryFailures: [...document.querySelectorAll('#failures > div > .grid-auto > article h3')].map((h) => h.textContent),
        moreOpen: document.getElementById('more-cases').open,
        moreCards: [...document.querySelectorAll('#more-cases article h3')].map((h) => h.textContent),
        lifecycle: [...document.querySelectorAll('#lifecycle .lstep h3')].map((h) => h.textContent),
      };
    });
    check('one <h1> "Trust is a grant, not a score.", no skipped heading levels', s.h1 === 1 && !s.skip && s.h1Text === 'Trust is a grant, not a score.', JSON.stringify(s));
    check('landmarks: header, main, footer, labelled nav; lang=en', s.main === 1 && s.header >= 1 && s.footer === 1 && s.nav >= 1 && s.lang === 'en', JSON.stringify(s));
    check('skip link is focusable and first (targets #main)', s.firstFocus.includes('skip-link'), JSON.stringify(s.firstFocus));
    check('every button and input has an accessible name', s.unlabeledButtons === 0 && s.unlabeledInputs === 0, JSON.stringify(s));
    check('executor is labelled as simulated on the page', s.simulatedLabel);
    check('no trust score is rendered', !s.noScoreWords);
    check('minimal navigation (4 links at most)', s.navLinks <= 4, String(s.navLinks));
    check('the decision stage (grant + both request buttons + verdict area) is in the first screen at 1440x900', s.stageVisible && s.verdictAnchorTop < 900, JSON.stringify({ v: s.stageVisible, t: s.verdictAnchorTop }));
    check(`the grant limit comes from the backend profile (${backendLimit})`, s.grant.includes(backendLimit.toLocaleString('en-US')), s.grant);
    check('before any request: no verdict, no comparison, and no outcome words in the stage', !s.hasVerdict && !s.hasCompare && /No decision yet/.test(s.stageText) && !/Authorized|Denied/.test(s.stageText), s.stageText.slice(0, 400));
    check('three primary failure demonstrations (spoof, revoked, replay); the other three sit behind a collapsed disclosure', JSON.stringify(s.primaryFailures) === JSON.stringify(['Spoofed agent', 'Revoked credential', 'Replayed request']) && !s.moreOpen && s.moreCards.length === 3, JSON.stringify(s));
    check('compact Grant / Scope / Revoke explanation', JSON.stringify(s.lifecycle) === JSON.stringify(['Grant', 'Scope', 'Revoke']), JSON.stringify(s.lifecycle));
  }
  check(`${w}px: no console errors on load`, page._errors.length === 0, page._errors.slice(0, 2).join(' | '));
  await page.close();
}

// ----------------------------------------------------------------- theme
{
  const page = await open(1440, 900);
  const light = await luminance(page);
  const isDark0 = await page.evaluate(() => document.documentElement.dataset.theme === 'dark');
  check('light is the default theme', !isDark0 && light > 200, `lum=${light}`);
  await page.click('button.theme-btn');
  const dark = await luminance(page);
  const pressed = await page.$eval('button.theme-btn', (b) => b.getAttribute('aria-pressed'));
  check('theme toggle switches to a dark palette (aria-pressed)', (await page.evaluate(() => document.documentElement.dataset.theme)) === 'dark' && dark < 60 && pressed === 'true', `lum=${dark}`);
  const overflowDark = await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1);
  check('dark theme: no horizontal overflow', overflowDark);
  await page.reload({ waitUntil: 'networkidle0' });
  await page.waitForFunction(() => /may refund up to/.test(document.body.innerText), { timeout: 30000 });
  check('the dark choice is remembered after reload', (await page.evaluate(() => document.documentElement.dataset.theme)) === 'dark' && (await luminance(page)) < 60);
  await page.click('button.theme-btn');
  check('toggling back restores light', (await page.evaluate(() => document.documentElement.dataset.theme)) !== 'dark' && (await luminance(page)) > 200);
  await page.close();
}

// ---------------------------------------------------- keyboard + DENY/ALLOW
{
  const page = await open(1440, 900);
  let landed = false;
  for (let i = 0; i < 40 && !landed; i++) {
    await page.keyboard.press('Tab');
    landed = await page.evaluate(() => /^5,000 sar/i.test(document.activeElement?.innerText?.trim() ?? ''));
  }
  check('keyboard: Tab reaches the 5,000 SAR button', landed);
  const before = page._evaluateRequests;
  await page.keyboard.press('Enter');
  await waitVerdict(page, 'Denied');
  check('keyboard: Enter on 5,000 SAR runs exactly one real evaluate request', page._evaluateRequests === before + 1);
  const deny = await page.evaluate(() => ({
    live: document.getElementById('verdict-anchor')?.innerText ?? '',
    role: document.getElementById('verdict-anchor')?.getAttribute('role'),
    focusKept: /^5,000 sar/i.test(document.activeElement?.innerText?.trim() ?? ''),
    steps: [...document.querySelectorAll('.step .lbl')].slice(0, 8).map((e) => e.textContent.replace(/^\d+/, '').trim()),
    stepValues: [...document.querySelectorAll('.step')].slice(0, 8).map((e) => e.querySelector('.val')?.textContent.trim()),
    meter: !!document.querySelector('.meter'),
    split: [...document.querySelectorAll('.split .row')].map((r) => r.innerText.replace(/\s+/g, ' ')),
    pipelineOpen: document.querySelector('.verdict-more > details')?.open,
    noCompare: !document.querySelector('.compare'),
    hint: document.querySelector('.ask-col')?.innerText.includes('Now run 120 SAR to compare'),
  }));
  check('DENY verdict shows AUTHORITY_LIMIT_EXCEEDED in a polite live region', /AUTHORITY_LIMIT_EXCEEDED/.test(deny.live) && deny.role === 'status');
  check('DENY wording: trusted but not for this action; limit comes from the signed delegation', /trusted — but not for this action/.test(deny.live) && /signed delegation/.test(deny.live));
  check('authorization and execution are separate rows: "Denied by policy" / "Not run — nothing was executed"', /Authorization Denied by policy/.test(deny.split[0]) && /Execution Not run/.test(deny.split[1]) && /Nothing was executed/.test(deny.split[1]), JSON.stringify(deny.split));
  check('DENY shows "4 of 4 verification steps passed" and "Policy: DENY"', /4 of 4 verification steps passed/.test(deny.live) && /Policy: DENY/.test(deny.live));
  check('focus stays on the button after the result arrives', deny.focusKept);
  check('the pipeline is behind a collapsed "How it was decided" disclosure', deny.pipelineOpen === false && /How it was decided/.test(deny.live));
  check('pipeline shows the REAL gateway order (8 steps)', JSON.stringify(deny.steps) === JSON.stringify(EXPECTED_STEPS), JSON.stringify(deny.steps));
  check('DENY: policy step is DENY, execution and outcome receipt did not run', deny.stepValues[4] === 'DENY' && deny.stepValues[6] === '—' && deny.stepValues[7] === '—', JSON.stringify(deny.stepValues));
  check('DENY: first four verification steps are PASS', deny.stepValues.slice(0, 4).every((v) => v === 'PASS'), JSON.stringify(deny.stepValues));
  check('amount-vs-limit meter is shown for the limit denial', deny.meter);
  check('after ONE request there is no comparison yet, only a hint to run the other amount', deny.noCompare && deny.hint);

  await page.evaluate(() => document.querySelector('.verdict-more > details > summary').click());
  const opened = await page.evaluate(() => document.querySelectorAll('.verdict-more .pgroup').length === 3 && document.querySelector('.verdict-more .step').getBoundingClientRect().height > 0);
  check('evidence disclosure: opening "How it was decided" reveals the three pipeline groups', opened);
  await page.evaluate(() => document.querySelectorAll('.verdict-more > details')[1].querySelector('summary').click());
  const ev = await page.evaluate(() => document.querySelectorAll('.verdict-more > details')[1].innerText);
  check('evidence disclosure: technical evidence lists the receipt id and hash', /Decision receipt/.test(ev) && /rcpt_dec_/.test(ev) && /sha256:[0-9a-f]{16}/.test(ev), ev.slice(0, 200));

  await (await buttonByText(page, '^120 sar')).click();
  await waitVerdict(page, 'Authorized');
  const allow = await page.evaluate(() => ({
    live: document.getElementById('verdict-anchor')?.innerText ?? '',
    values: [...document.querySelectorAll('.step')].slice(0, 8).map((e) => e.querySelector('.val')?.textContent.trim()),
    split: [...document.querySelectorAll('.split .row')].map((r) => r.innerText.replace(/\s+/g, ' ')),
    compare: document.querySelector('.compare')?.innerText ?? '',
    compareTitle: document.getElementById('compare-title')?.textContent ?? '',
  }));
  check('ALLOW verdict: Authorized + WITHIN_AUTHORITY', /Authorized/.test(allow.live) && /WITHIN_AUTHORITY/.test(allow.live));
  check('ALLOW: authorization "Allowed by policy" is separate from execution "Succeeded (simulated)"', /Authorization Allowed by policy/.test(allow.split[0]) && /Execution Succeeded \(simulated\)/.test(allow.split[1]), JSON.stringify(allow.split));
  check('ALLOW: execution is labelled simulated and the outcome receipt is recorded', allow.values[6] === 'SUCCEEDED (simulated)' && allow.values[7] === 'RECORDED', JSON.stringify(allow.values));
  check('comparison appears after BOTH real responses and holds both results', /120 SAR/.test(allow.compare) && /5,000 SAR/.test(allow.compare) && /AUTHORITY_LIMIT_EXCEEDED/.test(allow.compare) && /WITHIN_AUTHORITY/.test(allow.compare) && /Authorized/.test(allow.compare) && /Denied/.test(allow.compare), allow.compare);
  check('comparison headline states "different decision" because the two responses differed', /different decision/.test(allow.compareTitle), allow.compareTitle);

  // the three primary failure demonstrations
  const cardBtn = (id) => page.evaluateHandle((i) => document.querySelector(`#f-${i}`)?.closest('article')?.querySelector('button') ?? null, id).then((h) => h.asElement());
  const cardText = (id) => page.evaluate((i) => document.querySelector(`#f-${i}`).closest('article').innerText, id);
  await (await cardBtn('spoof')).click();
  await page.waitForFunction(() => /IDENTITY_PROOF_INVALID/.test(document.querySelector('#f-spoof')?.closest('article')?.innerText ?? ''), { timeout: 30000 });
  const spoof = await cardText('spoof');
  check('spoofed identity: Denied, IDENTITY_PROOF_INVALID, "not authenticated", no limit wording', /Denied/.test(spoof) && /not authenticated/i.test(spoof) && !/limit|exceed/i.test(spoof.replace(/Spoofed agent[\s\S]*?Run this case/i, '')), spoof.slice(0, 300));
  const mainStill = await verdictText(page);
  check('running a failure card does not overwrite the main verdict', /Authorized/.test(mainStill));
  await (await cardBtn('revoked')).click();
  await page.waitForFunction(() => /CREDENTIAL_REVOKED/.test(document.querySelector('#f-revoked')?.closest('article')?.innerText ?? ''), { timeout: 30000 });
  const revoked = await cardText('revoked');
  check('revocation: Denied with CREDENTIAL_REVOKED and a revocation explanation', /Denied/.test(revoked) && /CREDENTIAL_REVOKED/.test(revoked) && /revoked/i.test(revoked));
  await (await cardBtn('replay')).click();
  await page.waitForFunction(() => /REPLAY_DETECTED/.test(document.querySelector('#f-replay')?.closest('article')?.innerText ?? ''), { timeout: 30000 });
  const replay = await page.evaluate(() => document.querySelector('#f-replay').closest('article').textContent);
  check('replay: first send AUTHORIZED vs identical re-send DENIED (REPLAY_DETECTED); receipts attributed to the first send', /First send: AUTHORIZED/.test(replay) && /identical re-send: DENIED/.test(replay) && /Two sends/.test(replay), replay.slice(0, 200));
  check('failure cards keep per-request evidence (receipts disclosure)', /Technical evidence/.test(await cardText('spoof')));

  // disclosed failure cases
  await page.evaluate(() => document.querySelector('#more-cases > summary').click());
  await (await cardBtn('quarantine')).click();
  await page.waitForFunction(() => /Denied/.test(document.querySelector('#f-quarantine')?.closest('article')?.innerText ?? ''), { timeout: 30000 });
  const quarantine = await cardText('quarantine');
  check('a disclosed failure case (quarantine) runs for real and is denied with AGENT_QUARANTINED', /Denied/.test(quarantine) && /AGENT_QUARANTINED/.test(quarantine), quarantine.slice(0, 200));

  // evidence is preserved behind disclosures
  const closedByDefault = await page.evaluate(() => ['audit-acc', 'attestations-acc', 'runtime-acc'].every((id) => !document.getElementById(id).open));
  const evi = await page.evaluate(async () => {
    const report = document.getElementById('rep-title')?.closest('section')?.innerText ?? '';
    document.querySelector('#audit-acc > summary').click();
    document.querySelector('#attestations-acc > summary').click();
    document.querySelector('#runtime-acc > summary').click();
    await new Promise((r) => setTimeout(r, 200));
    return { report, audit: document.getElementById('audit-acc').innerText, att: document.getElementById('attestations-acc').innerText, runtime: document.getElementById('runtime-acc').innerText };
  });
  check('audit history, attestations and runtime facts are collapsed by default', closedByDefault);
  check('the security-suite report stays visible (e.g. "60 / 60 scenarios passed") and says it is build-time', /\d+ \/ \d+\s+scenarios passed/.test(evi.report) && /did\s+not\s+run when this page loaded/i.test(evi.report), evi.report.slice(0, 200));
  check('audit history: chain intact, signed checkpoint, honest log note, receipts of this session', /chain intact/.test(evi.audit) && /checkpoint signature valid/.test(evi.audit) && /not\s+anchored outside the server/.test(evi.audit) && /refund:create/.test(evi.audit), evi.audit.slice(0, 300));
  check('attestations: one accepted, one rejected (untrusted issuer), "never authority"', /accepted/.test(evi.att) && /UNTRUSTED_ISSUER/.test(evi.att) && /never grant permission/.test(evi.att), evi.att.slice(0, 300));
  check('runtime facts come from the backend status and standards are listed with no certification claim', /Replay store/.test(evi.runtime) && /DID Core/.test(evi.runtime) && /no independent conformance certification/.test(evi.runtime), evi.runtime.slice(0, 200));
  check('no console errors during the flow', page._errors.length === 0, page._errors.slice(0, 2).join(' | '));
  await page.close();
}

// ----- the comparison is DERIVED from the responses (never a hard-coded ALLOW/DENY)
{
  const mock = (amount, n) => ({
    result: {
      taskId: `mock_${n}`,
      outcome: 'DENIED',
      effect: 'DENY',
      reasonCodes: ['POLICY_EVALUATION_ERROR'],
      stages: { identity: 'PASS', replay: 'PASS', credential: 'PASS', authority: 'PASS', policy: 'FAIL', audit: 'NOT_RUN', execution: 'NOT_RUN' },
    },
    runReceipts: [{ sequence: n, recordedAt: '2026-09-15T12:00:00Z', actorDid: 'did:web:x', action: 'refund:create', resource: 'order:1', amount, currency: 'SAR', effect: 'DENY', reasonCodes: [], eventHash: 'ab'.repeat(32), receiptId: `r${n}` }],
  });
  let n = 0;
  const page = await open(1440, 900, {
    intercept: (req) => {
      if (req.method() === 'POST' && req.url().endsWith('/api/trust/evaluate')) {
        n += 1;
        const body = JSON.parse(req.postData() ?? '{}');
        req.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(mock(body.preset === 'valid-120' ? 120 : 5000, n)) });
        return true;
      }
      return false;
    },
  });
  await (await buttonByText(page, '^run both')).click();
  await page.waitForFunction(() => document.querySelector('.compare'), { timeout: 15000 });
  const t = await page.evaluate(() => ({ title: document.getElementById('compare-title')?.textContent ?? '', cmp: document.querySelector('.compare').innerText }));
  check('comparison follows the responses: if both come back denied it says so (no "different decision", no invented "Authorized")', /same outcome/.test(t.title) && !/different decision/.test(t.title) && !/Authorized/.test(t.cmp) && (t.cmp.match(/Denied/g) ?? []).length === 2 && /POLICY_EVALUATION_ERROR/.test(t.cmp), JSON.stringify(t));
  await page.close();
}

// ------------------------------------------- mobile: verdict into view, focus kept
{
  const page = await open(390, 844);
  await (await buttonByText(page, '^120 sar')).click();
  await waitVerdict(page, 'Authorized');
  await new Promise((r) => setTimeout(r, 900)); // let the smooth scroll settle
  const m = await page.evaluate(() => {
    const r = document.getElementById('verdict-anchor').getBoundingClientRect();
    return { top: r.top, inView: r.top >= -2 && r.top < innerHeight * 0.4, focus: /^120 sar/i.test(document.activeElement?.innerText?.trim() ?? ''), scrollY };
  });
  check('mobile: after an evaluation the verdict is scrolled into view', m.inView && m.scrollY > 0, JSON.stringify(m));
  check('mobile: focus stays on the pressed button (keyboard users keep their place)', m.focus, JSON.stringify(m));
  await (await buttonByText(page, '^5,000 sar')).click();
  await waitVerdict(page, 'Denied');
  const g = await page.evaluate(() => [...document.querySelectorAll('.verdict-more .pgroup')].map((d) => ({ title: d.querySelector('.gt')?.textContent, open: d.open })));
  check('mobile: the failing group is open, fully-passing groups are collapsed', g.length === 3 && g[1].open === true && g[0].open === false, JSON.stringify(g));
  const sum = await page.evaluate(() => document.querySelector('.verdict-more .pgroup .gs')?.textContent ?? '');
  check('mobile: collapsed verification group still states "4 of 4 passed"', /4 of 4 passed/.test(sum), sum);
  const cmp = await page.evaluate(() => ({ present: !!document.querySelector('.compare'), sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
  check('mobile: comparison renders without horizontal overflow', cmp.present && cmp.sw <= cmp.cw + 1, JSON.stringify(cmp));
  await page.close();
}

// --------------------------------------------- loading / error / validation
{
  const page = await open(1440, 900, {
    intercept: (req) => {
      if (req.method() === 'POST' && req.url().endsWith('/api/trust/evaluate')) {
        setTimeout(() => req.continue(), 900);
        return true;
      }
      return false;
    },
  });
  const btn = await buttonByText(page, '^120 sar');
  await btn.click();
  await new Promise((r) => setTimeout(r, 250));
  const busy = await page.evaluate(() => {
    const bs = [...document.querySelectorAll('.ask button')];
    return { ariaBusy: bs.some((b) => b.getAttribute('aria-busy') === 'true'), allDisabled: bs.every((b) => b.getAttribute('aria-disabled') === 'true' && !b.disabled), spinner: !!document.querySelector('.spinner') };
  });
  check('loading state: aria-busy + spinner; demo buttons are aria-disabled (still focusable) while a request runs', busy.ariaBusy && busy.allDisabled && busy.spinner, JSON.stringify(busy));
  await waitVerdict(page, 'Authorized');
  const re = await page.evaluate(() => [...document.querySelectorAll('.ask button')].every((b) => b.getAttribute('aria-disabled') !== 'true'));
  check('buttons re-enable after the result', re);
  await page.close();
}
{
  let posts = 0;
  const page = await open(1440, 900, {
    intercept: (req) => {
      if (req.method() === 'POST' && req.url().endsWith('/api/trust/evaluate')) {
        posts += 1;
        if (posts === 1) {
          req.respond({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'GATEWAY_UNAVAILABLE', detail: 'simulated outage' }) });
          return true;
        }
      }
      return false;
    },
  });
  await (await buttonByText(page, '^120 sar')).click();
  await page.waitForFunction(() => document.querySelector('#verdict-anchor [role="alert"]'), { timeout: 15000 });
  const e = await page.evaluate(() => document.querySelector('#verdict-anchor [role="alert"]').innerText);
  check('error state: role=alert with the machine reason and a Retry action; no verdict is shown', /could not be completed/i.test(e) && /GATEWAY_UNAVAILABLE/.test(e) && /Retry/.test(e) && (await page.evaluate(() => !document.querySelector('.verdict'))), e);
  await (await buttonByText(page, '^retry$')).click();
  await waitVerdict(page, 'Authorized');
  check('Retry really re-sends the request (second POST) and recovers to the real result', posts === 2 && page._evaluateRequests === 2, `posts=${posts}`);
  await page.close();
}
{
  let posts = 0;
  const page = await open(1440, 900, {
    intercept: (req) => {
      if (req.method() === 'POST' && req.url().endsWith('/api/trust/evaluate')) {
        posts += 1;
        if (posts === 2) {
          req.respond({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'GATEWAY_UNAVAILABLE', detail: 'simulated outage on the second leg' }) });
          return true;
        }
      }
      return false;
    },
  });
  await (await buttonByText(page, '^run both')).click();
  await page.waitForFunction(() => document.querySelector('#verdict-anchor [role="alert"]'), { timeout: 30000 });
  check('"Run both": no comparison is shown while one leg has failed', await page.evaluate(() => !document.querySelector('.compare')));
  await (await buttonByText(page, '^retry$')).click();
  await waitVerdict(page, 'Denied');
  check('"Run both": a failed second leg is retried alone (3 POSTs total, the successful 120 SAR leg is not repeated)', posts === 3, `posts=${posts}`);
  check('"Run both": the comparison appears once both legs have succeeded', await page.evaluate(() => !!document.querySelector('.compare')));
  await page.close();
}
{
  const page = await open(1440, 900);
  await page.evaluate(() => { document.getElementById('custom-amount')?.setAttribute('open', ''); });
  await page.$eval('#amount', (el) => { el.value = ''; });
  await page.type('#amount', 'abc');
  const before = page._evaluateRequests;
  await (await buttonByText(page, '^evaluate this amount$')).click();
  await new Promise((r) => setTimeout(r, 300));
  const v = await page.evaluate(() => ({ err: document.getElementById('amount-err')?.innerText ?? '', invalid: document.getElementById('amount')?.getAttribute('aria-invalid') }));
  check('validation: "abc" is rejected inline (aria-invalid) and sends no request', /positive number/.test(v.err) && v.invalid === 'true' && page._evaluateRequests === before, JSON.stringify(v));
  await page.$eval('#amount', (el) => { el.value = ''; });
  await page.type('#amount', '250');
  await (await buttonByText(page, '^evaluate this amount$')).click();
  await waitVerdict(page, 'Authorized');
  check('a valid custom amount (250) is evaluated by the backend and authorized', true);
  await page.close();
}

// ---------------------------------------------------------- reduced motion
{
  const page = await open(1440, 900, { reducedMotion: true });
  await (await buttonByText(page, '^120 sar')).click();
  await waitVerdict(page, 'Authorized');
  const d = await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector('.verdict')).animationDuration));
  check('prefers-reduced-motion: the verdict animation is effectively disabled', d <= 0.001, String(d));
  await page.close();
}

// ----------------------------------------------------------- /attacks page
{
  const page = await open(390, 844, { path: '/attacks', ready: /scenarios passed/ });
  const a = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, theme: !!document.querySelector('button.theme-btn') }));
  check('/attacks: no horizontal overflow at 390px and the theme toggle is present', a.sw <= a.cw + 1 && a.theme, JSON.stringify(a));
  await page.close();
}

await browser.close();
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} UI checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
