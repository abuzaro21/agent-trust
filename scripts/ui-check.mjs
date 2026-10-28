#!/usr/bin/env node
/**
 * pnpm ui:check — browser-automation checks of the REAL running UI.
 *
 *   UI_URL=http://localhost:3300 pnpm ui:check
 *
 * Covers: responsive layout (no horizontal overflow at 1920/1440/768/390),
 * landmarks and heading order, keyboard operation, ALLOW/DENY rendering,
 * the real gateway step order, reason-specific wording, loading / error /
 * validation states, reduced motion, and "no frontend-derived decisions"
 * (the page makes exactly one evaluate request per click and never decides).
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

async function open(width, height, { reducedMotion = false, intercept } = {}) {
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
  await page.goto(base + '/', { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => document.body.innerText.includes('did:web'), { timeout: 30000 });
  return page;
}

const buttonByText = (page, source) =>
  page.evaluateHandle((src) => [...document.querySelectorAll('button')].find((b) => new RegExp(src, 'i').test(b.innerText.trim())) ?? null, source).then((h) => h.asElement());

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
      return {
        h1: document.querySelectorAll('h1').length,
        skip,
        main: document.querySelectorAll('main').length,
        header: document.querySelectorAll('header').length,
        footer: document.querySelectorAll('footer').length,
        nav: document.querySelectorAll('nav[aria-label]').length,
        lang: document.documentElement.lang,
        title: document.title,
        firstFocus: (() => { document.querySelector('.skip-link')?.focus(); return document.activeElement?.className ?? ''; })(),
        unlabeledButtons: [...document.querySelectorAll('button')].filter((b) => b.textContent.trim() === '' && !b.getAttribute('aria-label')).length,
        unlabeledInputs: [...document.querySelectorAll('input')].filter((i) => !i.labels?.length && !i.getAttribute('aria-label')).length,
        simulatedLabel: document.body.innerText.includes('Simulated refund executor'),
        noScoreWords: /trust score of|reputation score of|\bscore: \d/i.test(document.body.innerText),
      };
    });
    check('one <h1>, no skipped heading levels', s.h1 === 1 && !s.skip, JSON.stringify(s));
    check('landmarks: header, main, footer, labelled nav; lang=en', s.main === 1 && s.header >= 1 && s.footer === 1 && s.nav >= 1 && s.lang === 'en', JSON.stringify(s));
    check('skip link is focusable and first (targets #main)', s.firstFocus.includes('skip-link'), JSON.stringify(s.firstFocus));
    check('every button and input has an accessible name', s.unlabeledButtons === 0 && s.unlabeledInputs === 0, JSON.stringify(s));
    check('executor is labelled as simulated on the page', s.simulatedLabel, JSON.stringify(s));
    check('no trust score is rendered', !s.noScoreWords);
  }
  check(`${w}px: no console errors on load`, page._errors.length === 0, page._errors.slice(0, 2).join(' | '));
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
  await page.waitForFunction(() => /Denied/.test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 });
  check('keyboard: Enter on 5,000 SAR runs exactly one real evaluate request', page._evaluateRequests === before + 1);
  const deny = await page.evaluate(() => ({
    live: document.getElementById('verdict-anchor')?.innerText ?? '',
    role: document.getElementById('verdict-anchor')?.getAttribute('role'),
    focusKept: /^5,000 sar/i.test(document.activeElement?.innerText?.trim() ?? ''),
    steps: [...document.querySelectorAll('#demo-title ~ * .step .lbl, .step .lbl')].slice(0, 8).map((e) => e.textContent.replace(/^\d+/, '').trim()),
    stepValues: [...document.querySelectorAll('.step')].slice(0, 8).map((e) => e.querySelector('.val')?.textContent.trim()),
    meter: !!document.querySelector('.meter'),
  }));
  check('DENY verdict shows AUTHORITY_LIMIT_EXCEEDED in a polite live region', /AUTHORITY_LIMIT_EXCEEDED/.test(deny.live) && deny.role === 'status');
  check('DENY wording: trusted but not for this action; limit comes from the signed delegation', /trusted — but not for this action/.test(deny.live) && /signed delegation/.test(deny.live));
  check('focus stays on the button after the result arrives', deny.focusKept);
  check('pipeline shows the REAL gateway order (8 steps)', JSON.stringify(deny.steps) === JSON.stringify(EXPECTED_STEPS), JSON.stringify(deny.steps));
  check('DENY: policy step is DENY, execution and outcome receipt did not run', deny.stepValues[4] === 'DENY' && deny.stepValues[6] === '—' && deny.stepValues[7] === '—', JSON.stringify(deny.stepValues));
  check('DENY: first four verification steps are PASS', deny.stepValues.slice(0, 4).every((v) => v === 'PASS'), JSON.stringify(deny.stepValues));
  check('amount-vs-limit meter is shown for the limit denial', deny.meter);

  const allowBtn = await buttonByText(page, '^120 sar');
  await allowBtn.click();
  await page.waitForFunction(() => /Authorized/.test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 });
  const allow = await page.evaluate(() => ({
    live: document.getElementById('verdict-anchor')?.innerText ?? '',
    values: [...document.querySelectorAll('.step')].slice(0, 8).map((e) => e.querySelector('.val')?.textContent.trim()),
    compare: document.querySelector('.compare')?.innerText ?? '',
  }));
  check('ALLOW verdict: Authorized + WITHIN_AUTHORITY', /Authorized/.test(allow.live) && /WITHIN_AUTHORITY/.test(allow.live));
  check('ALLOW: execution is labelled simulated and the outcome receipt is recorded', allow.values[6] === 'SUCCEEDED (simulated)' && allow.values[7] === 'RECORDED', JSON.stringify(allow.values));
  check('side-by-side comparison holds both of THIS browser\'s runs', /120 SAR/.test(allow.compare) && /5,000 SAR/.test(allow.compare) && /AUTHORITY_LIMIT_EXCEEDED/.test(allow.compare) && /WITHIN_AUTHORITY/.test(allow.compare), allow.compare);

  // reason-specific wording: a spoof is not a limit problem
  const spoofBtn = await page.evaluateHandle(() => document.querySelector('#f-spoof')?.closest('article')?.querySelector('button') ?? null);
  await spoofBtn.asElement().click();
  await page.waitForFunction(() => /IDENTITY_PROOF_INVALID/.test(document.querySelector('#f-spoof')?.closest('article')?.innerText ?? ''), { timeout: 30000 });
  const spoof = await page.evaluate(() => document.querySelector('#f-spoof').closest('article').innerText);
  check('spoof card: IDENTITY_PROOF_INVALID, "not authenticated", no limit wording', /not authenticated/i.test(spoof) && !/limit|exceed/i.test(spoof.replace(/Spoofed agent[\s\S]*?Run this case/i, '')), spoof.slice(0, 300));
  const mainStill = await page.evaluate(() => document.getElementById('verdict-anchor')?.innerText ?? '');
  check('running a failure card does not overwrite the main verdict', /Authorized/.test(mainStill));
  const evidence = await page.evaluate(() => document.querySelector('#f-spoof').closest('article').innerText);
  check('failure cards keep per-request evidence (receipts disclosure)', /Evidence & receipts/.test(evidence));
  check('no console errors during the flow', page._errors.length === 0, page._errors.slice(0, 2).join(' | '));
  await page.close();
}

// ------------------------------------------------------ mobile stepper
{
  const page = await open(390, 844);
  await (await buttonByText(page, '^5,000 sar')).click();
  await page.waitForFunction(() => /Denied/.test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 });
  const g = await page.evaluate(() => [...document.querySelectorAll('#demo .pgroup')].map((d) => ({ title: d.querySelector('.gt')?.textContent, open: d.open, failed: d.dataset.failed })));
  check('mobile: the failing group is open, fully-passing groups are collapsed', g.length === 3 && g[1].open === true && g[0].open === false, JSON.stringify(g));
  const sum = await page.evaluate(() => document.querySelector('#demo .pgroup .gs')?.textContent ?? '');
  check('mobile: collapsed verification group still states "4 of 4 passed"', /4 of 4 passed/.test(sum), sum);
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
  await page.waitForFunction(() => /Authorized/.test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 });
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
  check('error state: role=alert with the machine reason and a Retry action', /could not be completed/i.test(e) && /GATEWAY_UNAVAILABLE/.test(e) && /Retry/.test(e), e);
  await (await buttonByText(page, '^retry$')).click();
  await page.waitForFunction(() => /Authorized/.test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 });
  check('Retry really re-sends the request (second POST) and recovers to the real result', posts === 2 && page._evaluateRequests === 2, `posts=${posts}`);
  await page.close();
}
{
  const page = await open(1440, 900);
  await page.evaluate(() => { document.querySelector('details.disclose')?.setAttribute('open', ''); });
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
  await page.waitForFunction(() => /Authorized/.test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 });
  check('a valid custom amount (250) is evaluated by the backend and authorized', true);
  await page.close();
}

// ---------------------------------------------------------- reduced motion
{
  const page = await open(1440, 900, { reducedMotion: true });
  await (await buttonByText(page, '^120 sar')).click();
  await page.waitForFunction(() => /Authorized/.test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 });
  const d = await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector('.verdict')).animationDuration));
  check('prefers-reduced-motion: the verdict animation is effectively disabled', d <= 0.001, String(d));
  await page.close();
}

await browser.close();
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} UI checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
