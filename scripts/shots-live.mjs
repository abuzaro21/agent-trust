#!/usr/bin/env node
/**
 * pnpm shots:live — screenshot capture of the REAL running UI.
 *
 *   UI_URL=http://localhost:3300 pnpm shots:live
 *
 * Drives Chrome (puppeteer-core) through the judge flow at 1440x900 (light and
 * dark) plus 390x844 mobile (light and dark) and writes docs/screenshots/*.png.
 * Every state is produced by clicking the real buttons against the real
 * backend; nothing is composited or edited. Run it against a LOCAL or freshly
 * deployed instance of the release you are documenting — screenshots must
 * match the deployed commit.
 */
import { mkdirSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import puppeteer from 'puppeteer-core';

if (!process.env.UI_URL) {
  console.error('UI_URL is required (e.g. UI_URL=http://localhost:3300).');
  process.exit(2);
}
const base = process.env.UI_URL.replace(/\/$/, '');
const OUT = join(import.meta.dirname, '..', 'docs', 'screenshots');
mkdirSync(OUT, { recursive: true });
for (const f of readdirSync(OUT)) if (f.endsWith('.png')) rmSync(join(OUT, f)); // regenerate the whole set so no stale image survives
const CHROME = process.env.CHROME_PATH ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe';

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--hide-scrollbars'] });

async function session(width, height, theme, fn) {
  const page = await browser.newPage();
  await page.setViewport({ width, height, deviceScaleFactor: 1, isMobile: width < 500, hasTouch: width < 500 });
  await page.evaluateOnNewDocument((t) => { try { localStorage.setItem('at-theme', t); } catch {} }, theme);
  await page.goto(base + '/', { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => /may refund up to/.test(document.body.innerText), { timeout: 30000 });
  await fn(page);
  await page.close();
}
const settle = (ms = 900) => new Promise((r) => setTimeout(r, ms));
async function click(page, source) {
  const h = await page.evaluateHandle((s) => [...document.querySelectorAll('button')].find((b) => new RegExp(s, 'i').test(b.innerText.trim())) ?? null, source);
  await h.asElement().click();
}
const waitFor = (page, re) => page.waitForFunction((s) => new RegExp(s).test(document.getElementById('verdict-anchor')?.innerText ?? ''), { timeout: 30000 }, re);
const scrollTo = (page, sel, block = 'start') => page.evaluate((s, b) => { document.querySelector(s)?.scrollIntoView({ block: b, behavior: 'instant' }); }, sel, block);
async function shoot(page, name) {
  await settle();
  await page.screenshot({ path: join(OUT, name) });
  console.log('wrote', name);
}
const cardRun = async (page, id, re) => {
  const b = await page.evaluateHandle((i) => document.querySelector(`#f-${i}`)?.closest('article')?.querySelector('button') ?? null, id);
  await b.asElement().click();
  await page.waitForFunction((i, s) => new RegExp(s).test(document.querySelector(`#f-${i}`)?.closest('article')?.innerText ?? ''), { timeout: 30000 }, id, re);
};

await session(1440, 900, 'light', async (page) => {
  await shoot(page, '01-hero-light.png');
  await click(page, '^120 sar');
  await waitFor(page, 'Authorized');
  await shoot(page, '02-allow-120-light.png');
  await click(page, '^5,000 sar');
  await waitFor(page, 'Denied');
  await shoot(page, '03-deny-5000-light.png');
  await scrollTo(page, '.compare-wrap', 'center');
  await shoot(page, '04-comparison-light.png');
  await scrollTo(page, '#demo-title');
  await page.evaluate(() => document.querySelector('.verdict-more > details > summary')?.click());
  await scrollTo(page, '.verdict-more', 'center');
  await shoot(page, '05-pipeline-light.png');
  await scrollTo(page, '#failures');
  await cardRun(page, 'spoof', 'IDENTITY_PROOF_INVALID');
  await cardRun(page, 'revoked', 'CREDENTIAL_REVOKED');
  await cardRun(page, 'replay', 'REPLAY_DETECTED');
  await scrollTo(page, '#failures');
  await shoot(page, '06-failure-cases-light.png');
  await scrollTo(page, '#lifecycle');
  await shoot(page, '07-grant-scope-revoke-light.png');
  await page.evaluate(() => document.querySelector('#audit-acc > summary')?.click());
  await scrollTo(page, '#evidence');
  await shoot(page, '08-evidence-light.png');
});

await session(1440, 900, 'dark', async (page) => {
  await shoot(page, '09-hero-dark.png');
  await click(page, '^run both');
  await page.waitForFunction(() => document.querySelector('.compare'), { timeout: 30000 });
  await scrollTo(page, '#demo', 'start');
  await page.evaluate(() => window.scrollBy(0, 150));
  await shoot(page, '10-comparison-dark.png');
});

await session(390, 844, 'light', async (page) => {
  await shoot(page, '11-mobile-hero-light.png');
  await click(page, '^120 sar');
  await waitFor(page, 'Authorized');
  await shoot(page, '12-mobile-allow-light.png'); // the page scrolled the verdict into view by itself
  await click(page, '^5,000 sar');
  await waitFor(page, 'Denied');
  await shoot(page, '13-mobile-deny-light.png');
  await scrollTo(page, '.compare-wrap');
  await shoot(page, '14-mobile-comparison-light.png');
});

await session(390, 844, 'dark', async (page) => {
  await click(page, '^5,000 sar');
  await waitFor(page, 'Denied');
  await shoot(page, '15-mobile-deny-dark.png');
});

await session(768, 1024, 'light', async (page) => {
  await click(page, '^run both');
  await page.waitForFunction(() => document.querySelector('.compare'), { timeout: 30000 });
  await scrollTo(page, '#demo');
  await shoot(page, '16-tablet-comparison-light.png');
});

const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900 });
await page.goto(base + '/attacks', { waitUntil: 'networkidle0' });
await page.waitForFunction(() => /scenarios passed/.test(document.body.innerText), { timeout: 30000 });
await shoot(page, '17-security-tests.png');
await browser.close();
console.log('screenshots complete →', OUT);
