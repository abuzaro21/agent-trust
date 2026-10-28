#!/usr/bin/env node
/**
 * pnpm shots:live — screenshot capture of the REAL running UI.
 *
 *   UI_URL=http://localhost:3300 pnpm shots:live
 *
 * Drives Chrome (puppeteer-core) through the judge flow at 1440x900 (plus a
 * 390x844 mobile pair) and writes docs/screenshots/*.png. Every state is
 * produced by clicking the real buttons; nothing is composited or edited.
 * Run it against a LOCAL or freshly deployed instance of the release you
 * are documenting — screenshots must match the deployed commit.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import puppeteer from 'puppeteer-core';

if (!process.env.UI_URL) {
  console.error('UI_URL is required (e.g. UI_URL=http://localhost:3300).');
  process.exit(2);
}
const base = process.env.UI_URL.replace(/\/$/, '');
const OUT = join(import.meta.dirname, '..', 'docs', 'screenshots');
mkdirSync(OUT, { recursive: true });
const CHROME = process.env.CHROME_PATH ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe';

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--hide-scrollbars'] });

async function session(width, height, fn) {
  const page = await browser.newPage();
  await page.setViewport({ width, height, deviceScaleFactor: 1, isMobile: width < 500, hasTouch: width < 500 });
  await page.goto(base + '/', { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => document.body.innerText.includes('did:web'), { timeout: 30000 });
  await fn(page);
  await page.close();
}
const settle = () => new Promise((r) => setTimeout(r, 900));
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

await session(1440, 900, async (page) => {
  await shoot(page, '01-hero.png');
  await scrollTo(page, '#identity');
  await shoot(page, '02-identity-and-authority.png');
  await click(page, '^120 sar');
  await waitFor(page, 'Authorized');
  await scrollTo(page, '#demo-title');
  await shoot(page, '03-allow-120.png');
  await click(page, '^5,000 sar');
  await waitFor(page, 'Denied');
  await scrollTo(page, '#demo-title');
  await shoot(page, '04-deny-5000.png');
  await scrollTo(page, '.pipeline');
  await shoot(page, '05-pipeline.png');
  await scrollTo(page, '#failures');
  const spoof = await page.evaluateHandle(() => document.querySelector('#f-spoof')?.closest('article')?.querySelector('button') ?? null);
  await spoof.asElement().click();
  await page.waitForFunction(() => /IDENTITY_PROOF_INVALID/.test(document.querySelector('#f-spoof')?.closest('article')?.innerText ?? ''), { timeout: 30000 });
  await scrollTo(page, '#failures');
  await shoot(page, '06-spoof-denied.png');
  await scrollTo(page, '#lifecycle');
  await shoot(page, '07-grant-scope-revoke.png');
  await scrollTo(page, '#evidence');
  await shoot(page, '08-evidence-and-audit.png');
});

await session(390, 844, async (page) => {
  await click(page, '^5,000 sar');
  await waitFor(page, 'Denied');
  await shoot(page, '09-mobile-deny-5000.png');
});

const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900 });
await page.goto(base + '/attacks', { waitUntil: 'networkidle0' });
await page.waitForFunction(() => /scenarios passed/.test(document.body.innerText), { timeout: 30000 });
await shoot(page, '10-security-tests.png');
await browser.close();
console.log('screenshots complete →', OUT);
