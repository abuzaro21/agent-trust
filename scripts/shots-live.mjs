#!/usr/bin/env node
/**
 * pnpm shots:live — STEP 16AD screenshot capture.
 *
 *   DEMO_PUBLIC_URL=http://localhost:3000 pnpm shots:live
 *
 * Drives the real UI (Chrome via puppeteer-core, 1440x900) through the
 * judge flow and writes docs/screenshots/0N-*.png. No secrets ever render.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import puppeteer from 'puppeteer-core';

const base = (process.env.DEMO_PUBLIC_URL ?? 'http://localhost:3000').replace(/\/$/, '');
const OUT = join(import.meta.dirname, '..', 'docs', 'screenshots');
mkdirSync(OUT, { recursive: true });

const CHROME =
  process.env.CHROME_PATH ??
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: 'new',
  args: ['--window-size=1440,900', '--hide-scrollbars'],
});
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });

async function shot(name, waitSel, fn) {
  if (fn) await fn();
  if (waitSel) await page.waitForSelector(waitSel, { timeout: 25_000 });
  await new Promise((r) => setTimeout(r, 900)); // let fonts/animations settle
  await page.screenshot({ path: join(OUT, name) });
  console.log('wrote', name);
}

// 01 — Trust Profile (live did:web identity visible)
await page.goto(base + '/', { waitUntil: 'networkidle2' });
await shot('01-trust-profile.png', 'main');

// 02 — 120 SAR ALLOW
await shot('02-allow-120.png', null, async () => {
  await page.evaluate(() => {
    const btn = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Valid 120 SAR'));
    btn?.click();
  });
  await page.waitForFunction(
    () => document.body.innerText.includes('AUTHORIZED') && document.body.innerText.includes('SUCCEEDED'),
    { timeout: 30_000 },
  );
});

// 03 — 5000 SAR DENY
await shot('03-deny-5000.png', null, async () => {
  await page.evaluate(() => {
    const btn = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Over-limit 5000 SAR'));
    btn?.click();
  });
  await page.waitForFunction(() => document.body.innerText.includes('AUTHORITY_LIMIT_EXCEEDED'), { timeout: 30_000 });
});

// 04 — Spoofed agent
await shot('04-spoof-denied.png', null, async () => {
  await page.evaluate(() => {
    const btn = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Spoofed Agent'));
    btn?.click();
  });
  await page.waitForFunction(() => document.body.innerText.includes('IDENTITY_PROOF_INVALID'), { timeout: 30_000 });
});

// 05 — Security tests 60/60
await shot('05-security-tests.png', null, async () => {
  await page.goto(base + '/attacks', { waitUntil: 'networkidle2' });
});

await browser.close();
console.log('screenshots complete →', OUT);
