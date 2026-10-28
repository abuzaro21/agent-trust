#!/usr/bin/env node
/**
 * pnpm ui:shots — capture the REAL running UI at four viewports and report
 * horizontal overflow. Never fabricates states: it clicks the real buttons.
 *
 *   UI_URL=http://localhost:3300 UI_OUT=docs/screenshots/after UI_PREFIX=after pnpm ui:shots
 *
 * Steps per viewport: idle page -> run 120 SAR (ALLOW) -> run 5000 SAR (DENY).
 * Writes <out>/<prefix>-<width>-<state>.png and prints overflow metrics.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import puppeteer from 'puppeteer-core';

if (!process.env.UI_URL) {
  console.error('UI_URL is required (e.g. UI_URL=http://localhost:3300). It clicks the real demo buttons, so it never defaults to a port that may belong to another service.');
  process.exit(2);
}
const base = process.env.UI_URL.replace(/\/$/, '');
const out = process.env.UI_OUT ?? 'ui-shots';
const prefix = process.env.UI_PREFIX ?? 'shot';
const CHROME = process.env.CHROME_PATH ?? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const VIEWPORTS = [
  { w: 1440, h: 900 },
  { w: 1920, h: 1080 },
  { w: 768, h: 1024 },
  { w: 390, h: 844 },
];
mkdirSync(out, { recursive: true });

const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--hide-scrollbars'] });
const problems = [];
for (const vp of VIEWPORTS) {
  const page = await browser.newPage();
  await page.setViewport({ width: vp.w, height: vp.h, deviceScaleFactor: 1, isMobile: vp.w < 500, hasTouch: vp.w < 800 });
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await page.goto(base + '/', { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => document.body.innerText.includes('did:web'), { timeout: 20000 }).catch(() => {});
  const metrics = async (state) => {
    const m = await page.evaluate(() => ({
      scrollW: document.documentElement.scrollWidth,
      clientW: document.documentElement.clientWidth,
      height: document.documentElement.scrollHeight,
    }));
    const overflow = m.scrollW > m.clientW + 1;
    console.log(`${vp.w}px ${state}: scrollWidth=${m.scrollW} clientWidth=${m.clientW} pageHeight=${m.height} overflow=${overflow}`);
    if (overflow) problems.push(`${vp.w}px ${state} overflows horizontally`);
    await page.screenshot({ path: join(out, `${prefix}-${vp.w}-${state}.png`), fullPage: true });
  };
  await metrics('idle');

  const clickByText = async (re) => {
    const handle = await page.evaluateHandle((src) => {
      const rx = new RegExp(src, 'i');
      return [...document.querySelectorAll('button')].find((b) => rx.test(b.innerText.trim())) ?? null;
    }, re.source);
    const el = handle.asElement();
    if (!el) throw new Error(`button not found: ${re}`);
    await el.click();
  };
  try {
    await clickByText(/^120 sar/);
    await page.waitForFunction(() => /Authorized/.test(document.body.innerText), { timeout: 30000 });
    await metrics('allow-120');
    await clickByText(/^5,000 sar/);
    await page.waitForFunction(() => /Denied/.test(document.body.innerText), { timeout: 30000 });
    await metrics('deny-5000');
  } catch (e) {
    problems.push(`${vp.w}px flow failed: ${e.message}`);
  }
  if (errors.length) problems.push(`${vp.w}px console errors: ${errors.slice(0, 3).join(' | ')}`);
  await page.close();
}
await browser.close();
console.log(problems.length ? `\nPROBLEMS:\n- ${problems.join('\n- ')}` : '\nno overflow, no console errors');
process.exit(problems.length ? 1 : 0);
