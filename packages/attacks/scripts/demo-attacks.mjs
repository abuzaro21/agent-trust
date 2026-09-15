#!/usr/bin/env node
/**
 * pnpm demo:attacks — the deterministic adversarial suite (Step 13).
 *
 * Runs every registered scenario, renders a clean terminal report, and
 * writes artifacts/attacks/attack-report.{json,md} (generated output —
 * not committed, per Step 13O determinism guidance). `--ci` exits 1 on
 * any FAIL so the suite doubles as a security regression gate.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { runAttackSuite, renderReportMd } from '../src/index.js';

const ciMode = process.argv.includes('--ci');
const only = (() => {
  const i = process.argv.indexOf('--only');
  return i === -1 ? undefined : process.argv.slice(i + 1).filter((a) => !a.startsWith('-'));
})();

const b = (s) => `\x1b[1m${s}\x1b[0m`;
const g = (s) => `\x1b[32m${s}\x1b[0m`;
const r = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

console.log(b('agent-trust — Adversarial Suite'));
console.log(dim('every scenario: isolated world, frozen clock, denial reason AND side-effect invariants\n'));

const report = await runAttackSuite(only ? { only } : {});

let lastCategory = null;
for (const sc of report.scenarios) {
  if (sc.category !== lastCategory) {
    console.log(`\n${b(`── ${sc.category} ──`)}`);
    lastCategory = sc.category;
  }
  const status = sc.status === 'PASS' ? g('[PASS]') : r('[FAIL]');
  console.log(`${status} ${b(sc.id.padEnd(14))} ${sc.title}`);
  console.log(`       ${dim('→')} ${sc.observed.outcome}`);
  const codes = sc.observed.reasonCodes;
  if (codes.length > 0 && (sc.expected.reasonCode === undefined || !codes.includes(sc.expected.reasonCode))) {
    console.log(`       ${dim('reasons:')} ${codes.join(', ')}`);
  } else if (codes.length > 0) {
    console.log(`       ${dim('→')} ${codes.join(', ')}`);
  }
  if (sc.detail !== undefined && sc.status === 'FAIL') {
    console.log(`       ${r(`invariant: ${sc.detail}`)}`);
  }
}

const { summary } = report;
const attacksBlocked = `${summary.passed}/${summary.total}`;
const verdict = summary.failed === 0 ? g(attacksBlocked) : r(attacksBlocked);
console.log(`\n${'─'.repeat(46)}`);
console.log(`${b(verdict)} security scenarios passed (${summary.attacks} attacks + ${summary.failureDemos} failure demos)`);
const fails = report.scenarios.filter((sc) => sc.status === 'FAIL');
if (fails.length > 0) {
  console.log(r(`\nFAILED scenarios: ${fails.map((sc) => sc.id).join(', ')}`));
}

const outDir = join(import.meta.dirname, '../../../artifacts/attacks');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'attack-report.json'), `${JSON.stringify(report, null, 2)}\n`);
writeFileSync(join(outDir, 'attack-report.md'), renderReportMd(report));
console.log(dim(`\nreports: artifacts/attacks/attack-report.json · attack-report.md`));

if (ciMode && summary.failed > 0) process.exit(1);
void lastCategory;
