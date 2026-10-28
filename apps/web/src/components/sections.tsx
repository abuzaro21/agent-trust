'use client';

/**
 * Presentation components. Every decision, stage, reason code, limit, receipt
 * and suite result shown here is read from the backend gateway / signed
 * profile / report responses; nothing in this file computes authorization or
 * invents evidence. Before a request has run, the verdict area is empty.
 */

import { useEffect, useState } from 'react';

import type { AttackReportDto, AuditDto, DecisionDto, EvaluationDto, ProfileDto } from '@/lib/dto';
import {
  COMPACT_LIFECYCLE_KEYS,
  FAILURE_SCENARIOS,
  LIFECYCLE,
  PRIMARY_FAILURE_IDS,
  PRIMARY_SCENARIOS,
  STANDARDS,
  amountMeter,
  comparisonOf,
  decisionSplit,
  limitFromProfile,
  pipelineView,
  policyLabel,
  shortHash,
  stoppedAt,
  verdictFor,
  verificationSummary,
  type PipelineGroupView,
} from '@/lib/presentation';

export interface DemoStatus {
  identityMode: 'fixture' | 'web';
  dids: { org: string; support: string; refund: string };
  replayStore: 'redis' | 'in-memory';
  build?: { sha?: string };
  environment?: string;
  executor?: string;
  policy?: string;
  audit?: string;
  clock?: string;
}

/** One response from the backend, kept in this browser only. */
export interface RunRecord {
  evaluation: EvaluationDto;
  at: number;
}
export type Runs = Record<string, RunRecord | undefined>;

const REPO = 'https://github.com/abuzaro21/agent-trust';
const fmt = (n: number) => n.toLocaleString('en-US');

function requestedAmount(rec: RunRecord | undefined): number | undefined {
  return rec?.evaluation.runReceipts.find((r) => r.amount !== undefined)?.amount;
}

function Chip({ tone, children, title }: { tone: 'ok' | 'deny' | 'warn' | 'neutral'; children: React.ReactNode; title?: string }) {
  return (
    <span className={`badge badge--${tone}`} title={title}>
      {children}
    </span>
  );
}

function SectionHead({ id, eyebrow, title, children }: { id: string; eyebrow: string; title: string; children?: React.ReactNode }) {
  return (
    <div className="section-head">
      <div className="eyebrow">{eyebrow}</div>
      <h2 id={id}>{title}</h2>
      {children !== undefined && <p>{children}</p>}
    </div>
  );
}

function Busy({ label }: { label: string }) {
  return (
    <>
      <span className="spinner" aria-hidden />
      <span>{label}</span>
    </>
  );
}

// ------------------------------------------------------------------ chrome

/** Light by default. The choice is remembered per browser; storage may be unavailable, so it is optional. */
export function ThemeToggle() {
  const [dark, setDark] = useState(false);
  useEffect(() => {
    setDark(document.documentElement.dataset.theme === 'dark');
  }, []);
  const flip = () => {
    const next = !dark;
    if (next) document.documentElement.dataset.theme = 'dark';
    else delete document.documentElement.dataset.theme;
    try {
      localStorage.setItem('at-theme', next ? 'dark' : 'light');
    } catch {
      /* private mode: the toggle still works for this page view */
    }
    setDark(next);
  };
  return (
    <button type="button" className="theme-btn" onClick={flip} aria-label="Dark theme" aria-pressed={dark} title={dark ? 'Switch to light theme' : 'Switch to dark theme'}>
      <span aria-hidden>{dark ? '☀' : '◐'}</span>
    </button>
  );
}

export function TopBar({ backHome = false }: { backHome?: boolean }) {
  return (
    <header className="topbar">
      <a className="brand" href="/" style={{ color: 'inherit', textDecoration: 'none' }}>
        <span className="brand-mark" aria-hidden>✓</span>
        <span>Agent Trust</span>
      </a>
      <div className="top-right">
        <nav className="nav" aria-label="Sections">
          {backHome ? (
            <a href="/">← Back to the demo</a>
          ) : (
            <>
              <a href="#demo">Demo</a>
              <a className="opt-nav" href="#failures">Failure cases</a>
              <a href="#evidence">Evidence</a>
              <a className="opt-nav" href="/attacks">Security tests</a>
            </>
          )}
        </nav>
        <span className="sim-pill">Simulation · no real money</span>
        <ThemeToggle />
      </div>
    </header>
  );
}

export function Hero() {
  return (
    <section className="hero" aria-labelledby="hero-title">
      <div className="eyebrow">The agent that earns trust</div>
      <h1 id="hero-title">Trust is a grant, not a score.</h1>
      <p className="lead">
        An agent may act only as far as it was verifiably authorized. Signed credentials and a deterministic server-side policy decide every request — not reputation, not history, not this page.
      </p>
    </section>
  );
}

// ------------------------------------------------------------ decision stage

export function Verdict({ record, limit }: { record: RunRecord; limit: { amount: number; currency: string } | undefined }) {
  const decision = record.evaluation.result;
  const requested = requestedAmount(record);
  const v = verdictFor(decision, { requested, limit: limit?.amount, currency: limit?.currency });
  const meter = amountMeter(decision, requested, limit?.amount);
  const stop = stoppedAt(pipelineView(decision));
  const split = decisionSplit(decision);
  const verif = verificationSummary(decision);
  const policy = policyLabel(decision);
  return (
    <div className={`verdict verdict--${v.tone}`} key={decision.taskId}>
      <div className="top">
        <span className="ico" aria-hidden>{v.kind === 'allow' ? '✓' : v.kind === 'deny' ? '✕' : '!'}</span>
        <div>
          <div className="head">{v.headline}</div>
          {requested !== undefined && <div className="req num">{fmt(requested)} {limit?.currency ?? 'SAR'} refund request</div>}
        </div>
      </div>
      <div className="code">{v.code}</div>
      <p className="sentence">{v.sentence}</p>
      {meter !== undefined && limit !== undefined && requested !== undefined && (
        <div className="meter">
          <div className="meter-bar" role="img" aria-label={`${requested} of ${limit.amount} ${limit.currency} — ${meter.label}`}>
            <div className={`meter-fill ${meter.tone}`} style={{ width: `${meter.percent}%` }} />
          </div>
          <div className="meter-top" style={{ marginTop: 'var(--s2)' }}>
            <span className="nums num">{fmt(requested)} / {fmt(limit.amount)} {limit.currency}</span>
            <span className="note">{meter.label} (limit from the signed delegation)</span>
          </div>
        </div>
      )}
      <dl className="split">
        <div className="row" data-tone={split.authorization.tone}>
          <dt>Authorization</dt>
          <dd>
            <span className="state">{split.authorization.label}</span>
            <span className="why">{split.authorization.detail}</span>
          </dd>
        </div>
        <div className="row" data-tone={split.execution.tone}>
          <dt>Execution</dt>
          <dd>
            <span className="state">{split.execution.label}</span>
            <span className="why">{split.execution.detail}</span>
          </dd>
        </div>
      </dl>
      <div className="chips" style={{ marginTop: 'var(--s3)' }}>
        <Chip tone={verif.passed === verif.total ? 'ok' : 'deny'}>{verif.passed} of {verif.total} verification steps passed</Chip>
        <Chip tone={policy.tone}>Policy: {policy.text}</Chip>
      </div>
      {record.evaluation.firstResult !== undefined && (
        <p className="note" style={{ marginTop: 'var(--s2)' }}>
          First send: <strong>{record.evaluation.firstResult.outcome}</strong> · identical re-send: <strong>{decision.outcome}</strong>
        </p>
      )}
      {record.evaluation.note !== undefined && <p className="note" style={{ marginTop: 'var(--s2)' }}>{record.evaluation.note}</p>}
      <div className="verdict-more">
        <details className="disclose">
          <summary>
            How it was decided
            {stop !== undefined && <span className="hint"> · stopped at step {stop.order}: {stop.label}</span>}
          </summary>
          <PipelineStepper decision={decision} />
        </details>
        <EvidenceDetails record={record} />
      </div>
    </div>
  );
}

export function PipelineStepper({ decision }: { decision: DecisionDto }) {
  const groups = pipelineView(decision);
  const narrow = typeof window !== 'undefined' && window.matchMedia('(max-width: 560px)').matches;
  return (
    <div className="pipeline" role="group" aria-label="Verification and decision pipeline">
      {groups.map((g) => (
        <PipelineGroup key={g.id} group={g} defaultOpen={!narrow || g.steps.some((s) => s.tone === 'deny')} />
      ))}
    </div>
  );
}

function PipelineGroup({ group, defaultOpen }: { group: PipelineGroupView; defaultOpen: boolean }) {
  const failed = group.steps.some((s) => s.tone === 'deny');
  const done = group.steps.filter((s) => s.tone === 'ok').length;
  const ran = group.steps.filter((s) => s.tone !== 'neutral').length;
  return (
    <details className="pgroup" open={defaultOpen} data-failed={failed}>
      <summary>
        <span className="gt">{group.title}</span>
        <span className="gs">
          {group.subtitle} · {failed ? 'a step failed' : ran === 0 ? 'not reached' : `${done} of ${group.steps.length} passed`}
        </span>
      </summary>
      <ol className="steps">
        {group.steps.map((s) => (
          <li key={s.key} className="step enter" data-tone={s.tone}>
            <span className="ico" aria-hidden>{s.tone === 'ok' ? '✓' : s.tone === 'deny' ? '✕' : s.tone === 'warn' ? '!' : '–'}</span>
            <div style={{ minWidth: 0 }}>
              <div className="lbl">
                <span className="ord">{s.order}</span>
                {s.label}
              </div>
              <div className="det">{s.detail}</div>
            </div>
            <span className="val">{s.value}</span>
          </li>
        ))}
      </ol>
    </details>
  );
}

export function EvidenceDetails({ record }: { record: RunRecord }) {
  const d = record.evaluation.result;
  return (
    <details className="disclose">
      <summary>Technical evidence &amp; receipts</summary>
      <div className="table-wrap">
        <table className="table">
          <tbody>
            <tr><th scope="row">Task</th><td className="mono wrap-any">{d.taskId}</td></tr>
            <tr><th scope="row">Outcome</th><td className="mono">{d.outcome}</td></tr>
            <tr><th scope="row">Reason codes</th><td className="mono wrap-any">{d.reasonCodes.join(', ') || '—'}</td></tr>
            <tr><th scope="row">Decision receipt</th><td className="mono wrap-any">{d.decisionReceiptId ?? 'none written'}</td></tr>
            <tr><th scope="row">Outcome receipt</th><td className="mono wrap-any">{d.executionReceiptId ?? (d.stages.execution === 'NOT_RUN' ? 'none (nothing executed)' : 'none recorded')}</td></tr>
            {record.evaluation.firstResult !== undefined && (
              <tr><th scope="row">Two sends</th><td>The receipts listed here belong to the first send ({record.evaluation.firstResult.outcome}). The identical re-send ({d.outcome}) was refused before any receipt was written.</td></tr>
            )}
            {record.evaluation.runReceipts.map((r) => (
              <tr key={r.sequence}><th scope="row">Receipt #{r.sequence} hash</th><td className="mono wrap-any">sha256:{r.eventHash}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function GrantStrip({ profile, status }: { profile: ProfileDto | null; status: DemoStatus | null }) {
  const p = profile?.profile;
  const auth = p?.authority.active[0];
  const limit = limitFromProfile(profile);
  return (
    <>
      <div className="grant-strip">
        <div className="party">
          <span className="av av--org" aria-hidden>A</span>
          <div>
            <div className="name">AcmeOrg</div>
            <div className="sub">issuer · grants authority</div>
          </div>
        </div>
        <div className="grant-line" aria-live="polite">
          {profile === null ? (
            <span className="note" aria-busy="true">Loading the verified grant…</span>
          ) : auth === undefined ? (
            <span className="g-main">no active grant reported</span>
          ) : (
            <>
              <span className="g-main num">{limit !== undefined ? `may refund up to ${fmt(limit.amount)} ${limit.currency}` : 'may refund (no amount limit)'}</span>
              <span className="g-sub">signed delegation credential</span>
            </>
          )}
        </div>
        <div className="party">
          <span className="av" aria-hidden>SA</span>
          <div>
            <div className="name">SupportAgent</div>
            <div className="sub">{p === undefined ? 'resolving identity…' : p.identity.resolved ? '✓ DID resolved' : '✗ DID unresolved'}</div>
          </div>
        </div>
      </div>
      <details className="disclose grant-more" id="grant-details">
        <summary>Credential and identity details</summary>
        {auth !== undefined && p !== undefined ? (
          <dl className="kv">
            <dt>Issuer</dt>
            <dd className="mono wrap-any">{auth.issuer}</dd>
            <dt>Agent</dt>
            <dd className="mono wrap-any">{p.agent.did}</dd>
            <dt>Service</dt>
            <dd className="mono wrap-any">{status?.dids.refund ?? auth.audience?.[0] ?? '—'}</dd>
            <dt>Action</dt>
            <dd className="mono">{auth.actions.join(', ')}</dd>
            <dt>Resources</dt>
            <dd className="mono wrap-any">{auth.resources.join(', ')}</dd>
            <dt>Audience</dt>
            <dd className="mono wrap-any">{auth.audience?.[0] ?? '—'}</dd>
            <dt>Credentials</dt>
            <dd>
              <Chip tone={p.credentials.revoked === 0 && p.credentials.suspended === 0 ? 'ok' : 'warn'}>
                {p.credentials.active} active
              </Chip>{' '}
              <Chip tone="neutral" title={auth.evidenceDigest}>evidence sha256:{shortHash(auth.evidenceDigest)}</Chip>
            </dd>
          </dl>
        ) : (
          <p className="note">Not available yet.</p>
        )}
        <p className="note" style={{ marginTop: 'var(--s3)' }}>
          {status?.identityMode === 'web'
            ? 'DID documents are fetched over public HTTPS by a hardened did:web resolver.'
            : 'Local mode: identities resolve from bundled did:web fixtures, not from a live HTTPS fetch.'}{' '}
          Authority comes from this credential — not from this page and not from history.
        </p>
      </details>
    </>
  );
}

export function DecisionStage(props: {
  profile: ProfileDto | null;
  status: DemoStatus | null;
  runs: Runs;
  last: RunRecord | undefined;
  running: string | null;
  error: string | null;
  amount: string;
  amountError: string | null;
  onAmount: (v: string) => void;
  onRun: (id: string) => void;
  onCustom: () => void;
  onBoth: () => void;
  onRetry: () => void;
}) {
  const limit = limitFromProfile(props.profile);
  const busy = props.running !== null;
  const ran = PRIMARY_SCENARIOS.filter((s) => props.runs[s.id] !== undefined);
  const other = ran.length === 1 ? PRIMARY_SCENARIOS.find((s) => props.runs[s.id] === undefined) : undefined;
  return (
    <section className="card stage" id="demo" aria-labelledby="demo-title">
      <GrantStrip profile={props.profile} status={props.status} />
      <div className="stage-cols">
        <div className="ask-col">
          <h2 id="demo-title">Ask SupportAgent to issue a refund</h2>
          <p className="card-sub">Same agent, same credential. Only the amount changes. The request is signed on the server and sent through the real trust gateway.</p>
          <div className="ask">
            {PRIMARY_SCENARIOS.map((s) => (
              <button
                key={s.id}
                type="button"
                className="btn"
                onClick={() => props.onRun(s.id)}
                aria-disabled={busy}
                aria-busy={props.running === s.id}
              >
                {props.running === s.id ? (
                  <Busy label="Evaluating…" />
                ) : (
                  <>
                    <span className="big num">{fmt(s.amount)} SAR</span>
                    <span className="hint">
                      {s.id === 'valid-120' ? 'inside the grant' : limit !== undefined ? `above the ${fmt(limit.amount)} ${limit.currency} grant` : 'above the grant'}
                    </span>
                    <span className="go">Run request →</span>
                  </>
                )}
              </button>
            ))}
          </div>
          <div className="ask-row">
            <button type="button" className="btn btn--small" onClick={props.onBoth} aria-disabled={busy} aria-busy={props.running === 'both'}>
              {props.running === 'both' ? <Busy label="Running both…" /> : 'Run both and compare'}
            </button>
          </div>
          {other !== undefined && <p className="note" style={{ marginTop: 'var(--s3)' }}>Now run {fmt(other.amount)} SAR to compare the two results side by side.</p>}
          <details className="disclose" id="custom-amount" style={{ marginTop: 'var(--s2)' }}>
            <summary>Try another amount</summary>
            <form
              className="ask-row"
              onSubmit={(e) => {
                e.preventDefault();
                props.onCustom();
              }}
            >
              <div>
                <label className="label" htmlFor="amount">Amount (SAR)</label>
                <input
                  id="amount"
                  className="input num"
                  inputMode="decimal"
                  autoComplete="off"
                  spellCheck={false}
                  value={props.amount}
                  onChange={(e) => props.onAmount(e.target.value)}
                  aria-invalid={props.amountError !== null}
                  aria-describedby={props.amountError !== null ? 'amount-err' : undefined}
                />
              </div>
              <button type="submit" className="btn btn--small" aria-disabled={busy} style={{ alignSelf: 'end' }}>Evaluate this amount</button>
              {props.amountError !== null && <div id="amount-err" className="field-err" role="alert" style={{ flexBasis: '100%' }}>{props.amountError}</div>}
            </form>
          </details>
          <p className="note sim-note">Simulated refund executor — no money moves.</p>
        </div>

        <div className="verdict-col">
          <div id="verdict-anchor" role="status" aria-live="polite" aria-atomic="false">
            {props.error !== null && (
              <div className="err" role="alert">
                <strong>The request could not be completed.</strong>
                <div className="mono wrap-any" style={{ marginTop: 4 }}>{props.error}</div>
                <button type="button" className="btn btn--small" style={{ marginTop: 'var(--s3)' }} onClick={props.onRetry}>Retry</button>
              </div>
            )}
            {props.error === null && props.last === undefined && (
              <div className="placeholder">
                <strong>No decision yet.</strong>
                Run a request. The verdict, the verification steps and the receipts all come from the live gateway — this page never computes them.
              </div>
            )}
            {props.last !== undefined && <Verdict record={props.last} limit={limit} />}
          </div>
        </div>
      </div>
    </section>
  );
}

/** Appears only once BOTH primary requests have returned; every field is read from those two responses. */
export function Comparison({ runs }: { runs: Runs }) {
  const [a, b] = PRIMARY_SCENARIOS.map((s) => runs[s.id]);
  if (a === undefined || b === undefined) return null;
  const va = verdictFor(a.evaluation.result);
  const vb = verdictFor(b.evaluation.result);
  const rel = comparisonOf(a.evaluation.result, b.evaluation.result);
  return (
    <div className="compare-wrap" aria-labelledby="compare-title">
      <h3 className="compare-title" id="compare-title">
        {rel === 'different-decision'
          ? 'Same agent. Same credential. Different amount — different decision.'
          : rel === 'different-outcome'
            ? 'Same agent. Same credential. Different amount — the authorization matched, the outcome did not.'
            : 'Same agent. Same credential. Both requests received the same outcome.'}
      </h3>
      <div className="compare" aria-label="The two requests side by side">
        {[
          { rec: a, v: va, fallback: PRIMARY_SCENARIOS[0]!.amount },
          { rec: b, v: vb, fallback: PRIMARY_SCENARIOS[1]!.amount },
        ].map(({ rec, v, fallback }) => {
          const split = decisionSplit(rec.evaluation.result);
          return (
            <div key={rec.evaluation.result.taskId} className={`cell ${v.tone}`}>
              <div className="amt">{fmt(requestedAmount(rec) ?? fallback)} SAR</div>
              <div className="res">{v.kind === 'allow' ? '✓ ' : v.kind === 'deny' ? '✕ ' : '! '}{v.headline}</div>
              <div className="mono note">{v.code}</div>
              <div className="note" style={{ marginTop: 'var(--s1)' }}>Execution: {split.execution.label}</div>
            </div>
          );
        })}
      </div>
      <p className="note" style={{ marginTop: 'var(--s2)' }}>Both results are the server&apos;s responses to the two requests you ran in this browser session.</p>
    </div>
  );
}

// --------------------------------------------------------- failure examples

function ScenarioCard({ s, runs, running, onRun, limit }: { s: (typeof FAILURE_SCENARIOS)[number]; runs: Runs; running: string | null; onRun: (id: string) => void; limit: { amount: number; currency: string } | undefined }) {
  const rec = runs[s.id];
  const v = rec !== undefined ? verdictFor(rec.evaluation.result, { limit: limit?.amount, currency: limit?.currency }) : undefined;
  return (
    <article className="card scenario" aria-labelledby={`f-${s.id}`}>
      <div className="tag">
        <h3 className="card-title" id={`f-${s.id}`}>{s.title}</h3>
        <Chip tone={s.tone === 'warn' ? 'warn' : 'deny'}>expected: denied</Chip>
      </div>
      <p className="card-sub">{s.proves}</p>
      {s.note !== undefined && <p className="note"><strong>Note:</strong> {s.note}</p>}
      <div>
        <button type="button" className="btn btn--small" onClick={() => onRun(s.id)} aria-disabled={running !== null} aria-busy={running === s.id}>
          {running === s.id ? <Busy label="Evaluating…" /> : rec === undefined ? 'Run this case' : 'Run again'}
        </button>{' '}
        <a className="btn btn--link btn--small" href="/attacks">Also covered by {s.suite} →</a>
      </div>
      {rec !== undefined && v !== undefined && (
        <div className="mini">
          <Chip tone={v.tone}>{v.headline}</Chip> <span className="mono wrap-any">{v.code}</span>
          <p className="note" style={{ marginTop: 'var(--s2)' }}>{v.sentence}</p>
          {rec.evaluation.firstResult !== undefined && (
            <p className="note">First send: <strong>{rec.evaluation.firstResult.outcome}</strong> · identical re-send: <strong>{rec.evaluation.result.outcome}</strong></p>
          )}
          <details className="disclose">
            <summary>Show the pipeline</summary>
            <PipelineStepper decision={rec.evaluation.result} />
          </details>
          <EvidenceDetails record={rec} />
        </div>
      )}
    </article>
  );
}

export function FailureExamples({ runs, running, onRun, limit }: { runs: Runs; running: string | null; onRun: (id: string) => void; limit: { amount: number; currency: string } | undefined }) {
  const primary = FAILURE_SCENARIOS.filter((s) => (PRIMARY_FAILURE_IDS as readonly string[]).includes(s.id));
  const rest = FAILURE_SCENARIOS.filter((s) => !(PRIMARY_FAILURE_IDS as readonly string[]).includes(s.id));
  return (
    <div>
      <div className="grid-auto">
        {primary.map((s) => (
          <ScenarioCard key={s.id} s={s} runs={runs} running={running} onRun={onRun} limit={limit} />
        ))}
      </div>
      <details className="disclose more-cases" id="more-cases">
        <summary>
          {rest.length} more failure cases <span className="hint">· {rest.map((s) => s.title.toLowerCase()).join(', ')}</span>
        </summary>
        <div className="grid-auto">
          {rest.map((s) => (
            <ScenarioCard key={s.id} s={s} runs={runs} running={running} onRun={onRun} limit={limit} />
          ))}
        </div>
      </details>
    </div>
  );
}

// ---------------------------------------------------------------- lifecycle

export function Lifecycle({ profile, runs, running, onRun }: { profile: ProfileDto | null; runs: Runs; running: string | null; onRun: (id: string) => void }) {
  const auth = profile?.profile.authority.active[0];
  const limit = limitFromProfile(profile);
  const steps = LIFECYCLE.filter((s) => (COMPACT_LIFECYCLE_KEYS as readonly string[]).includes(s.key));
  return (
    <div>
      <ol className="life">
        {steps.map((step) => {
          const rec = step.preset !== undefined ? runs[step.preset] : undefined;
          const v = rec !== undefined ? verdictFor(rec.evaluation.result, { limit: limit?.amount, currency: limit?.currency }) : undefined;
          return (
            <li key={step.key} className="card tight lstep">
              <h3>{step.title}</h3>
              <p className="note" style={{ fontSize: '0.88rem' }}>{step.text}</p>
              {step.key === 'grant' && auth !== undefined && (
                <p className="note">
                  Live grant: <span className="mono">{auth.actions.join(', ')}</span>
                  {limit !== undefined && <> ≤ {fmt(limit.amount)} {limit.currency}</>}, evidence <span className="mono">{shortHash(auth.evidenceDigest)}</span>
                </p>
              )}
              {step.preset !== undefined && (
                <div>
                  <button type="button" className="btn btn--small" onClick={() => onRun(step.preset!)} aria-disabled={running !== null} aria-busy={running === step.preset}>
                    {running === step.preset ? <Busy label="Evaluating…" /> : 'Run this step'}
                  </button>
                </div>
              )}
              {v !== undefined && (
                <div>
                  <Chip tone={v.tone}>{v.headline}</Chip> <span className="mono wrap-any">{v.code}</span>
                </div>
              )}
              {step.suite !== undefined && <a className="note" href="/attacks">Suite evidence: {step.suite}</a>}
            </li>
          );
        })}
      </ol>
      <p className="note" style={{ marginTop: 'var(--s3)', maxWidth: '70ch' }}>
        This page has no issue or revoke controls. The <em>Revoke</em> step runs a server-scripted case on a separate, isolated credential so the shared grant stays valid for other visitors;
        reversible suspension (STATUS-002) is covered by the security suite.
      </p>
    </div>
  );
}

// ----------------------------------------------------------------- evidence

export function EvidenceSection({
  profile,
  audit,
  status,
  report,
  reportError,
}: {
  profile: ProfileDto | null;
  audit: AuditDto | null;
  status: DemoStatus | null;
  report: AttackReportDto | null;
  reportError: string | null;
}) {
  const p = profile?.profile;
  const totals = Object.values(p?.history.byAction ?? {}).reduce(
    (a, e) => ({ allow: a.allow + e.decisions.allow, deny: a.deny + e.decisions.deny, ok: a.ok + e.execution.succeeded }),
    { allow: 0, deny: 0, ok: 0 },
  );
  const receipts = audit?.receipts.slice(-6).reverse() ?? [];
  return (
    <div>
      <ReportSummary report={report} error={reportError} />

      <details className="card acc" id="audit-acc" style={{ marginTop: 'var(--s3)' }}>
        <summary>
          <span>Signed audit history</span>
          <span className="hint">{audit === null || audit.error !== undefined ? 'hash-chained receipts' : `${audit.receipts.length} receipts · ${audit.chain.valid ? 'chain intact' : 'chain broken'}`}</span>
        </summary>
        <div className="acc-body">
          <p className="card-sub">
            When a request reaches policy and the audit store is available, its decision (and later the execution outcome) is appended to a hash chain; editing or deleting an old entry breaks the chain after it. Nothing is recorded for requests rejected earlier (a spoofed identity, a replay, a credential problem), for a policy-engine failure, or during an audit-store outage — so nobody can write entries under someone else&apos;s name, and a missing entry is never evidence of an allowed action.
          </p>
          {audit === null ? (
            <div className="skeleton" style={{ marginTop: 'var(--s4)' }} aria-busy="true" />
          ) : audit.error !== undefined ? (
            <div className="err" role="alert" style={{ marginTop: 'var(--s3)' }}><strong>Audit unavailable.</strong> <span className="mono">{audit.error}</span></div>
          ) : (
            <>
              <div className="chips" style={{ marginTop: 'var(--s3)' }}>
                <Chip tone={audit.chain.valid ? 'ok' : 'deny'}>{audit.chain.valid ? `✓ chain intact (${audit.receipts.length} receipts)` : '✕ chain broken'}</Chip>
                <Chip tone={audit.checkpoint.signatureValid ? 'ok' : 'deny'}>{audit.checkpoint.signatureValid ? '✓ checkpoint signature valid' : '✕ checkpoint signature invalid'}</Chip>
                <Chip tone={audit.checkpoint.chainMatches ? 'ok' : 'warn'}>{audit.checkpoint.chainMatches ? '✓ checkpoint covers this chain' : '! checkpoint does not match this chain'}</Chip>
              </div>
              <div className="callout" style={{ marginTop: 'var(--s3)' }}>
                <strong>Read this log honestly:</strong> it is one shared demo log (all visitors, in memory, resets on restart); every receipt carries the frozen demo clock
                (2026-09-15T12:00:00Z); the checkpoint is signed by this demo&apos;s own signer, which shows internal consistency — it is <strong>not</strong> anchored outside the server.
              </div>
              <p className="note" style={{ marginTop: 'var(--s3)' }}>
                History so far: allowed {totals.allow} · denied {totals.deny} · simulated executions succeeded {totals.ok}. History describes what happened; it grants nothing.
              </p>
              <ol className="timeline" aria-label="Most recent receipts">
                {receipts.length === 0 && <li className="note">No receipts yet — run a request.</li>}
                {receipts.map((r) => (
                  <li key={r.sequence} className="tl">
                    <span className="seq">#{r.sequence}</span>
                    <div style={{ minWidth: 0 }}>
                      <span className="mono">{r.action}</span>
                      {r.amount !== undefined && <span className="num"> · {fmt(r.amount)} {r.currency}</span>}
                      <div className="meta">{r.reasonCodes.join(', ')} · {r.taskId ?? ''}</div>
                    </div>
                    <span className="badges">
                      <Chip tone={r.effect === 'ALLOW' ? 'ok' : 'deny'}>{r.effect}</Chip>
                      {r.executionState !== undefined && r.executionState !== 'NOT_EXECUTED' && (
                        <Chip tone={r.executionState === 'SUCCEEDED' ? 'ok' : r.executionState === 'FAILED' ? 'deny' : 'warn'}>
                          {r.executionState === 'SUCCEEDED' ? 'SUCCEEDED (simulated)' : r.executionState}
                        </Chip>
                      )}
                    </span>
                  </li>
                ))}
              </ol>
              <p className="note mono wrap-any" style={{ marginTop: 'var(--s2)' }}>head {shortHash(audit.checkpoint.headHash)}</p>
            </>
          )}
        </div>
      </details>

      <details className="card acc" id="attestations-acc">
        <summary>
          <span>Attestations — evidence, never authority</span>
          <span className="hint">{p === undefined ? '' : `${p.attestations.trusted.length} accepted · ${p.attestations.rejected.length} rejected`}</span>
        </summary>
        <div className="acc-body">
          <p className="card-sub">Third-party claims about the agent. They are shown as separate items; they are never added up into a score and never grant permission.</p>
          {profile === null ? (
            <div className="skeleton" style={{ marginTop: 'var(--s4)' }} aria-busy="true" />
          ) : (
            <div style={{ marginTop: 'var(--s3)' }}>
              {p!.attestations.trusted.length === 0 && p!.attestations.rejected.length === 0 && <p className="note">None recorded.</p>}
              {p!.attestations.trusted.map((t) => (
                <div key={t.credentialId} style={{ padding: 'var(--s2) 0', borderTop: '1px solid var(--border)' }}>
                  <Chip tone="ok">✓ accepted · {t.type}</Chip> <strong>{t.statement}</strong>
                  <div className="mono note wrap-any">issuer {t.issuer}</div>
                </div>
              ))}
              {p!.attestations.rejected.map((r, i) => (
                <div key={i} style={{ padding: 'var(--s2) 0', borderTop: '1px solid var(--border)' }}>
                  <Chip tone="deny">✕ rejected</Chip> <span className="mono">{r.reasonCodes.join(', ')}</span>
                  {r.issuer !== undefined && <div className="mono note wrap-any">issuer {r.issuer}</div>}
                  <div className="note">A valid signature from an issuer that is not trusted for this type is still rejected.</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </details>

      <details className="card acc" id="runtime-acc">
        <summary>
          <span>Runtime and standards</span>
          <span className="hint">as reported by the backend</span>
        </summary>
        <div className="acc-body">
          {status === null ? (
            <p className="note">Waiting for the backend…</p>
          ) : (
            <dl className="kv">
              <dt>Identity</dt>
              <dd>{status.identityMode === 'web' ? 'did:web resolved live over HTTPS' : 'did:web fixtures (local mode)'}</dd>
              <dt>Replay store</dt>
              <dd>{status.replayStore === 'redis' ? 'Redis' : 'in-memory'}</dd>
              {status.build?.sha !== undefined && (<><dt>Build</dt><dd className="mono">{status.build.sha}</dd></>)}
              {status.executor !== undefined && (<><dt>Executor</dt><dd>{status.executor}</dd></>)}
              {status.policy !== undefined && (<><dt>Policy</dt><dd>{status.policy}</dd></>)}
              {status.environment !== undefined && (<><dt>Environment</dt><dd>{status.environment}</dd></>)}
            </dl>
          )}
          <div className="label" style={{ marginTop: 'var(--s4)' }}>Built on these standards (profiles implemented; no independent conformance certification is claimed)</div>
          <div className="chips" style={{ marginTop: 'var(--s2)' }}>
            {STANDARDS.map((s) => (
              <Chip key={s.name} tone="neutral" title={s.use}>{s.name}</Chip>
            ))}
          </div>
        </div>
      </details>
    </div>
  );
}

export function ReportSummary({ report, error }: { report: AttackReportDto | null; error: string | null }) {
  return (
    <section className="card" aria-labelledby="rep-title">
      <h3 className="card-title" id="rep-title">Security test suite</h3>
      {error !== null ? (
        <div className="err" role="alert" style={{ marginTop: 'var(--s3)' }}><strong>Report unavailable.</strong> <span className="mono">{error}</span></div>
      ) : report === null ? (
        <div className="skeleton" style={{ marginTop: 'var(--s4)' }} aria-busy="true" />
      ) : (
        <>
          <p style={{ marginTop: 'var(--s2)' }}>
            <strong className="num" style={{ fontSize: '1.6rem', color: report.summary.failed === 0 ? 'var(--ok)' : 'var(--deny)' }}>
              {report.summary.passed} / {report.summary.total}
            </strong>{' '}
            scenarios passed ({report.summary.attacks} attacks + {report.summary.failureDemos} failure demos)
          </p>
          <details className="disclose">
            <summary>Results by layer</summary>
            <div className="chips" style={{ marginTop: 0 }}>
              {Object.entries(report.summary.byCategory).map(([c, b]) => (
                <Chip key={c} tone={b.passed === b.total ? 'ok' : 'deny'}>{c.replaceAll('_', ' ').toLowerCase()} {b.passed}/{b.total}</Chip>
              ))}
            </div>
          </details>
          <p className="note">
            Generated when the container image was built and served as a stored report — it did <strong>not</strong> run when this page loaded. Each scenario declares a typed expected outcome and is judged on machine-checked
            invariants (for example, that the executor and policy did not run on a denial). <a href="/attacks">Open the full report →</a> · <a href={`${REPO}/tree/main/packages/attacks`}>suite source</a>
          </p>
        </>
      )}
    </section>
  );
}

// ------------------------------------------------------------- architecture

export function Architecture() {
  return (
    <div className="card arch">
      <div className="a"><div className="n">1</div><h3>Identity</h3><p>A DID per agent. Each request is signed with that agent&apos;s key (proof of possession).</p></div>
      <div className="a"><div className="n">2</div><h3>Claims</h3><p>Signed credentials: who delegated what to whom, plus third-party attestations.</p></div>
      <div className="a"><div className="n">3</div><h3>Verification</h3><p>Replay, signature, issuer trust, revocation, quarantine, delegation chain — all before policy.</p></div>
      <div className="a"><div className="n">4</div><h3>Policy</h3><p>A deterministic decision over verified facts only, then receipts, then the (simulated) action.</p></div>
    </div>
  );
}

export function Footer() {
  return (
    <footer className="footer">
      <strong style={{ color: 'var(--fg-muted)' }}>What this demo is — and is not</strong>
      <ul>
        <li>The refund executor is a simulation. No money moves.</li>
        <li>The agents are server-side fixtures; this public page does not authenticate external callers.</li>
        <li>The demo clock is frozen at 2026-09-15T12:00:00Z, so all receipts share one timestamp.</li>
        <li>Audit, status and profile state live in memory, are shared by every visitor, and reset when the service restarts.</li>
        <li>The gateway accepts a single delegation link; per-day limits and human approval are not implemented.</li>
      </ul>
      <p style={{ marginTop: 'var(--s4)' }}>
        <a href={REPO}>Source on GitHub</a> · <a href={`${REPO}/blob/main/docs/submission/two-year-thesis.md`}>Two-year thesis</a> ·{' '}
        <a href={`${REPO}/blob/main/docs/threat-model.md`}>Threat model &amp; known limitations</a> · MIT licensed
      </p>
    </footer>
  );
}

export { SectionHead };
