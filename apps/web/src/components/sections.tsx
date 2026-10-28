'use client';

/**
 * Presentation components. Every decision, stage, reason code and limit shown
 * here is read from the backend gateway / signed profile responses; nothing in
 * this file computes authorization or invents evidence.
 */

import type { AttackReportDto, AuditDto, DecisionDto, EvaluationDto, ProfileDto } from '@/lib/dto';
import {
  FAILURE_SCENARIOS,
  LIFECYCLE,
  PRIMARY_SCENARIOS,
  STANDARDS,
  amountMeter,
  limitFromProfile,
  pipelineView,
  shortHash,
  stoppedAt,
  verdictFor,
  type PipelineGroupView,
} from '@/lib/presentation';

export interface DemoStatus {
  identityMode: 'fixture' | 'web';
  dids: { org: string; support: string; refund: string };
  replayStore: 'redis' | 'in-memory';
  build?: { sha?: string };
  environment?: string;
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

export function TopBar({ status }: { status: DemoStatus | null }) {
  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark" aria-hidden>✓</span>
        <span>Agent Trust</span>
      </div>
      <nav className="nav" aria-label="Sections">
        <a href="#identity">Identity &amp; authority</a>
        <a href="#demo">Live decision</a>
        <a href="#failures">Failure cases</a>
        <a href="#lifecycle">Grant · revoke</a>
        <a href="#evidence">Evidence</a>
        <a href="/attacks">Security tests</a>
      </nav>
      <div className="chips" style={{ margin: 0 }}>
        <Chip tone={status?.identityMode === 'web' ? 'ok' : 'neutral'}>
          {status === null ? 'Connecting…' : status.identityMode === 'web' ? '✓ did:web live over HTTPS' : 'did:web fixtures (local mode)'}
        </Chip>
        <Chip tone={status?.replayStore === 'redis' ? 'ok' : 'neutral'}>
          {status === null ? 'Replay: …' : status.replayStore === 'redis' ? '✓ Replay store: Redis' : 'Replay store: in-memory'}
        </Chip>
        {status?.build?.sha !== undefined && status.build.sha !== 'dev' && <Chip tone="neutral">build {status.build.sha.slice(0, 7)}</Chip>}
      </div>
    </header>
  );
}

export function Hero({ onCompare, busy }: { onCompare: () => void; busy: boolean }) {
  return (
    <section className="hero" aria-labelledby="hero-title">
      <h1 id="hero-title">
        Trust is not a score. <span className="soft">It is verifiable, scoped, revocable authority.</span>
      </h1>
      <p className="lead">
        AI agents are starting to act for companies — refunds, payments, data access. Knowing <strong>who</strong> an agent is does not tell you{' '}
        <strong>what it may do</strong>. This demo lets a support agent ask a payment agent for a refund, then shows the decision, the proof behind it, and the audit trail.
      </p>
      <p className="contrast">Same agent. Same valid identity. Different requested amount. Different trust decision.</p>
      <div className="ask-row" style={{ marginTop: 'var(--s5)' }}>
        <button type="button" className="btn btn--allow" onClick={onCompare} aria-disabled={busy} aria-busy={busy}>
          {busy ? <Busy label="Running both requests…" /> : 'Run the 120 vs 5,000 SAR comparison'}
        </button>
        <a className="btn btn--link" href="#demo">
          or choose one yourself ↓
        </a>
      </div>
      <div className="chips">
        <Chip tone="warn" title="DemoRefundExecutor moves no money">Simulated refund executor — no money moves</Chip>
        <Chip tone="neutral">Demo clock frozen at 2026-09-15</Chip>
        <Chip tone="neutral">Demo state is shared and resets on restart</Chip>
      </div>
    </section>
  );
}

// -------------------------------------------------- identity and authority

export function IdentityAuthority({ profile, status }: { profile: ProfileDto | null; status: DemoStatus | null }) {
  const live = status?.identityMode === 'web';
  const p = profile?.profile;
  const auth = p?.authority.active[0];
  const limit = limitFromProfile(profile);
  return (
    <div className="stack">
      <section className="card" aria-labelledby="who-title">
        <h3 className="card-title" id="who-title">Who is acting</h3>
        <p className="card-sub">Three principals. The agent proves it holds its key on every request; nobody is trusted for its name.</p>
        <div className="principals">
          <div className="principal">
            <span className="pi" aria-hidden>🏢</span>
            <div style={{ minWidth: 0 }}>
              <div className="role">Issuer (grants authority)</div>
              <div className="name">AcmeOrg</div>
              <div className="did mono wrap-any">{status?.dids.org ?? '…'}</div>
            </div>
          </div>
          <div className="principal">
            <span className="pi" aria-hidden>🤖</span>
            <div style={{ minWidth: 0 }}>
              <div className="role">Agent (asks for the refund)</div>
              <div className="name">
                SupportAgent{' '}
                {p !== undefined && (
                  <Chip tone={p.identity.resolved ? 'ok' : 'deny'}>{p.identity.resolved ? '✓ DID resolved' : '✗ DID unresolved'}</Chip>
                )}
              </div>
              <div className="did mono wrap-any">{p?.agent.did ?? status?.dids.support ?? '…'}</div>
            </div>
          </div>
          <div className="principal">
            <span className="pi" aria-hidden>💳</span>
            <div style={{ minWidth: 0 }}>
              <div className="role">Service (enforces the decision)</div>
              <div className="name">RefundAgent</div>
              <div className="did mono wrap-any">{status?.dids.refund ?? '…'}</div>
            </div>
          </div>
        </div>
        <p className="note" style={{ marginTop: 'var(--s3)' }}>
          {live
            ? 'DID documents are fetched over public HTTPS by a hardened did:web resolver.'
            : 'Local mode: identities resolve from bundled did:web fixtures, not from a live HTTPS fetch.'}
        </p>
      </section>

      <section className="card" aria-labelledby="grant-title">
        <h3 className="card-title" id="grant-title">What it is allowed to do</h3>
        <p className="card-sub">AcmeOrg → SupportAgent, by a signed delegation credential — not by this page and not by history.</p>
        {profile === null ? (
          <div className="stack" style={{ marginTop: 'var(--s4)' }} aria-busy="true">
            <div className="skeleton" style={{ width: '60%' }} />
            <div className="skeleton" />
            <div className="skeleton" style={{ width: '80%' }} />
            <span className="note">Loading the verified profile…</span>
          </div>
        ) : auth === undefined ? (
          <p className="note" style={{ marginTop: 'var(--s3)' }}>No active delegation credential was reported for this agent.</p>
        ) : (
          <div className="grant">
            <div className="label">Limit per request</div>
            <div className="limit num">{limit !== undefined ? `≤ ${fmt(limit.amount)} ${limit.currency}` : 'no amount limit'}</div>
            <hr className="rule" />
            <dl className="kv">
              <dt>Action</dt>
              <dd className="mono">{auth.actions.join(', ')}</dd>
              <dt>Resources</dt>
              <dd className="mono wrap-any">{auth.resources.join(', ')}</dd>
              <dt>Audience</dt>
              <dd className="mono wrap-any">{auth.audience?.[0] ?? '—'}</dd>
              <dt>Status</dt>
              <dd>
                <Chip tone={p !== undefined && p.credentials.revoked === 0 && p.credentials.suspended === 0 ? 'ok' : 'warn'}>
                  {p?.credentials.active ?? 0} active credential{(p?.credentials.active ?? 0) === 1 ? '' : 's'}
                </Chip>{' '}
                <Chip tone="neutral" title={auth.evidenceDigest}>evidence sha256:{shortHash(auth.evidenceDigest)}</Chip>
              </dd>
            </dl>
          </div>
        )}
      </section>
    </div>
  );
}

// ---------------------------------------------------------------- the demo

export function Verdict({ record, limit, title }: { record: RunRecord; limit: { amount: number; currency: string } | undefined; title?: string }) {
  const decision = record.evaluation.result;
  const requested = requestedAmount(record);
  const v = verdictFor(decision, { requested, limit: limit?.amount, currency: limit?.currency });
  const meter = amountMeter(decision, requested, limit?.amount);
  const stop = stoppedAt(pipelineView(decision));
  return (
    <div className={`verdict verdict--${v.tone}`} key={decision.taskId}>
      {title !== undefined && <div className="label">{title}</div>}
      <div className="head">
        <span aria-hidden>{v.kind === 'allow' ? '✓' : v.kind === 'deny' ? '✕' : '!'}</span>
        <span>{v.headline}</span>
      </div>
      <div className="code">{v.code}</div>
      <p className="sentence">{v.sentence}</p>
      {meter !== undefined && limit !== undefined && requested !== undefined && (
        <div className="meter">
          <div className="meter-top">
            <span className="nums num">
              {fmt(requested)} / {fmt(limit.amount)} {limit.currency}
            </span>
            <span className="note">{meter.label} (limit from the signed delegation)</span>
          </div>
          <div className="meter-bar" role="img" aria-label={`${requested} of ${limit.amount} ${limit.currency} — ${meter.label}`}>
            <div className={`meter-fill ${meter.tone}`} style={{ width: `${meter.percent}%` }} />
          </div>
        </div>
      )}
      {stop !== undefined && (
        <p className="stopped">
          Stopped at <strong>step {stop.order}: {stop.label}</strong>
          {stop.order > 4 ? ' — every verification step before it passed.' : ' — later steps did not run.'}
        </p>
      )}
      {record.evaluation.firstResult !== undefined && (
        <p className="stopped">
          First send: <strong>{record.evaluation.firstResult.outcome}</strong> · identical re-send: <strong>{decision.outcome}</strong>
        </p>
      )}
      {record.evaluation.note !== undefined && <p className="note" style={{ marginTop: 'var(--s2)' }}>{record.evaluation.note}</p>}
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
    <details className="disclose" style={{ marginTop: 'var(--s3)' }}>
      <summary>Evidence &amp; receipts for this request</summary>
      <div className="table-wrap">
        <table className="table">
          <tbody>
            <tr><th scope="row">Task</th><td className="mono wrap-any">{d.taskId}</td></tr>
            <tr><th scope="row">Outcome</th><td className="mono">{d.outcome}</td></tr>
            <tr><th scope="row">Reason codes</th><td className="mono wrap-any">{d.reasonCodes.join(', ') || '—'}</td></tr>
            <tr><th scope="row">Decision receipt</th><td className="mono wrap-any">{d.decisionReceiptId ?? 'none written'}</td></tr>
            <tr><th scope="row">Outcome receipt</th><td className="mono wrap-any">{d.executionReceiptId ?? 'none (nothing executed)'}</td></tr>
            {record.evaluation.runReceipts.map((r) => (
              <tr key={r.sequence}><th scope="row">Receipt #{r.sequence} hash</th><td className="mono wrap-any">sha256:{r.eventHash}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

export function DemoPanel(props: {
  profile: ProfileDto | null;
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
  return (
    <section className="card" aria-labelledby="demo-title">
      <h3 className="card-title" id="demo-title">SupportAgent asks RefundAgent for a refund</h3>
      <p className="card-sub">
        Pick an amount. The request is signed in the server, sent through the real trust gateway, and the result below is exactly what the gateway returned.
      </p>

      <div className="ask">
        {PRIMARY_SCENARIOS.map((s) => (
          <button
            key={s.id}
            type="button"
            className={`btn ${s.id === 'valid-120' ? 'btn--allow' : 'btn--deny'}`}
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
                  {s.id === 'valid-120' ? 'Inside the grant' : `Above the ${limit !== undefined ? fmt(limit.amount) : ''} ${limit?.currency ?? ''} grant`.replace(/\s+/g, ' ').trim()}
                </span>
              </>
            )}
          </button>
        ))}
      </div>
      <div className="ask-row">
        <button type="button" className="btn btn--small" onClick={props.onBoth} aria-disabled={busy} aria-busy={props.running === 'both'}>
          {props.running === 'both' ? <Busy label="Running both…" /> : 'Run both, one after the other'}
        </button>
      </div>
      <details className="disclose">
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

      <hr className="rule" />
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
            <strong>No decision yet.</strong> Run a request above. The verdict, the verification pipeline and the receipts all come from the live gateway — this page never computes them.
          </div>
        )}
        {props.last !== undefined && <Verdict record={props.last} limit={limit} />}
      </div>

      {(props.runs['valid-120'] !== undefined || props.runs['over-5000'] !== undefined) && (
        <div className="compare" aria-label="Your two requests side by side">
          {PRIMARY_SCENARIOS.map((s) => {
            const rec = props.runs[s.id];
            const v = rec !== undefined ? verdictFor(rec.evaluation.result) : undefined;
            return (
              <div key={s.id} className={`cell ${v?.kind === 'allow' ? 'ok' : v !== undefined ? 'deny' : ''}`}>
                <div className="label">Your request</div>
                <div className="amt">{fmt(s.amount)} SAR</div>
                {v === undefined ? (
                  <div className="note">not run yet</div>
                ) : (
                  <div>
                    <Chip tone={v.tone}>{v.headline}</Chip> <span className="mono">{v.code}</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {props.last !== undefined && (
        <>
          <h4 className="eyebrow" style={{ marginTop: 'var(--s5)', marginBottom: 0 }}>How the gateway got there</h4>
          <PipelineStepper decision={props.last.evaluation.result} />
          <EvidenceDetails record={props.last} />
        </>
      )}
    </section>
  );
}

// --------------------------------------------------------- failure examples

export function FailureExamples({ runs, running, onRun, limit }: { runs: Runs; running: string | null; onRun: (id: string) => void; limit: { amount: number; currency: string } | undefined }) {
  return (
    <div className="grid-auto">
      {FAILURE_SCENARIOS.map((s, i) => {
        const rec = runs[s.id];
        const v = rec !== undefined ? verdictFor(rec.evaluation.result, { limit: limit?.amount, currency: limit?.currency }) : undefined;
        return (
          <article key={s.id} className={`card scenario ${i === 0 ? 'scenario--lead' : ''}`} aria-labelledby={`f-${s.id}`} style={i === 0 ? { gridColumn: '1 / -1' } : undefined}>
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
      })}
    </div>
  );
}

// ---------------------------------------------------------------- lifecycle

export function Lifecycle({ profile, runs, running, onRun }: { profile: ProfileDto | null; runs: Runs; running: string | null; onRun: (id: string) => void }) {
  const auth = profile?.profile.authority.active[0];
  const limit = limitFromProfile(profile);
  return (
    <div>
      <ol className="life" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {LIFECYCLE.map((step) => {
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
      <p className="note" style={{ marginTop: 'var(--s4)', maxWidth: '70ch' }}>
        <strong>What is and is not shown live:</strong> the public page never exposes controls that issue or revoke credentials. The <em>Revoke</em> step runs a server-scripted case on a
        separate, isolated credential so the shared grant above stays valid for other visitors; reversible suspension (STATUS-002) is covered by the security suite, not this page.
      </p>
    </div>
  );
}

// ----------------------------------------------------------------- evidence

export function EvidenceSection({ profile, audit, status }: { profile: ProfileDto | null; audit: AuditDto | null; status: DemoStatus | null }) {
  const p = profile?.profile;
  const totals = Object.values(p?.history.byAction ?? {}).reduce(
    (a, e) => ({ allow: a.allow + e.decisions.allow, deny: a.deny + e.decisions.deny, ok: a.ok + e.execution.succeeded }),
    { allow: 0, deny: 0, ok: 0 },
  );
  const receipts = audit?.receipts.slice(-6).reverse() ?? [];
  return (
    <div className="grid-auto" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 340px), 1fr))' }}>
      <section className="card" aria-labelledby="att-title">
        <h3 className="card-title" id="att-title">Attestations — evidence, never authority</h3>
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
      </section>

      <section className="card" aria-labelledby="audit-title">
        <h3 className="card-title" id="audit-title">Signed audit history</h3>
        <p className="card-sub">Decisions that reach policy, and the outcomes of executions, are appended to a hash chain; editing or deleting an old entry breaks the chain after it. Requests rejected earlier (a spoofed identity, a replay, a credential problem) are denied but leave no receipt, so nobody can write entries under someone else&apos;s name.</p>
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
        {status?.environment !== undefined && <p className="note" style={{ marginTop: 'var(--s2)' }}>{status.environment}.</p>}
      </section>
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
          <div className="chips">
            {Object.entries(report.summary.byCategory).map(([c, b]) => (
              <Chip key={c} tone={b.passed === b.total ? 'ok' : 'deny'}>{c.replaceAll('_', ' ').toLowerCase()} {b.passed}/{b.total}</Chip>
            ))}
          </div>
          <p className="note" style={{ marginTop: 'var(--s3)' }}>
            Generated when the container image was built and served as a stored report — it did <strong>not</strong> run when this page loaded. Each scenario checks the expected reason and its own
            side-effect invariants (for example, that the executor did not run on a denial). <a href="/attacks">Open the full report →</a> · <a href={`${REPO}/tree/main/packages/attacks`}>suite source</a>
          </p>
        </>
      )}
    </section>
  );
}

// ------------------------------------------------------------- architecture

export function Architecture() {
  return (
    <div className="stack">
      <div className="arch">
        <div className="a"><div className="n">1</div><h3>Identity</h3><p>A DID per agent. Each request is signed with that agent&apos;s key (proof of possession).</p></div>
        <div className="a"><div className="n">2</div><h3>Claims</h3><p>Signed credentials: who delegated what to whom, plus third-party attestations.</p></div>
        <div className="a"><div className="n">3</div><h3>Verification</h3><p>Replay, signature, issuer trust, revocation, quarantine, delegation chain — all before policy.</p></div>
        <div className="a"><div className="n">4</div><h3>Policy</h3><p>A deterministic decision over verified facts only, then receipts, then the (simulated) action.</p></div>
      </div>
      <div className="card tight">
        <div className="label">Built on these standards (profiles implemented; no independent conformance certification is claimed)</div>
        <div className="chips" style={{ marginTop: 'var(--s2)' }}>
          {STANDARDS.map((s) => (
            <Chip key={s.name} tone="neutral" title={s.use}>{s.name}</Chip>
          ))}
        </div>
      </div>
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
