'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import {
  Architecture,
  DemoPanel,
  EvidenceSection,
  FailureExamples,
  Footer,
  Hero,
  IdentityAuthority,
  Lifecycle,
  ReportSummary,
  TopBar,
  type DemoStatus,
  type RunRecord,
  type Runs,
} from '@/components/sections';
import type { AttackReportDto, AuditDto, EvaluationDto, ProfileDto } from '@/lib/dto';
import { limitFromProfile } from '@/lib/presentation';

type ApiError = { error?: string; detail?: string };
const PRIMARY = new Set(['valid-120', 'over-5000', 'custom']);

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Returns an error message for an invalid amount, or the parsed positive number. */
function parseAmount(raw: string): { ok: true; value: number } | { ok: false; message: string } {
  const cleaned = raw.trim().replace(/,/g, '');
  if (cleaned === '') return { ok: false, message: 'Enter an amount, for example 250.' };
  const n = Number(cleaned);
  if (!Number.isFinite(n) || n <= 0) return { ok: false, message: 'Amount must be a positive number, for example 250.' };
  return { ok: true, value: n };
}

export default function Page() {
  const [profile, setProfile] = useState<ProfileDto | null>(null);
  const [audit, setAudit] = useState<AuditDto | null>(null);
  const [status, setStatus] = useState<DemoStatus | null>(null);
  const [report, setReport] = useState<AttackReportDto | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  const [runs, setRuns] = useState<Runs>({});
  const [last, setLast] = useState<RunRecord | undefined>(undefined);
  const [running, setRunning] = useState<string | null>(null);
  const [errorPrimary, setErrorPrimary] = useState<string | null>(null);
  const [errorOther, setErrorOther] = useState<string | null>(null);
  const [amount, setAmount] = useState('250');
  const [amountError, setAmountError] = useState<string | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  // One request at a time. Buttons use aria-disabled (not `disabled`) so keyboard focus is never lost.
  const busyRef = useRef(false);
  const begin = useCallback((id: string): boolean => {
    if (busyRef.current) return false;
    busyRef.current = true;
    setRunning(id);
    return true;
  }, []);
  const release = useCallback(() => {
    busyRef.current = false;
    setRunning(null);
  }, []);

  const refresh = useCallback(async (attempt = 0): Promise<void> => {
    try {
      const [pr, ar, sr] = await Promise.all([
        fetch('/api/agents/support/profile'),
        fetch('/api/audit/acme-demo'),
        fetch('/api/demo/status'),
      ]);
      if (!pr.ok || !ar.ok) throw new Error('backend initializing');
      setProfile(await pr.json());
      setAudit(await ar.json());
      if (sr.ok) {
        const s = (await sr.json()) as DemoStatus;
        if (s.dids !== undefined) setStatus(s);
      }
      setBootError(null);
    } catch {
      // Free hosts cold-start: the first request can outlive the first render.
      // Retry with backoff while keeping the honest "loading" state visible.
      if (attempt < 8) setTimeout(() => void refresh(attempt + 1), 900 + attempt * 800);
      else setBootError('The demo backend did not respond. It may be starting up — try again in a minute.');
    }
  }, []);

  useEffect(() => {
    void refresh();
    fetch('/api/attacks/report')
      .then(async (r) => {
        const j = (await r.json()) as AttackReportDto & ApiError;
        if (!r.ok || j.error !== undefined) throw new Error(j.error ?? `HTTP ${r.status}`);
        setReport(j);
      })
      .catch((e: unknown) => setReportError(e instanceof Error ? e.message : String(e)));
  }, [refresh]);

  /** One real gateway call. Returns the backend's response; decides nothing. */
  const evaluate = useCallback(async (id: string, customAmount?: number): Promise<RunRecord | undefined> => {
    const body = id === 'custom' ? { amount: customAmount } : { preset: id };
    const res = await fetch('/api/trust/evaluate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as EvaluationDto & ApiError;
    if (!res.ok || json.error !== undefined) {
      throw new Error(`${json.error ?? 'ERROR'}${json.detail ? `: ${json.detail}` : ''}`);
    }
    const rec: RunRecord = { evaluation: json, at: Date.now() };
    setRuns((prev) => ({ ...prev, [id]: rec }));
    return rec;
  }, []);

  const reloadEvidence = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([fetch('/api/agents/support/profile').then((r) => r.json()), fetch('/api/audit/acme-demo').then((r) => r.json())]);
      setProfile(p);
      setAudit(a);
    } catch {
      /* evidence panels keep their previous (still-true) content */
    }
  }, []);

  const scrollToVerdict = useCallback(() => {
    requestAnimationFrame(() => {
      document.getElementById('verdict-anchor')?.scrollIntoView({ block: 'nearest', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    });
  }, []);

  const runPrimary = useCallback(
    async (id: string, customAmount?: number) => {
      if (!begin(id)) return;
      setErrorPrimary(null);
      try {
        const rec = await evaluate(id, customAmount);
        if (rec !== undefined) setLast(rec);
        release(); // the verdict is on screen; refresh the evidence panels in the background
        scrollToVerdict();
        await reloadEvidence();
      } catch (e) {
        setErrorPrimary(e instanceof Error ? e.message : String(e));
      } finally {
        release();
      }
    },
    [begin, release, evaluate, reloadEvidence, scrollToVerdict],
  );

  const runBoth = useCallback(async () => {
    if (!begin('both')) return;
    setErrorPrimary(null);
    try {
      await evaluate('valid-120');
      const second = await evaluate('over-5000');
      if (second !== undefined) setLast(second);
      release();
      scrollToVerdict();
      await reloadEvidence();
    } catch (e) {
      setErrorPrimary(e instanceof Error ? e.message : String(e));
    } finally {
      release();
    }
  }, [begin, release, evaluate, reloadEvidence, scrollToVerdict]);

  const runCustom = useCallback(() => {
    const parsed = parseAmount(amount);
    if (!parsed.ok) {
      setAmountError(parsed.message);
      return;
    }
    setAmountError(null);
    void runPrimary('custom', parsed.value);
  }, [amount, runPrimary]);

  const runOther = useCallback(
    async (id: string) => {
      if (!begin(id)) return;
      setErrorOther(null);
      try {
        // Presets that belong to the main demo also update the main verdict.
        const rec = await evaluate(id);
        if (rec !== undefined && PRIMARY.has(id)) setLast(rec);
        release();
        await reloadEvidence();
      } catch (e) {
        setErrorOther(e instanceof Error ? e.message : String(e));
      } finally {
        release();
      }
    },
    [begin, release, evaluate, reloadEvidence],
  );

  const limit = limitFromProfile(profile);

  return (
    <div className="page">
      <TopBar status={status} />

      <main id="main">
        <Hero onCompare={() => void runBoth()} busy={running === 'both'} />

        {bootError !== null && (
          <div className="err" role="alert" style={{ marginTop: 'var(--s5)' }}>
            <strong>Backend not ready.</strong> {bootError}{' '}
            <button type="button" className="btn btn--small" onClick={() => { setBootError(null); void refresh(); }}>Retry</button>
          </div>
        )}

        <div className="section" id="identity" aria-labelledby="identity-h">
          <div className="section-head">
            <div className="eyebrow">1 · Identity, authority and the live decision</div>
            <h2 id="identity-h">Who is asking, what were they granted, and what happens at the limit?</h2>
          </div>
          <div className="grid-2" id="demo">
            <IdentityAuthority profile={profile} status={status} />
            <DemoPanel
              profile={profile}
              runs={runs}
              last={last}
              running={running}
              error={errorPrimary}
              amount={amount}
              amountError={amountError}
              onAmount={(v) => { setAmount(v); setAmountError(null); }}
              onRun={(id) => void runPrimary(id)}
              onCustom={runCustom}
              onBoth={() => void runBoth()}
              onRetry={() => setErrorPrimary(null)}
            />
          </div>
        </div>

        <section className="section" id="failures" aria-labelledby="failures-h">
          <div className="section-head">
            <div className="eyebrow">2 · Failure thinking</div>
            <h2 id="failures-h">What happens when something is wrong?</h2>
            <p>
              Each case below is a real request through the same gateway. All of them must be denied, and the protected action must never run. The full 60-scenario suite checks
              those side effects too.
            </p>
          </div>
          {errorOther !== null && (
            <div className="err" role="alert" style={{ marginBottom: 'var(--s4)' }}>
              <strong>The request could not be completed.</strong> <span className="mono wrap-any">{errorOther}</span>
            </div>
          )}
          <FailureExamples runs={runs} running={running} onRun={(id) => void runOther(id)} limit={limit} />
        </section>

        <section className="section" id="lifecycle" aria-labelledby="life-h">
          <div className="section-head">
            <div className="eyebrow">3 · Grant · scope · revoke</div>
            <h2 id="life-h">How trust is granted, narrowed and withdrawn</h2>
            <p>The lifecycle of one delegation, with every step tied to something you can run or a test that proves it.</p>
          </div>
          <Lifecycle profile={profile} runs={runs} running={running} onRun={(id) => void runOther(id)} />
        </section>

        <section className="section" id="evidence" aria-labelledby="ev-h">
          <div className="section-head">
            <div className="eyebrow">4 · Trust profile evidence</div>
            <h2 id="ev-h">Credentials, attestations and an audit trail you can check</h2>
          </div>
          <EvidenceSection profile={profile} audit={audit} status={status} />
          <div style={{ marginTop: 'var(--s4)' }}>
            <ReportSummary report={report} error={reportError} />
          </div>
        </section>

        <section className="section" id="architecture" aria-labelledby="arch-h">
          <div className="section-head">
            <div className="eyebrow">5 · Architecture and standards</div>
            <h2 id="arch-h">Identity → claims → verification → policy</h2>
            <p>Every step runs in the trusted backend. This page only renders what the gateway already decided.</p>
          </div>
          <Architecture />
        </section>
      </main>

      <Footer />
    </div>
  );
}
