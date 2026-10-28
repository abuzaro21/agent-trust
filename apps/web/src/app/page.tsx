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
  // Each run owns a token; only the owner can release the lock, so a late `finally`
  // from an earlier run can never free a newer run's lock.
  const activeRef = useRef<number | null>(null);
  const seqRef = useRef(0);
  const begin = useCallback((id: string): number | null => {
    if (activeRef.current !== null) return null;
    const token = ++seqRef.current;
    activeRef.current = token;
    setRunning(id);
    return token;
  }, []);
  const release = useCallback((token: number) => {
    if (activeRef.current !== token) return;
    activeRef.current = null;
    setRunning(null);
  }, []);
  const lastReq = useRef<{ id: string; amount?: number } | null>(null);
  const evSeq = useRef(0);
  const [evidenceStale, setEvidenceStale] = useState(false);

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
    const mine = ++evSeq.current; // only the newest refresh may update the panels
    try {
      const [pr, ar] = await Promise.all([fetch('/api/agents/support/profile'), fetch('/api/audit/acme-demo')]);
      if (!pr.ok || !ar.ok) throw new Error('evidence refresh failed');
      const [p, a] = await Promise.all([pr.json(), ar.json()]);
      if (mine !== evSeq.current) return;
      setProfile(p);
      setAudit(a);
      setEvidenceStale(false);
    } catch {
      // The panels keep their previous content, which no longer includes the latest run: say so.
      if (mine === evSeq.current) setEvidenceStale(true);
    }
  }, []);

  const scrollToVerdict = useCallback(() => {
    requestAnimationFrame(() => {
      document.getElementById('verdict-anchor')?.scrollIntoView({ block: 'nearest', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    });
  }, []);

  const runPrimary = useCallback(
    async (id: string, customAmount?: number) => {
      const token = begin(id);
      if (token === null) return;
      lastReq.current = { id, amount: customAmount };
      setErrorPrimary(null);
      try {
        const rec = await evaluate(id, customAmount);
        if (rec !== undefined) setLast(rec);
        release(token); // the verdict is on screen; refresh the evidence panels in the background
        scrollToVerdict();
        await reloadEvidence();
      } catch (e) {
        setErrorPrimary(e instanceof Error ? e.message : String(e));
      } finally {
        release(token);
      }
    },
    [begin, release, evaluate, reloadEvidence, scrollToVerdict],
  );

  const runBoth = useCallback(async () => {
    const token = begin('both');
    if (token === null) return;
    lastReq.current = { id: 'both' };
    setErrorPrimary(null);
    try {
      await evaluate('valid-120');
      const second = await evaluate('over-5000');
      if (second !== undefined) setLast(second);
      release(token);
      scrollToVerdict();
      await reloadEvidence();
    } catch (e) {
      setErrorPrimary(e instanceof Error ? e.message : String(e));
    } finally {
      release(token);
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
      const token = begin(id);
      if (token === null) return;
      setErrorOther(null);
      try {
        // Presets that belong to the main demo also update the main verdict.
        const rec = await evaluate(id);
        if (rec !== undefined && PRIMARY.has(id)) setLast(rec);
        release(token);
        await reloadEvidence();
      } catch (e) {
        setErrorOther(e instanceof Error ? e.message : String(e));
      } finally {
        release(token);
      }
    },
    [begin, release, evaluate, reloadEvidence],
  );

  const retryLast = useCallback(() => {
    const req = lastReq.current;
    setErrorPrimary(null);
    if (req === null) return;
    if (req.id === 'both') void runBoth();
    else void runPrimary(req.id, req.amount);
  }, [runBoth, runPrimary]);

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
              onRetry={retryLast}
            />
          </div>
        </div>

        <section className="section" id="failures" aria-labelledby="failures-h">
          <div className="section-head">
            <div className="eyebrow">2 · Failure thinking</div>
            <h2 id="failures-h">What happens when something is wrong?</h2>
            <p>
              Each case below is a real request through the same gateway and must be denied. (In the replay case the first send is legitimate — one authorization, one execution —
              and only the identical re-send must be refused.) The 60-scenario suite checks each scenario&apos;s side-effect invariants too, for example that the executor did not run on a denial.
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
          {evidenceStale && (
            <div className="callout" role="status" style={{ marginBottom: 'var(--s4)' }}>
              <strong>The evidence panels could not be refreshed after the last request,</strong> so they may not include it.{' '}
              <button type="button" className="btn btn--small" onClick={() => void reloadEvidence()}>Reload evidence</button>
            </div>
          )}
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
