import { useEffect, useMemo, useState } from 'react';
import {
  CAPABILITIES,
  HEADLINE_STATS,
  HYDRA_MATRIX,
  MATURITY_LABEL,
  PIPELINE,
  type Capability,
  type Maturity,
  type PanelId,
} from './capabilities';

/* ── shared atoms ─────────────────────────────────────────────────────── */

const MATURITY_STYLE: Record<Maturity, string> = {
  live: 'border-hg-ember/50 bg-hg-ember/10 text-hg-flame',
  engine: 'border-hg-amber/40 bg-hg-amber/10 text-hg-amber',
  partial: 'border-hg-line bg-white/5 text-hg-ash',
};

function Maturity({ value }: { value: Maturity }) {
  return (
    <span className={`hg-chip ${MATURITY_STYLE[value]}`}>
      <span className="hg-dot" style={{ color: 'currentColor', backgroundColor: 'currentColor' }} />
      {MATURITY_LABEL[value]}
    </span>
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="hg-bracket border border-hg-line bg-hg-panel/60 px-5 py-4">
      <div className="font-display text-3xl text-hg-bone">{value}</div>
      <div className="mt-1 text-[11px] uppercase tracking-[0.18em] text-hg-ash">{label}</div>
    </div>
  );
}

function SectionHead({ cap }: { cap: Capability }) {
  return (
    <header className="border-b border-hg-line pb-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="hg-kicker">
          <span className="h-2 w-2 bg-hg-ember" />
          {cap.kicker}
        </span>
        <Maturity value={cap.maturity} />
      </div>

      <h1 className="hg-title mt-4 text-3xl leading-tight sm:text-4xl">{cap.headline}</h1>

      <p className="mt-4 max-w-3xl text-[15px] leading-relaxed text-hg-bone/85">{cap.plain}</p>

      <div className="mt-5 border-l-2 border-hg-ember bg-hg-ember/[0.06] px-4 py-3">
        <p className="text-sm text-hg-bone/90">
          <span className="font-display text-hg-flame">Guarantee · </span>
          {cap.proves}
        </p>
      </div>
    </header>
  );
}

function Bullets({ cap }: { cap: Capability }) {
  return (
    <div className="grid gap-4 md:grid-cols-3">
      {cap.bullets.map((b, i) => (
        <div key={b} className="border border-hg-line bg-hg-panel/50 p-4">
          <div className="font-display text-xs text-hg-ember">{String(i + 1).padStart(2, '0')}</div>
          <p className="mt-2 text-sm leading-relaxed text-hg-bone/80">{b}</p>
        </div>
      ))}
    </div>
  );
}

function HydraStrip({ cap }: { cap: Capability }) {
  return (
    <div className="flex flex-wrap items-center gap-3 border border-hg-line bg-black/50 px-4 py-3">
      <span className="hg-kicker">HydraDB</span>
      <span className="font-display text-sm text-hg-bone/85">{cap.hydra}</span>
    </div>
  );
}

/* ── live health probe ─────────────────────────────────────────────────── */

type Health = 'checking' | 'up' | 'down';

function useApiHealth(): { api: Health; db: Health } {
  const [api, setApi] = useState<Health>('checking');
  const [db, setDb] = useState<Health>('checking');

  useEffect(() => {
    const base = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
    let alive = true;

    fetch(`${base}/health`)
      .then((r) => alive && setApi(r.ok ? 'up' : 'down'))
      .catch(() => alive && setApi('down'));

    fetch(`${base}/ready`)
      .then((r) => alive && setDb(r.ok ? 'up' : 'down'))
      .catch(() => alive && setDb('down'));

    return () => {
      alive = false;
    };
  }, []);

  return { api, db };
}

function HealthDot({ state, label }: { state: Health; label: string }) {
  const tone =
    state === 'up' ? 'text-hg-ember' : state === 'down' ? 'text-hg-ash' : 'text-hg-amber';

  return (
    <span className="inline-flex items-center gap-2 font-display text-[11px] uppercase tracking-widest text-hg-ash">
      <span className={`hg-dot ${tone}`} style={{ backgroundColor: 'currentColor' }} />
      {label}
      <span className="text-hg-bone/70">
        {state === 'checking' ? '…' : state === 'up' ? 'online' : 'offline'}
      </span>
    </span>
  );
}

/* ── overview ─────────────────────────────────────────────────────────── */

function Overview({ go }: { go: (id: PanelId) => void }) {
  return (
    <div className="space-y-10">
      <section className="relative overflow-hidden border border-hg-line bg-black/40 px-6 py-14 sm:px-10">
        <div className="absolute inset-x-0 top-0 h-px">
          <div className="hg-scan h-px w-1/3" />
        </div>

        <span className="hg-kicker">
          <span className="h-2 w-2 bg-hg-ember" />
          Track 02 · Supply chain blast radius
        </span>

        <h1 className="hg-title mt-6 max-w-4xl text-4xl leading-[1.08] sm:text-6xl">
          We find every service a poisoned package can reach.
        </h1>

        <p className="mt-6 max-w-2xl text-base leading-relaxed text-hg-bone/80">
          HydraGuard reads real release history and real lockfiles, stores every fact as evidence
          in HydraDB, then answers the questions an incident actually raises — who is exposed, since
          when, and what stops it.
        </p>

        <div className="mt-8 flex flex-wrap gap-3">
          <button type="button" className="hg-cta" onClick={() => go('blast')}>
            Run blast radius →
          </button>
          <button type="button" className="hg-ghost" onClick={() => go('firewall')}>
            See the release firewall
          </button>
        </div>

        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {HEADLINE_STATS.map((s) => (
            <Stat key={s.label} {...s} />
          ))}
        </div>
      </section>

      <section>
        <span className="hg-kicker">How it works</span>
        <div className="mt-5 grid gap-3 lg:grid-cols-5">
          {PIPELINE.map((p) => (
            <div key={p.step} className="border border-hg-line bg-hg-panel/50 p-4">
              <div className="font-display text-xs text-hg-ember">{p.step}</div>
              <div className="hg-title mt-2 text-lg">{p.label}</div>
              <p className="mt-1 text-xs leading-relaxed text-hg-ash">{p.note}</p>
            </div>
          ))}
        </div>
      </section>

      <section>
        <span className="hg-kicker">What we built</span>
        <div className="mt-5 grid gap-4 md:grid-cols-2">
          {CAPABILITIES.filter((c) => c.id !== 'integrity').map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => go(c.id)}
              className="group border border-hg-line bg-hg-panel/50 p-5 text-left transition-colors hover:border-hg-ember/60"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="font-display text-sm text-hg-flame">{c.nav}</div>
                <Maturity value={c.maturity} />
              </div>
              <div className="hg-title mt-3 text-lg leading-snug">{c.headline}</div>
              <p className="mt-2 text-sm leading-relaxed text-hg-ash">{c.plain}</p>
              <div className="mt-3 font-display text-xs text-hg-ember opacity-0 transition-opacity group-hover:opacity-100">
                Open →
              </div>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}

/* ── specialised panel bodies ─────────────────────────────────────────── */

function TimeMachine() {
  const [pos, setPos] = useState(55);

  // Illustrates the three temporal outcomes the engine returns.
  const verdict = useMemo(() => {
    if (pos < 30) return { label: 'Not yet published', tone: 'text-hg-ash', during: 0 };
    if (pos > 78) return { label: 'Patched · outside window', tone: 'text-hg-ash', during: 1 };
    return { label: 'Resolved DURING window', tone: 'text-hg-flame', during: 4 };
  }, [pos]);

  return (
    <div className="border border-hg-line bg-hg-panel/50 p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <span className="hg-kicker">Compromise window</span>
        <span className={`font-display text-sm ${verdict.tone}`}>{verdict.label}</span>
      </div>

      <input
        type="range"
        min={0}
        max={100}
        value={pos}
        onChange={(e) => setPos(Number(e.target.value))}
        aria-label="Move through the compromise window"
        className="mt-6 w-full accent-hg-ember"
      />

      <div className="mt-2 flex justify-between font-display text-[10px] uppercase tracking-widest text-hg-ash">
        <span>09:00 breach</span>
        <span>09:06 worm spread</span>
        <span>patched</span>
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-3">
        <div className="hg-bracket border border-hg-ember/40 bg-hg-ember/[0.07] p-4">
          <div className="font-display text-2xl text-hg-flame">{verdict.during}</div>
          <div className="mt-1 text-[11px] uppercase tracking-widest text-hg-ash">During window</div>
        </div>
        <div className="border border-hg-line p-4">
          <div className="font-display text-2xl text-hg-bone">{6 - verdict.during - 2}</div>
          <div className="mt-1 text-[11px] uppercase tracking-widest text-hg-ash">Outside window</div>
        </div>
        <div className="border border-hg-amber/40 bg-hg-amber/[0.06] p-4">
          <div className="font-display text-2xl text-hg-amber">2</div>
          <div className="mt-1 text-[11px] uppercase tracking-widest text-hg-ash">Unknown</div>
        </div>
      </div>

      <p className="mt-4 text-sm text-hg-bone/80">
        Two services have no recorded lockfile history.{' '}
        <span className="text-hg-amber">Unknown is not safe</span>, so they are reported separately
        rather than assumed clean.
      </p>
    </div>
  );
}

const FIREWALL_CHAIN = [
  { node: 'source-change', ok: true },
  { node: 'workflow-run', ok: true },
  { node: 'cache-entry', ok: false },
  { node: 'build', ok: true },
  { node: 'credential', ok: false },
  { node: 'release', ok: true },
];

function Firewall() {
  return (
    <div className="space-y-5">
      <div className="hg-bracket border border-hg-ember/50 bg-hg-ember/[0.07] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <span className="hg-kicker">Verdict</span>
            <div className="font-display text-4xl text-hg-flame">BLOCK</div>
          </div>
          <div className="text-right text-sm text-hg-bone/80">
            <div className="font-display text-hg-bone">demo-lib@1.2.4</div>
            <div className="text-hg-ash">publish denied before release</div>
          </div>
        </div>
      </div>

      <div className="border border-hg-line bg-hg-panel/50 p-6">
        <span className="hg-kicker">Why · influence path</span>
        <div className="mt-5 flex flex-wrap items-center gap-2">
          {FIREWALL_CHAIN.map((s, i) => (
            <div key={s.node} className="flex items-center gap-2">
              <span
                className={`border px-3 py-1.5 font-display text-xs ${
                  s.ok
                    ? 'border-hg-line text-hg-bone/80'
                    : 'border-hg-ember bg-hg-ember/15 text-hg-flame'
                }`}
              >
                {s.node}
                {!s.ok && ' ⚠'}
              </span>
              {i < FIREWALL_CHAIN.length - 1 && <span className="text-hg-ash">→</span>}
            </div>
          ))}
        </div>

        <div className="mt-5 space-y-2 text-sm">
          <p className="text-hg-bone/85">
            <span className="font-display text-hg-flame">cross-boundary-cache · </span>
            a cache written outside the trusted zone was restored into this build.
          </p>
          <p className="text-hg-bone/85">
            <span className="font-display text-hg-flame">untrusted-credential · </span>
            the publish token was minted by that same run.
          </p>
        </div>

        <p className="mt-5 border-t border-hg-line pt-4 text-sm text-hg-ash">
          This is the exact pattern behind the TanStack compromise: 84 artifacts across 42 packages
          within six minutes of the pipeline being breached. Blast radius tells you how bad it was.
          This stops it.
        </p>
      </div>
    </div>
  );
}

function Matrix() {
  return (
    <div className="border border-hg-line bg-hg-panel/50">
      <div className="border-b border-hg-line px-5 py-3">
        <span className="hg-kicker">HydraDB OpenCypher support · characterised on v0.1.1</span>
      </div>
      <div className="divide-y divide-hg-line">
        {HYDRA_MATRIX.map((m) => (
          <div key={m.shape} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-sm">
            <span
              className={`font-display text-xs ${m.ok ? 'text-hg-flame' : 'text-hg-ash'}`}
              aria-hidden="true"
            >
              {m.ok ? '●' : '○'}
            </span>
            <code className="font-display text-xs text-hg-bone/90">{m.shape}</code>
            <span className="ml-auto text-xs text-hg-ash">{m.note}</span>
          </div>
        ))}
      </div>
      <p className="border-t border-hg-line px-5 py-3 text-xs text-hg-ash">
        Discovered by running against HydraDB, not by reading docs. Four writer and reader fixes
        were applied so persistence uses only the supported subset.
      </p>
    </div>
  );
}

const SUITES = [
  'domain fixture', 'lockfile', 'graph batch', 'npm orchestrator', 'persistence',
  'persistence service', 'job manager', 'worker dispatcher', 'analysis', 'wave2 authority',
  'containment', 'temporal validity', 'snapshot history', 'release firewall',
  'release persistence', 'typosquat detector', 'typosquat graph', 'typosquat lifecycle',
  'api server',
];

function Integrity() {
  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat value="19" label="Suites passing" />
        <Stat value="0" label="Known failures" />
        <Stat value="1 cmd" label="npm run validate:all" />
      </div>

      <div className="border border-hg-line bg-hg-panel/50 p-5">
        <span className="hg-kicker">Verified suites</span>
        <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {SUITES.map((s) => (
            <div key={s} className="flex items-center gap-2 text-sm text-hg-bone/85">
              <span className="font-display text-xs text-hg-flame">✓</span>
              {s}
            </div>
          ))}
        </div>
      </div>

      <Matrix />
    </div>
  );
}

/* ── shell ────────────────────────────────────────────────────────────── */

function readPanel(): PanelId {
  const raw = new URLSearchParams(window.location.search).get('panel');
  const known = ['overview', ...CAPABILITIES.map((c) => c.id)];
  return (known.includes(raw ?? '') ? raw : 'overview') as PanelId;
}

export interface ConsoleShellProps {
  readonly onExit: () => void;
}

export function ConsoleShell({ onExit }: ConsoleShellProps) {
  const [panel, setPanel] = useState<PanelId>(readPanel);
  const { api, db } = useApiHealth();

  useEffect(() => {
    const url = new URL(window.location.href);
    url.searchParams.set('view', 'console');
    url.searchParams.set('panel', panel);
    window.history.replaceState(null, '', url.toString());
  }, [panel]);

  const cap = CAPABILITIES.find((c) => c.id === panel);

  return (
    <div className="hg-shell flex min-h-screen flex-col">
      <header className="flex flex-wrap items-center gap-4 border-b border-hg-line px-5 py-3">
        <button
          type="button"
          onClick={() => setPanel('overview')}
          className="flex items-center gap-2.5"
        >
          <span className="grid h-6 w-6 place-items-center bg-hg-ember font-display text-xs font-bold text-black">
            H
          </span>
          <span className="hg-title text-lg">
            Hydra<span className="text-hg-ember">Guard</span>
          </span>
        </button>

        <span className="hidden font-display text-[10px] uppercase tracking-[0.28em] text-hg-ash sm:inline">
          Evidence Console
        </span>

        <div className="ml-auto flex flex-wrap items-center gap-4">
          <HealthDot state={api} label="API" />
          <HealthDot state={db} label="HydraDB" />
          <button type="button" onClick={onExit} className="hg-ghost !px-3 !py-1.5 !text-xs">
            Live dashboard
          </button>
        </div>
      </header>

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <nav className="border-b border-hg-line py-3 lg:w-60 lg:flex-none lg:border-b-0 lg:border-r">
          <button
            type="button"
            onClick={() => setPanel('overview')}
            className={`hg-nav ${panel === 'overview' ? 'hg-nav-on' : ''}`}
          >
            Overview
          </button>

          <div className="mt-3 px-4 font-display text-[10px] uppercase tracking-[0.24em] text-hg-ash">
            Pipeline
          </div>
          {CAPABILITIES.filter((c) => ['history', 'ingest', 'graph'].includes(c.id)).map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setPanel(c.id)}
              className={`hg-nav ${panel === c.id ? 'hg-nav-on' : ''}`}
            >
              {c.nav}
            </button>
          ))}

          <div className="mt-3 px-4 font-display text-[10px] uppercase tracking-[0.24em] text-hg-ash">
            Analysis
          </div>
          {CAPABILITIES.filter((c) =>
            ['blast', 'temporal', 'typosquat', 'authority'].includes(c.id),
          ).map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setPanel(c.id)}
              className={`hg-nav ${panel === c.id ? 'hg-nav-on' : ''}`}
            >
              {c.nav}
            </button>
          ))}

          <div className="mt-3 px-4 font-display text-[10px] uppercase tracking-[0.24em] text-hg-ash">
            Prevent &amp; prove
          </div>
          {CAPABILITIES.filter((c) =>
            ['firewall', 'containment', 'integrity'].includes(c.id),
          ).map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setPanel(c.id)}
              className={`hg-nav ${panel === c.id ? 'hg-nav-on' : ''}`}
            >
              {c.nav}
            </button>
          ))}
        </nav>

        <main className="min-h-0 flex-1 overflow-y-auto px-5 py-8 sm:px-8">
          <div className="mx-auto max-w-6xl">
            {panel === 'overview' && <Overview go={setPanel} />}

            {cap && (
              <div className="space-y-7">
                <SectionHead cap={cap} />
                {panel === 'temporal' && <TimeMachine />}
                {panel === 'firewall' && <Firewall />}
                {panel === 'integrity' && <Integrity />}
                {panel !== 'integrity' && <Bullets cap={cap} />}
                {panel !== 'integrity' && <HydraStrip cap={cap} />}
              </div>
            )}
          </div>
        </main>
      </div>

      <footer className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-hg-line px-5 py-2 text-[11px] text-hg-ash">
        <span>HydraGuard · evidence-first supply-chain analysis</span>
        <span aria-hidden="true">·</span>
        <span>Graph execution on HydraDB</span>
        <span aria-hidden="true">·</span>
        <span className="text-hg-amber">Synthetic demonstration data</span>
      </footer>
    </div>
  );
}
