import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';

import {
  ApiError,
  createNpmIngestion,
  fetchIngestionJob,
  fetchLiveBlastRadius,
  fetchPackageOverview,
  fetchTyposquattingFindings,
} from '../lib/api-client';

import type {
  IngestionJobResponse,
  LiveBlastRadiusResponse,
  PackageOverviewResponse,
  TyposquattingFindingSummary,
} from '../lib/api-types';

import type { PanelId } from './capabilities';

type InvestigationState = 'idle' | 'submitting' | 'polling' | 'reading' | 'ready' | 'failed';

interface PackageInvestigationProps {
  readonly onOpenPanel: (panel: PanelId) => void;
}

const PRESETS = ['axios', 'react', '@tanstack/react-router'] as const;

function terminal(status: IngestionJobResponse['status']): boolean {
  return status === 'completed' || status === 'partially-completed' || status === 'failed';
}

function formatDate(value: number | null): string {
  return value === null ? 'not recorded' : new Date(value).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

function statusTone(status: InvestigationState): string {
  if (status === 'ready') return 'text-hg-flame border-hg-ember/50 bg-hg-ember/10';
  if (status === 'failed') return 'text-red-300 border-red-400/40 bg-red-500/10';
  if (status === 'idle') return 'text-hg-ash border-hg-line';
  return 'text-hg-amber border-hg-amber/40 bg-hg-amber/10';
}

function Card({
  label,
  endpoint,
  children,
  tone = 'normal',
}: {
  readonly label: string;
  readonly endpoint: string;
  readonly children: ReactNode;
  readonly tone?: 'normal' | 'alert';
}) {
  return (
    <section className={`hg-bracket border p-5 ${tone === 'alert' ? 'border-hg-ember/45 bg-hg-ember/[0.055]' : 'border-hg-line bg-hg-panel/65'}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <h3 className="font-display text-sm text-hg-bone">{label}</h3>
        <code className="border border-hg-line bg-black/40 px-2 py-1 font-display text-[10px] text-hg-ash">{endpoint}</code>
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function Empty({ children }: { readonly children: React.ReactNode }) {
  return <p className="text-sm leading-relaxed text-hg-ash">{children}</p>;
}

function Telemetry({ overview }: { readonly overview: PackageOverviewResponse }) {
  const { hydraRead } = overview;
  return (
    <div className="flex flex-wrap gap-x-5 gap-y-2 border-t border-hg-line pt-4 font-display text-[10px] uppercase tracking-wider text-hg-ash">
      <span><b className="text-hg-ember">{hydraRead.engine}</b> execution</span>
      <span>{hydraRead.queryCount} bounded reads</span>
      <span>{hydraRead.rowsRead} rows verified</span>
      <span>{hydraRead.latencyMs} ms</span>
      <span className="text-hg-bone/70">epoch {new Date(hydraRead.readEpoch).toLocaleTimeString()}</span>
    </div>
  );
}

function InvestigationResults({
  overview,
  blast,
  findings,
  onOpenPanel,
}: {
  readonly overview: PackageOverviewResponse;
  readonly blast: LiveBlastRadiusResponse | null;
  readonly findings: readonly TyposquattingFindingSummary[];
  readonly onOpenPanel: (panel: PanelId) => void;
}) {
  const serviceDependents = overview.dependents.filter((entry) => entry.nodeKind === 'Service');

  return (
    <div className="mt-6 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4 border-y border-hg-line bg-black/40 px-4 py-3">
        <div>
          <span className="hg-kicker">Live package investigation</span>
          <h2 className="hg-title mt-1 text-2xl">{overview.packageName}</h2>
        </div>
        <div className="text-right font-display text-xs text-hg-ash">
          <div className="text-hg-bone">{overview.versions.length} observed versions</div>
          <div>{overview.dependents.length} exact graph dependents</div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Card label="01 · Identity & release history" endpoint="GET /packages/:name">
          {overview.versions.length === 0 ? <Empty>No persisted version is available yet.</Empty> : (
            <div className="space-y-2">
              {overview.versions.map((version) => (
                <div key={version.id} className="flex items-center justify-between border-b border-hg-line/70 pb-2 text-sm last:border-0">
                  <span className="font-display text-hg-flame">{overview.packageName}@{version.version}</span>
                  <span className="text-hg-ash">published {formatDate(version.publishedAt)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card label="02 · Depends on" endpoint="DECLARES_DEPENDENCY · registry evidence">
          {overview.declarations.length === 0 ? <Empty>No registry declarations were persisted for the returned versions.</Empty> : (
            <div className="space-y-2">
              {overview.declarations.map((dependency) => (
                <div key={`${dependency.sourceVersionId}-${dependency.packageName}`} className="flex flex-wrap items-center justify-between gap-2 border-b border-hg-line/70 pb-2 text-sm last:border-0">
                  <span className="font-display text-hg-bone">{dependency.packageName}</span>
                  <span className="text-hg-ash">{dependency.declaredRange} · {dependency.dependencyType}</span>
                </div>
              ))}
            </div>
          )}
          <p className="mt-3 text-xs text-hg-amber">Registry declaration = requested range, not proof of internal installation.</p>
        </Card>

        <Card label="03 · Your graph depends on this" endpoint="USED_BY → canonical DEPENDS_ON">
          {overview.dependents.length === 0 ? (
            <Empty>No exact lockfile-backed dependent is currently in your HydraDB graph. Ingest a service lockfile to turn registry facts into internal exposure proof.</Empty>
          ) : (
            <div className="space-y-2">
              {overview.dependents.map((dependent) => (
                <div key={`${dependent.rootVersionId}-${dependent.nodeId}`} className="border-b border-hg-line/70 pb-2 text-sm last:border-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-display text-hg-bone">{dependent.displayName}</span>
                    <span className="hg-chip !border-hg-line !text-[9px]">{dependent.nodeKind}{dependent.criticality ? ` · ${dependent.criticality}` : ''}</span>
                  </div>
                  <div className="mt-1 text-xs text-hg-ash">{dependent.lockfilePath ?? 'exact graph relationship'} · valid from {formatDate(dependent.validFrom)}</div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card label="04 · Timeline & incident window" endpoint="AFFECTS + ?asOf">
          {overview.incidents.length === 0 ? (
            <Empty>No persisted incident currently names one of these exact versions. Create an incident only when you have a verified advisory or analyst evidence; HydraGuard will then expose the time-machine and blast-radius views.</Empty>
          ) : (
            <div className="space-y-3">
              {overview.incidents.map((incident) => (
                <button key={incident.id} type="button" className="w-full border border-hg-line p-3 text-left transition-colors hover:border-hg-ember/60" onClick={() => onOpenPanel('temporal')}>
                  <div className="font-display text-sm text-hg-flame">{incident.title}</div>
                  <div className="mt-1 text-xs text-hg-ash">{formatDate(incident.intervalStart)} → {formatDate(incident.intervalEnd)} · {incident.status}</div>
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card label="05 · Typosquat radar" endpoint="GET /typosquatting/findings">
          {findings.length === 0 ? <Empty>No persisted typosquatting finding currently targets {overview.packageName}. A name is only confirmed after a real lockfile resolves the candidate.</Empty> : (
            <div className="space-y-2">
              {findings.map((finding) => (
                <div key={finding.findingId} className="border-b border-hg-line/70 pb-2 text-sm last:border-0">
                  <div className="font-display text-hg-flame">{finding.candidateName} <span className="text-hg-ash">→ {finding.status}</span></div>
                  <div className="mt-1 text-xs text-hg-ash">score {finding.score}/100 · {finding.transformations.join(', ')}</div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card label="06 · Authority pivot" endpoint="MAINTAINS">
          {overview.maintainers.length === 0 ? <Empty>No registry maintainer link is persisted for this package yet.</Empty> : (
            <div className="flex flex-wrap gap-2">
              {overview.maintainers.map((maintainer) => (
                <span key={maintainer.handle} className="border border-hg-ember/45 bg-hg-ember/[0.07] px-3 py-2 font-display text-xs text-hg-bone">
                  @{maintainer.handle}
                </span>
              ))}
            </div>
          )}
          {overview.authorityPackages.length === 0 ? <Empty>No other persisted package currently shares these maintainer links.</Empty> : (
            <div className="mt-3 space-y-1.5">
              {overview.authorityPackages.map((item) => (
                <div key={`${item.maintainerHandle}-${item.packageName}`} className="flex items-center justify-between text-xs text-hg-ash">
                  <span>@{item.maintainerHandle}</span><span className="font-display text-hg-bone">{item.packageName}</span>
                </div>
              ))}
            </div>
          )}
          <p className="mt-3 text-xs text-hg-ash">Maintainer links identify shared publishing authority; they are reachability context, not a compromise claim.</p>
        </Card>

        <Card label="07 · Confirmed blast radius" endpoint="GET /incidents/:id/blast-radius" tone={blast ? 'alert' : 'normal'}>
          {!blast ? (
            <Empty>Blast radius activates when an evidence-backed incident is linked to an exact package version. {serviceDependents.length > 0 ? `${serviceDependents.length} internal service relationship(s) are already available as exposure candidates.` : ''}</Empty>
          ) : (
            <div className="space-y-3">
              <div className="font-display text-2xl text-hg-flame">{blast.services.length} services · {blast.totalPathCount} proof paths</div>
              {blast.services.slice(0, 3).map((candidate) => (
                <div key={candidate.service.id} className="border-b border-hg-ember/25 pb-2 text-sm last:border-0">
                  <span className="font-display text-hg-bone">{candidate.service.name}</span>
                  <span className="ml-2 text-hg-ash">depth {candidate.minimumDepth} · {candidate.paths.length} path(s)</span>
                </div>
              ))}
              <button type="button" className="hg-ghost !px-3 !py-1.5 !text-xs" onClick={() => onOpenPanel('blast')}>Open full blast-radius evidence →</button>
            </div>
          )}
        </Card>

        <Card label="08 · Release firewall" endpoint="GET /release-influence/snapshots/:id/firewall">
          <div className="font-display text-lg text-hg-amber">INDEPENDENT PRE-PUBLISH GATE</div>
          <p className="mt-2 text-sm leading-relaxed text-hg-bone/80">The firewall evaluates a CI release-influence snapshot — source change → workflow → cache → credential → artifact → publish. Registry search never fabricates a release verdict without that provenance snapshot.</p>
          <button type="button" className="hg-ghost mt-4 !px-3 !py-1.5 !text-xs" onClick={() => onOpenPanel('firewall')}>Open firewall model →</button>
        </Card>
      </div>

      <Telemetry overview={overview} />
    </div>
  );
}

export function PackageInvestigation({ onOpenPanel }: PackageInvestigationProps) {
  const [query, setQuery] = useState('axios');
  const [state, setState] = useState<InvestigationState>('idle');
  const [job, setJob] = useState<IngestionJobResponse | null>(null);
  const [overview, setOverview] = useState<PackageOverviewResponse | null>(null);
  const [blast, setBlast] = useState<LiveBlastRadiusResponse | null>(null);
  const [findings, setFindings] = useState<readonly TyposquattingFindingSummary[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const runRef = useRef(0);

  const runInvestigation = useCallback(async (rawName: string) => {
    const packageName = rawName.trim();
    if (!packageName) {
      setMessage('Enter an npm package name first.');
      return;
    }

    const run = ++runRef.current;
    const controller = new AbortController();
    setState('submitting');
    setJob(null);
    setOverview(null);
    setBlast(null);
    setFindings([]);
    setMessage(null);

    try {
      const accepted = await createNpmIngestion(
        packageName,
        `console-${packageName.replace(/[^A-Za-z0-9._-]/g, '-')}-${Date.now()}`.slice(0, 80),
        controller.signal,
      );
      if (run !== runRef.current) return;

      setState('polling');
      let current: IngestionJobResponse;
      do {
        await new Promise((resolve) => window.setTimeout(resolve, 900));
        current = await fetchIngestionJob(accepted.ingestionId, controller.signal);
        if (run !== runRef.current) return;
        setJob(current);
      } while (!terminal(current.status));

      if (current.status === 'failed') {
        setState('failed');
        setMessage(current.errors?.[0] ?? 'The ingestion job failed before it could be verified.');
        return;
      }

      setState('reading');
      const nextOverview = await fetchPackageOverview(packageName, controller.signal);
      if (run !== runRef.current) return;
      setOverview(nextOverview);

      const [typosquatResult, blastResult] = await Promise.allSettled([
        fetchTyposquattingFindings(controller.signal),
        nextOverview.incidents.length > 0 ? fetchLiveBlastRadius(nextOverview.incidents[0].id, { signal: controller.signal }) : Promise.resolve(null),
      ]);

      if (run !== runRef.current) return;
      if (typosquatResult.status === 'fulfilled') {
        setFindings(typosquatResult.value.findings.filter((finding) => finding.targetName === packageName));
      }
      if (blastResult.status === 'fulfilled') setBlast(blastResult.value);
      setState('ready');
    } catch (error) {
      if (run !== runRef.current) return;
      setState('failed');
      setMessage(error instanceof ApiError ? `${error.code}: ${error.message}` : 'The package investigation could not be completed.');
    }
  }, []);

  useEffect(() => () => { runRef.current += 1; }, []);

  const label = useMemo(() => {
    if (state === 'submitting') return 'queueing npm collection';
    if (state === 'polling') return job ? `ingestion ${job.status}` : 'waiting for ingestion job';
    if (state === 'reading') return 'reading verified HydraDB graph';
    if (state === 'ready') return 'investigation complete';
    if (state === 'failed') return 'investigation needs attention';
    return 'ready for investigation';
  }, [job, state]);

  return (
    <section className="hg-bracket relative overflow-hidden border border-hg-ember/45 bg-black/70 p-5 sm:p-7">
      <div className="absolute inset-x-0 top-0 h-px"><div className="hg-scan h-px w-1/2" /></div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <span className="hg-kicker"><span className="h-2 w-2 bg-hg-ember" />Live HydraDB investigation</span>
          <h1 className="hg-title mt-3 text-2xl sm:text-3xl">Ask one package. Reveal the whole supply-chain picture.</h1>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-hg-bone/75">Collect real registry evidence, persist it in HydraDB, then separate declared dependencies from exact internal lockfile exposure.</p>
        </div>
        <span className={`hg-chip ${statusTone(state)}`}><span className="hg-dot" style={{ backgroundColor: 'currentColor' }} />{label}</span>
      </div>

      <form className="mt-6 flex flex-col gap-3 sm:flex-row" onSubmit={(event) => { event.preventDefault(); void runInvestigation(query); }}>
        <label className="flex min-w-0 flex-1 items-center gap-3 border border-hg-line bg-black/70 px-4 py-3 focus-within:border-hg-ember">
          <span className="font-display text-lg text-hg-ember">⌕</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} className="min-w-0 flex-1 bg-transparent font-display text-sm text-hg-bone outline-none placeholder:text-hg-ash" placeholder="axios or @tanstack/react-router" aria-label="npm package name" />
        </label>
        <button type="submit" className="hg-cta justify-center disabled:cursor-wait disabled:opacity-60" disabled={state === 'submitting' || state === 'polling' || state === 'reading'}>
          {state === 'submitting' || state === 'polling' || state === 'reading' ? 'INVESTIGATING…' : 'INVESTIGATE →'}
        </button>
      </form>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-hg-ash">
        <span className="font-display uppercase tracking-wider">Try:</span>
        {PRESETS.map((preset) => <button type="button" key={preset} className="border border-hg-line px-2 py-1 font-display text-[10px] text-hg-bone hover:border-hg-ember hover:text-hg-flame" onClick={() => { setQuery(preset); void runInvestigation(preset); }}>{preset}</button>)}
        {job && <span className="ml-auto font-display text-[10px]">job {job.ingestionId.slice(0, 8)} · {job.nodeCount ?? 0} nodes · {job.edgeCount ?? 0} edges</span>}
      </div>

      {message && <div className="mt-4 border border-red-400/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">{message}</div>}
      {overview && <InvestigationResults overview={overview} blast={blast} findings={findings} onOpenPanel={onOpenPanel} />}
    </section>
  );
}
