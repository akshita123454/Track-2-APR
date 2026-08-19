import type { IncidentSummary, AffectedVersionSummary } from '../lib/api-types';
import { formatTimestamp } from '../lib/formatters';

interface Props {
  incident: IncidentSummary;
  affectedVersions: readonly AffectedVersionSummary[];
}

export function IncidentHeader({ incident, affectedVersions }: Props) {
  return (
    <div className="flex justify-between items-start">
      <div>
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-2xl font-semibold tracking-tight">{incident.title}</h1>
          <span className={`hydra-badge border ${
            incident.status === 'active' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
            incident.status === 'contained' ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :
            'bg-gray-500/10 text-gray-400 border-gray-500/30'
          }`}>
            {incident.status.toUpperCase()}
          </span>
          {incident.synthetic && (
            <span className="hydra-badge bg-purple-500/10 text-purple-400 border border-purple-500/30">
              SYNTHETIC
            </span>
          )}
        </div>
        <div className="text-sm text-hydra-muted">
          Active since: {formatTimestamp(incident.intervalStart)}
          {incident.intervalEnd && ` · Ended: ${formatTimestamp(incident.intervalEnd)}`}
        </div>
      </div>
      <div className="text-right">
        <div className="text-sm font-medium text-gray-400 mb-1">Affected Packages</div>
        <div className="flex flex-col gap-1.5 items-end">
          {affectedVersions.map((av) => (
            <span key={av.id} className="text-xs bg-hydra-surface border border-hydra-border px-2 py-1 rounded-md shadow-sm">
              <span className="text-gray-300">{av.packageName}</span>
              <span className="text-hydra-accent ml-1 font-medium">@{av.version}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
