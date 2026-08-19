import type { HydraReadTelemetry } from '../lib/api-types';

interface Props {
  telemetry: HydraReadTelemetry;
}

export function HydraTelemetry({ telemetry }: Props) {
  return (
    <div className="flex items-center gap-4 text-xs font-mono bg-hydra-surface border border-hydra-border px-3 py-1.5 rounded-lg">
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>
        <span className="text-emerald-500 font-bold tracking-widest text-[10px] mt-px">HYDRADB LIVE</span>
      </div>

      <div className="w-px h-4 bg-gray-700"></div>

      <div className="flex items-center gap-4 text-gray-400">
        <div className="flex items-center gap-1.5">
          <span className="text-gray-200 font-medium">{telemetry.latencyMs} ms</span>
        </div>
        <span className="text-gray-600">·</span>
        <div className="flex items-center gap-1.5">
          <span className="text-gray-200 font-medium">{telemetry.queryCount} queries</span>
        </div>
        <span className="text-gray-600">·</span>
        <div className="flex items-center gap-1.5">
          <span className="text-gray-200 font-medium">{telemetry.rowsRead} rows</span>
        </div>
      </div>

      <div className="w-px h-4 bg-gray-700"></div>

      <div className="text-[10px] text-gray-500 tracking-wide">
        Bounded multi-statement read
      </div>
    </div>
  );
}
