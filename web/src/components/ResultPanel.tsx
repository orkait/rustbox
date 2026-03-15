import {
  CheckCircle2,
  Clock,
  HardDrive,
  AlertCircle,
  Timer,
  Cpu,
  Loader2,
} from "lucide-react";
import type { ResultResponse } from "../types.ts";

interface ResultPanelProps {
  result: ResultResponse | null;
  loading: boolean;
  error?: string | null;
}

function verdictConfig(verdict: string | null) {
  switch (verdict) {
    case "AC":
      return {
        color: "bg-emerald-900/50 text-emerald-400 border-emerald-700",
        icon: CheckCircle2,
        label: "Accepted",
      };
    case "TLE":
      return {
        color: "bg-yellow-900/50 text-yellow-400 border-yellow-700",
        icon: Clock,
        label: "Time Limit Exceeded",
      };
    case "MLE":
      return {
        color: "bg-orange-900/50 text-orange-400 border-orange-700",
        icon: HardDrive,
        label: "Memory Limit Exceeded",
      };
    case "RE":
      return {
        color: "bg-red-900/50 text-red-400 border-red-700",
        icon: AlertCircle,
        label: "Runtime Error",
      };
    case "SIG":
      return {
        color: "bg-purple-900/50 text-purple-400 border-purple-700",
        icon: AlertCircle,
        label: "Killed by Signal",
      };
    case "IE":
      return {
        color: "bg-red-900/50 text-red-400 border-red-700",
        icon: AlertCircle,
        label: "Internal Error",
      };
    default:
      return {
        color: "bg-gray-800/50 text-gray-400 border-gray-700",
        icon: Loader2,
        label: verdict ?? "Pending",
      };
  }
}

export function ResultPanel({ result, loading, error }: ResultPanelProps) {
  if (error) {
    return (
      <div className="rounded-xl bg-red-950/30 border border-red-800 p-6">
        <div className="flex items-center gap-2 text-red-400">
          <AlertCircle className="w-5 h-5" />
          <span className="font-semibold">Error</span>
        </div>
        <p className="mt-2 text-red-300 text-sm">{error}</p>
      </div>
    );
  }

  if (loading && !result) {
    return (
      <div className="rounded-xl bg-gray-900 border border-gray-700 p-6 flex items-center justify-center gap-3 text-gray-400">
        <Loader2 className="w-5 h-5 animate-spin" />
        <span>Running submission...</span>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="rounded-xl bg-gray-900 border border-gray-700 p-6 text-gray-500 text-center text-sm">
        Submit code to see results
      </div>
    );
  }

  const config = verdictConfig(result.verdict);
  const VerdictIcon = config.icon;

  return (
    <div className="rounded-xl bg-gray-900 border border-gray-700 p-6 space-y-4">
      {/* Verdict badge */}
      <div className="flex items-center justify-between">
        <div
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border ${config.color}`}
        >
          <VerdictIcon className="w-4 h-4" />
          <span className="font-semibold text-sm">{config.label}</span>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4 text-sm text-gray-400">
          {result.time_ms !== null && (
            <div className="flex items-center gap-1">
              <Timer className="w-4 h-4" />
              <span>{result.time_ms} ms</span>
            </div>
          )}
          {result.memory_kb !== null && (
            <div className="flex items-center gap-1">
              <Cpu className="w-4 h-4" />
              <span>{result.memory_kb} KB</span>
            </div>
          )}
          {result.exit_code !== null && (
            <span>Exit: {result.exit_code}</span>
          )}
        </div>
      </div>

      {/* Stdout */}
      {result.stdout !== null && result.stdout.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Stdout
          </h3>
          <pre className="bg-gray-950 rounded-lg p-3 text-sm text-gray-200 font-mono overflow-x-auto whitespace-pre-wrap border border-gray-800">
            {result.stdout}
          </pre>
        </div>
      )}

      {/* Stderr */}
      {result.stderr !== null && result.stderr.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Stderr
          </h3>
          <pre className="bg-red-950/20 rounded-lg p-3 text-sm text-red-300 font-mono overflow-x-auto whitespace-pre-wrap border border-red-900/30">
            {result.stderr}
          </pre>
        </div>
      )}
    </div>
  );
}
