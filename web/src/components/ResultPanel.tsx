import {
  CheckCircle2,
  Clock,
  HardDrive,
  AlertCircle,
  Timer,
  Cpu,
  Loader2,
  Hash,
  Zap,
  Terminal,
  Code2,
  Calendar,
} from "lucide-react";
import type { ResultResponse } from "../types.ts";

function signalName(sig: number): string {
  const signals: Record<number, string> = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    6: "SIGABRT",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
  };
  return signals[sig] ?? `SIG${sig}`;
}

function formatMemory(kb: number): string {
  if (kb < 1024) return `${kb} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

function formatRelativeTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diffMs = now - then;
  if (diffMs < 0) return "just now";
  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function languageLabel(lang: string): string {
  const labels: Record<string, string> = {
    python: "Python",
    cpp: "C++",
    java: "Java",
  };
  return labels[lang] ?? lang;
}

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

        {loading && result.status === "running" && (
          <div className="flex items-center gap-1.5 text-sm text-gray-500">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>Running...</span>
          </div>
        )}
      </div>

      {/* Execution Details */}
      <div className="rounded-lg bg-gray-950 border border-gray-800 p-4">
        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
          Execution Details
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-3">
          {/* Language */}
          <div className="space-y-0.5">
            <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
              <Code2 className="w-3 h-3" />
              Language
            </div>
            <div className="text-sm text-gray-200">
              {languageLabel(result.language)}
            </div>
          </div>

          {/* Wall Time */}
          {result.wall_time_ms !== null && (
            <div className="space-y-0.5">
              <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                <Timer className="w-3 h-3" />
                Wall Time
              </div>
              <div className="text-sm text-gray-200">
                {result.wall_time_ms.toFixed(1)} ms
              </div>
            </div>
          )}

          {/* CPU Time */}
          {result.cpu_time_ms !== null && (
            <div className="space-y-0.5">
              <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                <Cpu className="w-3 h-3" />
                CPU Time
              </div>
              <div className="text-sm text-gray-200">
                {result.cpu_time_ms.toFixed(1)} ms
              </div>
            </div>
          )}

          {/* Fallback: time_ms if wall/cpu not available */}
          {result.wall_time_ms === null &&
            result.cpu_time_ms === null &&
            result.time_ms !== null && (
              <div className="space-y-0.5">
                <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                  <Timer className="w-3 h-3" />
                  Time
                </div>
                <div className="text-sm text-gray-200">
                  {result.time_ms.toFixed(1)} ms
                </div>
              </div>
            )}

          {/* Memory Peak */}
          {result.memory_kb !== null && (
            <div className="space-y-0.5">
              <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                <HardDrive className="w-3 h-3" />
                Memory Peak
              </div>
              <div className="text-sm text-gray-200">
                {formatMemory(result.memory_kb)}
              </div>
            </div>
          )}

          {/* Exit Code */}
          {result.exit_code !== null && (
            <div className="space-y-0.5">
              <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                <Terminal className="w-3 h-3" />
                Exit Code
              </div>
              <div
                className={`text-sm font-mono ${result.exit_code === 0 ? "text-emerald-400" : "text-red-400"}`}
              >
                {result.exit_code}
              </div>
            </div>
          )}

          {/* Signal */}
          {result.signal !== null && (
            <div className="space-y-0.5">
              <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                <Zap className="w-3 h-3" />
                Signal
              </div>
              <div className="text-sm text-red-400 font-mono">
                {signalName(result.signal)} ({result.signal})
              </div>
            </div>
          )}

          {/* Submission ID */}
          <div className="space-y-0.5">
            <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
              <Hash className="w-3 h-3" />
              Submission ID
            </div>
            <div className="text-sm text-gray-400 font-mono truncate" title={result.id}>
              {result.id.slice(0, 8)}
            </div>
          </div>

          {/* Submitted At */}
          <div className="space-y-0.5">
            <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
              <Calendar className="w-3 h-3" />
              Submitted
            </div>
            <div
              className="text-sm text-gray-400"
              title={new Date(result.created_at).toLocaleString()}
            >
              {formatRelativeTime(result.created_at)}
            </div>
          </div>

          {/* Completed At */}
          {result.completed_at !== null && (
            <div className="space-y-0.5">
              <div className="flex items-center gap-1 text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                <Clock className="w-3 h-3" />
                Completed
              </div>
              <div
                className="text-sm text-gray-400"
                title={new Date(result.completed_at).toLocaleString()}
              >
                {formatRelativeTime(result.completed_at)}
              </div>
            </div>
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

      {/* Error Message */}
      {result.error_message !== null && (
        <div>
          <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">
            Error
          </h3>
          <pre className="bg-red-950/30 rounded-lg p-3 text-sm text-red-300 font-mono overflow-x-auto whitespace-pre-wrap border border-red-800/40">
            {result.error_message}
          </pre>
        </div>
      )}
    </div>
  );
}
