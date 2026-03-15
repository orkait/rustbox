import { Play, Loader2 } from "lucide-react";

interface SubmitButtonProps {
  onClick: () => void;
  loading: boolean;
  disabled?: boolean;
}

export function SubmitButton({ onClick, loading, disabled }: SubmitButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={loading || disabled}
      className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold px-5 py-2 rounded-lg transition-colors cursor-pointer"
    >
      {loading ? (
        <Loader2 className="w-5 h-5 animate-spin" />
      ) : (
        <Play className="w-5 h-5" />
      )}
      {loading ? "Running..." : "Run"}
    </button>
  );
}
