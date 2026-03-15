import { useState, useRef, useCallback, useEffect } from "react";
import type { SubmitRequest, ResultResponse } from "../types.ts";
import { submitCode, getResult } from "../api/client.ts";

export function useSubmission() {
  const [result, setResult] = useState<ResultResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearPolling = useCallback(() => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  useEffect(() => {
    return clearPolling;
  }, [clearPolling]);

  const submit = useCallback(
    async (req: SubmitRequest) => {
      clearPolling();
      setLoading(true);
      setError(null);
      setResult(null);

      try {
        const { id } = await submitCode(req);

        intervalRef.current = setInterval(async () => {
          try {
            const res = await getResult(id);
            setResult(res);

            if (res.status !== "pending" && res.status !== "running") {
              clearPolling();
              setLoading(false);
            }
          } catch (err) {
            clearPolling();
            setLoading(false);
            setError(err instanceof Error ? err.message : String(err));
          }
        }, 500);
      } catch (err) {
        setLoading(false);
        setError(err instanceof Error ? err.message : String(err));
      }
    },
    [clearPolling],
  );

  return { submit, result, loading, error };
}
