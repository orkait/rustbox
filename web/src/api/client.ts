import type { SubmitRequest, SubmitResponse, ResultResponse } from "../types.ts";

export async function submitCode(req: SubmitRequest): Promise<SubmitResponse> {
  const res = await fetch("/api/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Submit failed (${res.status}): ${text}`);
  }
  return res.json() as Promise<SubmitResponse>;
}

export async function getResult(id: string): Promise<ResultResponse> {
  const res = await fetch(`/api/result/${encodeURIComponent(id)}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Get result failed (${res.status}): ${text}`);
  }
  return res.json() as Promise<ResultResponse>;
}

export async function getLanguages(): Promise<string[]> {
  const res = await fetch("/api/languages");
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Get languages failed (${res.status}): ${text}`);
  }
  return res.json() as Promise<string[]>;
}
