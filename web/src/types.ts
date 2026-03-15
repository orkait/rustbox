export interface SubmitRequest {
  language: string;
  code: string;
  stdin: string;
}

export interface SubmitResponse {
  id: string;
}

export interface ResultResponse {
  id: string;
  status: string;
  verdict: string | null;
  stdout: string | null;
  stderr: string | null;
  exit_code: number | null;
  time_ms: number | null;
  memory_kb: number | null;
  created_at: string;
  completed_at: string | null;
}
