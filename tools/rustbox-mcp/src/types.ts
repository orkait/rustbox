export type SymbolKind =
  | "module"
  | "function"
  | "struct"
  | "enum"
  | "trait"
  | "impl"
  | "const"
  | "static"
  | "type";

export interface SymbolRecord {
  name: string;
  kind: SymbolKind;
  file: string;
  line: number;
  signature: string;
}

export interface SemanticMatch {
  score: number;
  file: string;
  startLine: number;
  endLine: number;
  symbols: string[];
  excerpt: string;
  content?: string;
}

export interface SymbolMatch {
  score: number;
  name: string;
  kind: SymbolKind;
  file: string;
  line: number;
  signature: string;
}

export interface RepoMapResult {
  rootDir: string;
  gitHead: string | null;
  indexedAt: string;
  fileCount: number;
  chunkCount: number;
  symbolCount: number;
  symbolKinds: Record<string, number>;
  topDirectories: Array<{ path: string; fileCount: number }>;
  topFiles: Array<{ file: string; symbolCount: number; symbols: string[] }>;
}

export interface IndexRefreshResult {
  updated: boolean;
  gitHead: string | null;
  indexedAt: string;
  fileCount: number;
  chunkCount: number;
  symbolCount: number;
}

export interface RecentCommit {
  hash: string;
  date: string;
  author: string;
  subject: string;
  files: string[];
}

export interface DependencyTraceResult {
  symbol: string;
  definitions: SymbolRecord[];
  callers: Array<{ caller: string; file: string; line: number }>;
  callees: Array<{ callee: string; count: number; definitions: SymbolRecord[] }>;
  imports: Array<{ file: string; line: number; statement: string }>;
  references: Array<{ file: string; line: number; context: string }>;
  note: string;
}
