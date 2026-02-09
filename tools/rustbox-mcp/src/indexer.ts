import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import type {
  DependencyTraceResult,
  IndexRefreshResult,
  RecentCommit,
  RepoMapResult,
  SemanticMatch,
  SymbolKind,
  SymbolMatch,
  SymbolRecord
} from "./types.js";

const execFileAsync = promisify(execFile);

const INDEX_EXTENSIONS = new Set([
  ".rs",
  ".toml",
  ".md",
  ".json",
  ".yaml",
  ".yml",
  ".sh",
  ".txt"
]);

const SKIP_DIRS = new Set([
  ".git",
  "target",
  "node_modules",
  "dist",
  "build",
  ".idea",
  ".vscode",
  ".mcp-cache"
]);

const STOP_WORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "for",
  "from",
  "has",
  "in",
  "is",
  "it",
  "mod",
  "of",
  "on",
  "or",
  "pub",
  "self",
  "that",
  "the",
  "this",
  "to",
  "use",
  "with"
]);

const RUST_KEYWORDS = new Set([
  "if",
  "else",
  "match",
  "loop",
  "while",
  "for",
  "return",
  "break",
  "continue",
  "Some",
  "None",
  "Ok",
  "Err"
]);

const MAX_FILE_BYTES = 1_500_000;
const CHUNK_SIZE = 70;
const CHUNK_STEP = 45;
const MAX_SPAN_LINES = 400;

interface FileSnapshot {
  file: string;
  absolutePath: string;
  mtimeMs: number;
  size: number;
  text: string;
  lines: string[];
}

interface ChunkRecord {
  id: string;
  file: string;
  startLine: number;
  endLine: number;
  text: string;
  tokenCounts: Map<string, number>;
  tokenCount: number;
  symbols: string[];
}

interface UseRecord {
  file: string;
  line: number;
  statement: string;
}

interface FunctionSpan {
  name: string;
  file: string;
  line: number;
  endLine: number;
  text: string;
}

function toPosix(value: string): string {
  return value.split(path.sep).join("/");
}

function hashString(input: string): string {
  let hash = 2166136261;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function normalizeRelPath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.?\//, "");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function tokenize(input: string): string[] {
  const normalized = input
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase();
  const tokens = normalized
    .split(/[^a-z0-9_]+/g)
    .filter((token) => token.length >= 2 && !STOP_WORDS.has(token));
  return tokens;
}

function countTokens(tokens: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const token of tokens) {
    counts.set(token, (counts.get(token) ?? 0) + 1);
  }
  return counts;
}

function preview(text: string, maxLength = 500): string {
  const compact = text.replace(/\s+/g, " ").trim();
  if (compact.length <= maxLength) {
    return compact;
  }
  return `${compact.slice(0, maxLength - 1)}…`;
}

export class RustboxIndexer {
  private readonly rootDir: string;

  private snapshots: FileSnapshot[] = [];
  private chunks: ChunkRecord[] = [];
  private symbols: SymbolRecord[] = [];
  private uses: UseRecord[] = [];
  private functionSpans: FunctionSpan[] = [];
  private docFreq = new Map<string, number>();
  private indexedAt = "";
  private gitHead: string | null = null;
  private fingerprint = "";

  public constructor(rootDir: string) {
    this.rootDir = path.resolve(rootDir);
  }

  public async refreshIfNeeded(force = false): Promise<IndexRefreshResult> {
    const [snapshots, gitHead] = await Promise.all([
      this.collectSnapshots(),
      this.readGitHead()
    ]);
    const fingerprint = this.computeFingerprint(snapshots, gitHead);

    if (!force && fingerprint === this.fingerprint) {
      return this.getRefreshResult(false);
    }

    this.rebuild(snapshots, gitHead);
    this.fingerprint = fingerprint;
    return this.getRefreshResult(true);
  }

  public getRepoMap(maxFiles = 30): RepoMapResult {
    const kindCounts: Record<string, number> = {};
    for (const symbol of this.symbols) {
      kindCounts[symbol.kind] = (kindCounts[symbol.kind] ?? 0) + 1;
    }

    const directoryCounts = new Map<string, number>();
    for (const snapshot of this.snapshots) {
      const directory = snapshot.file.includes("/")
        ? snapshot.file.slice(0, snapshot.file.indexOf("/"))
        : ".";
      directoryCounts.set(directory, (directoryCounts.get(directory) ?? 0) + 1);
    }

    const symbolsByFile = new Map<string, SymbolRecord[]>();
    for (const symbol of this.symbols) {
      const list = symbolsByFile.get(symbol.file) ?? [];
      list.push(symbol);
      symbolsByFile.set(symbol.file, list);
    }

    const topFiles = [...symbolsByFile.entries()]
      .sort((left, right) => right[1].length - left[1].length)
      .slice(0, Math.max(1, maxFiles))
      .map(([file, fileSymbols]) => ({
        file,
        symbolCount: fileSymbols.length,
        symbols: fileSymbols.slice(0, 8).map((item) => item.name)
      }));

    return {
      rootDir: this.rootDir,
      gitHead: this.gitHead,
      indexedAt: this.indexedAt,
      fileCount: this.snapshots.length,
      chunkCount: this.chunks.length,
      symbolCount: this.symbols.length,
      symbolKinds: kindCounts,
      topDirectories: [...directoryCounts.entries()]
        .sort((left, right) => right[1] - left[1])
        .slice(0, 20)
        .map(([directory, fileCount]) => ({ path: directory, fileCount })),
      topFiles
    };
  }

  public getStatus(): IndexRefreshResult {
    return this.getRefreshResult(false);
  }

  public searchSemantic(
    query: string,
    limit = 8,
    pathPrefix?: string,
    includeContent = false
  ): SemanticMatch[] {
    const trimmedQuery = query.trim();
    if (!trimmedQuery) {
      return [];
    }

    const queryTokens = tokenize(trimmedQuery);
    const queryLower = trimmedQuery.toLowerCase();
    const normalizedPrefix = pathPrefix ? normalizeRelPath(pathPrefix) : undefined;
    const totalChunks = this.chunks.length || 1;

    const scored = this.chunks
      .map((chunk) => {
        if (normalizedPrefix && !chunk.file.startsWith(normalizedPrefix)) {
          return null;
        }

        let score = 0;
        for (const token of queryTokens) {
          const tf = chunk.tokenCounts.get(token) ?? 0;
          if (tf === 0) {
            continue;
          }
          const df = this.docFreq.get(token) ?? 1;
          const idf = Math.log((1 + totalChunks) / (1 + df)) + 1;
          score += (1 + Math.log(tf)) * idf;
        }

        const chunkLower = chunk.text.toLowerCase();
        if (queryLower.length > 3 && chunkLower.includes(queryLower)) {
          score += 2.5;
        }
        if (chunk.file.toLowerCase().includes(queryLower)) {
          score += 1.5;
        }
        if (score <= 0) {
          return null;
        }

        return {
          score,
          file: chunk.file,
          startLine: chunk.startLine,
          endLine: chunk.endLine,
          symbols: chunk.symbols.slice(0, 8),
          excerpt: preview(chunk.text),
          content: includeContent ? chunk.text : undefined
        } as SemanticMatch;
      })
      .filter((item): item is SemanticMatch => item !== null)
      .sort((left, right) => right.score - left.score)
      .slice(0, Math.max(1, limit))
      .map((item) => ({
        ...item,
        score: Number(item.score.toFixed(4))
      }));

    return scored;
  }

  public searchSymbols(query: string, kind?: SymbolKind, limit = 20): SymbolMatch[] {
    const normalized = query.trim().toLowerCase();
    if (!normalized) {
      return [];
    }

    return this.symbols
      .map((symbol) => {
        if (kind && symbol.kind !== kind) {
          return null;
        }

        const nameLower = symbol.name.toLowerCase();
        const signatureLower = symbol.signature.toLowerCase();
        const fileLower = symbol.file.toLowerCase();
        let score = 0;

        if (nameLower === normalized) {
          score += 10;
        } else if (nameLower.startsWith(normalized)) {
          score += 6;
        } else if (nameLower.includes(normalized)) {
          score += 4;
        } else if (signatureLower.includes(normalized)) {
          score += 2;
        }

        if (fileLower.includes(normalized)) {
          score += 1;
        }
        if (score <= 0) {
          return null;
        }

        return {
          score,
          name: symbol.name,
          kind: symbol.kind,
          file: symbol.file,
          line: symbol.line,
          signature: symbol.signature
        } as SymbolMatch;
      })
      .filter((item): item is SymbolMatch => item !== null)
      .sort((left, right) => right.score - left.score)
      .slice(0, Math.max(1, limit))
      .map((item) => ({
        ...item,
        score: Number(item.score.toFixed(2))
      }));
  }

  public async openFileSpan(
    relPath: string,
    startLine = 1,
    endLine = startLine + 120
  ): Promise<{
    file: string;
    totalLines: number;
    startLine: number;
    endLine: number;
    content: string;
  }> {
    const normalizedRelPath = normalizeRelPath(relPath);
    const absolutePath = this.resolveWorkspacePath(normalizedRelPath);
    const content = await fs.readFile(absolutePath, "utf8");
    const lines = content.split(/\r?\n/);
    const totalLines = lines.length;

    const clampedStart = Math.min(Math.max(1, startLine), totalLines);
    const requestedEnd = Math.max(clampedStart, endLine);
    const clampedEnd = Math.min(
      requestedEnd,
      clampedStart + MAX_SPAN_LINES - 1,
      totalLines
    );

    const withLineNumbers = lines
      .slice(clampedStart - 1, clampedEnd)
      .map((line, index) => `${String(clampedStart + index).padStart(5, " ")} | ${line}`)
      .join("\n");

    return {
      file: normalizedRelPath,
      totalLines,
      startLine: clampedStart,
      endLine: clampedEnd,
      content: withLineNumbers
    };
  }

  public async getRecentChanges(limit = 10): Promise<{
    gitHead: string | null;
    commits: RecentCommit[];
  }> {
    const safeLimit = Math.min(Math.max(1, limit), 50);
    const gitHead = await this.readGitHead();
    if (!gitHead) {
      return { gitHead: null, commits: [] };
    }

    const args = [
      "-C",
      this.rootDir,
      "log",
      "--date=iso-strict",
      `-n`,
      String(safeLimit),
      "--name-only",
      "--pretty=format:%H%x1f%ad%x1f%an%x1f%s"
    ];

    const { stdout } = await execFileAsync("git", args);
    const commits: RecentCommit[] = [];
    let current: RecentCommit | null = null;

    for (const rawLine of stdout.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) {
        if (current) {
          commits.push(current);
          current = null;
        }
        continue;
      }

      if (line.includes("\u001f")) {
        if (current) {
          commits.push(current);
        }
        const [hash, date, author, subject] = line.split("\u001f");
        current = {
          hash,
          date,
          author,
          subject,
          files: []
        };
        continue;
      }

      if (current) {
        current.files.push(line);
      }
    }

    if (current) {
      commits.push(current);
    }

    return { gitHead, commits };
  }

  public traceDependency(symbol: string, limit = 30): DependencyTraceResult {
    const safeLimit = Math.max(1, limit);
    const normalized = symbol.trim();
    if (!normalized) {
      throw new Error("symbol must not be empty");
    }

    const symbolLeaf = normalized.includes("::")
      ? normalized.split("::").at(-1) ?? normalized
      : normalized;

    const exactDefinitions = this.symbols.filter((item) => item.name === symbolLeaf);
    const definitions = (
      exactDefinitions.length > 0
        ? exactDefinitions
        : this.symbols.filter((item) => item.name.includes(symbolLeaf))
    ).slice(0, safeLimit);

    const imports = this.uses
      .filter((item) => item.statement.includes(symbolLeaf))
      .slice(0, safeLimit);

    const wordPattern = new RegExp(`\\b${escapeRegExp(symbolLeaf)}\\b`);
    const callPattern = new RegExp(`\\b${escapeRegExp(symbolLeaf)}\\s*\\(`);

    const references: Array<{ file: string; line: number; context: string }> = [];
    for (const snapshot of this.snapshots) {
      for (let index = 0; index < snapshot.lines.length; index += 1) {
        const line = snapshot.lines[index];
        if (!wordPattern.test(line)) {
          continue;
        }
        references.push({
          file: snapshot.file,
          line: index + 1,
          context: preview(line, 220)
        });
        if (references.length >= safeLimit) {
          break;
        }
      }
      if (references.length >= safeLimit) {
        break;
      }
    }

    const callers = this.functionSpans
      .filter((item) => item.name !== symbolLeaf && callPattern.test(item.text))
      .slice(0, safeLimit)
      .map((item) => ({
        caller: item.name,
        file: item.file,
        line: item.line
      }));

    const calleeCount = new Map<string, number>();
    const targetSpans = this.functionSpans.filter((item) => item.name === symbolLeaf);
    const calleePattern = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;

    for (const span of targetSpans) {
      for (const match of span.text.matchAll(calleePattern)) {
        const callee = match[1];
        if (callee === symbolLeaf || RUST_KEYWORDS.has(callee)) {
          continue;
        }
        calleeCount.set(callee, (calleeCount.get(callee) ?? 0) + 1);
      }
    }

    const callees = [...calleeCount.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, safeLimit)
      .map(([callee, count]) => ({
        callee,
        count,
        definitions: this.symbols
          .filter((item) => item.name === callee)
          .slice(0, 5)
      }));

    return {
      symbol: normalized,
      definitions,
      callers,
      callees,
      imports,
      references,
      note: "Call relationships are heuristic (regex-based), optimized for fast context retrieval."
    };
  }

  private getRefreshResult(updated: boolean): IndexRefreshResult {
    return {
      updated,
      gitHead: this.gitHead,
      indexedAt: this.indexedAt,
      fileCount: this.snapshots.length,
      chunkCount: this.chunks.length,
      symbolCount: this.symbols.length
    };
  }

  private async collectSnapshots(): Promise<FileSnapshot[]> {
    const snapshots: FileSnapshot[] = [];
    await this.walkDir(this.rootDir, snapshots);
    snapshots.sort((left, right) => left.file.localeCompare(right.file));
    return snapshots;
  }

  private async walkDir(currentDir: string, snapshots: FileSnapshot[]): Promise<void> {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (this.shouldSkipDirectory(entry.name)) {
          continue;
        }
        await this.walkDir(path.join(currentDir, entry.name), snapshots);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const extension = path.extname(entry.name).toLowerCase();
      if (!INDEX_EXTENSIONS.has(extension)) {
        continue;
      }

      const absolutePath = path.join(currentDir, entry.name);
      const stat = await fs.stat(absolutePath);
      if (stat.size > MAX_FILE_BYTES) {
        continue;
      }

      let text: string;
      try {
        text = await fs.readFile(absolutePath, "utf8");
      } catch {
        continue;
      }

      const relative = toPosix(path.relative(this.rootDir, absolutePath));
      snapshots.push({
        file: relative,
        absolutePath,
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        text,
        lines: text.split(/\r?\n/)
      });
    }
  }

  private shouldSkipDirectory(name: string): boolean {
    if (SKIP_DIRS.has(name)) {
      return true;
    }
    return name.startsWith(".") && name !== ".cargo";
  }

  private computeFingerprint(files: FileSnapshot[], gitHead: string | null): string {
    const seed = [
      gitHead ?? "nogit",
      String(files.length),
      ...files.map((file) => `${file.file}:${Math.trunc(file.mtimeMs)}:${file.size}`)
    ].join("|");
    return hashString(seed);
  }

  private rebuild(files: FileSnapshot[], gitHead: string | null): void {
    const symbols: SymbolRecord[] = [];
    const uses: UseRecord[] = [];
    const functionSpans: FunctionSpan[] = [];
    const chunks: ChunkRecord[] = [];
    const docFreq = new Map<string, number>();

    for (const snapshot of files) {
      const parsed = this.parseRustMetadata(snapshot);
      symbols.push(...parsed.symbols);
      uses.push(...parsed.uses);
      functionSpans.push(...parsed.functionSpans);

      for (const chunk of this.chunkFile(snapshot, parsed.symbols)) {
        chunks.push(chunk);
        for (const token of chunk.tokenCounts.keys()) {
          docFreq.set(token, (docFreq.get(token) ?? 0) + 1);
        }
      }
    }

    this.snapshots = files;
    this.symbols = symbols;
    this.uses = uses;
    this.functionSpans = functionSpans;
    this.chunks = chunks;
    this.docFreq = docFreq;
    this.gitHead = gitHead;
    this.indexedAt = new Date().toISOString();
  }

  private parseRustMetadata(snapshot: FileSnapshot): {
    symbols: SymbolRecord[];
    uses: UseRecord[];
    functionSpans: FunctionSpan[];
  } {
    if (path.extname(snapshot.file) !== ".rs") {
      return { symbols: [], uses: [], functionSpans: [] };
    }

    const symbols: SymbolRecord[] = [];
    const uses: UseRecord[] = [];
    const functionSpans: FunctionSpan[] = [];

    const lines = snapshot.lines;
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("//")) {
        continue;
      }

      const lineNo = index + 1;

      const moduleMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (moduleMatch) {
        symbols.push({
          name: moduleMatch[1],
          kind: "module",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const functionMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (functionMatch) {
        symbols.push({
          name: functionMatch[1],
          kind: "function",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const structMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (structMatch) {
        symbols.push({
          name: structMatch[1],
          kind: "struct",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const enumMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (enumMatch) {
        symbols.push({
          name: enumMatch[1],
          kind: "enum",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const traitMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (traitMatch) {
        symbols.push({
          name: traitMatch[1],
          kind: "trait",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const implMatch = trimmed.match(/^(?:unsafe\s+)?impl(?:<[^>]*>)?\s*([^ {]*)/);
      if (implMatch) {
        const implName = implMatch[1] ? implMatch[1].replace(/\s+for\s+.*/, "") : "impl";
        symbols.push({
          name: implName || "impl",
          kind: "impl",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const constMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (constMatch) {
        symbols.push({
          name: constMatch[1],
          kind: "const",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const staticMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?static\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (staticMatch) {
        symbols.push({
          name: staticMatch[1],
          kind: "static",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const typeMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?type\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (typeMatch) {
        symbols.push({
          name: typeMatch[1],
          kind: "type",
          file: snapshot.file,
          line: lineNo,
          signature: trimmed
        });
      }

      const useMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?use\s+([^;]+);/
      );
      if (useMatch) {
        uses.push({
          file: snapshot.file,
          line: lineNo,
          statement: useMatch[1]
        });
      }
    }

    functionSpans.push(...this.parseFunctionSpans(snapshot));
    return { symbols, uses, functionSpans };
  }

  private parseFunctionSpans(snapshot: FileSnapshot): FunctionSpan[] {
    const spans: FunctionSpan[] = [];
    const lines = snapshot.lines;

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("//")) {
        continue;
      }

      const functionMatch = trimmed.match(
        /^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)/
      );
      if (!functionMatch) {
        continue;
      }

      let endLine = index + 1;
      let balance = 0;
      let sawBrace = false;
      const maxScan = Math.min(lines.length - 1, index + 800);

      for (let cursor = index; cursor <= maxScan; cursor += 1) {
        const candidate = lines[cursor];
        for (const char of candidate) {
          if (char === "{") {
            sawBrace = true;
            balance += 1;
          } else if (char === "}") {
            balance -= 1;
          }
        }

        endLine = cursor + 1;
        if (!sawBrace && candidate.includes(";")) {
          break;
        }
        if (sawBrace && balance <= 0) {
          break;
        }
      }

      spans.push({
        name: functionMatch[1],
        file: snapshot.file,
        line: index + 1,
        endLine,
        text: lines.slice(index, endLine).join("\n")
      });

      if (endLine > index + 1) {
        index = endLine - 1;
      }
    }

    return spans;
  }

  private chunkFile(snapshot: FileSnapshot, fileSymbols: SymbolRecord[]): ChunkRecord[] {
    const chunks: ChunkRecord[] = [];
    const lines = snapshot.lines;

    if (lines.length === 0) {
      return chunks;
    }

    for (let start = 0; start < lines.length; start += CHUNK_STEP) {
      const end = Math.min(lines.length, start + CHUNK_SIZE);
      const text = lines.slice(start, end).join("\n");
      const symbols = fileSymbols
        .filter((item) => item.line >= start + 1 && item.line <= end)
        .map((item) => item.name);
      const tokens = tokenize(`${snapshot.file}\n${text}\n${symbols.join(" ")}`);
      const tokenCounts = countTokens(tokens);

      chunks.push({
        id: `${snapshot.file}:${start + 1}-${end}`,
        file: snapshot.file,
        startLine: start + 1,
        endLine: end,
        text,
        tokenCounts,
        tokenCount: tokens.length,
        symbols
      });

      if (end >= lines.length) {
        break;
      }
    }

    return chunks;
  }

  private resolveWorkspacePath(relPath: string): string {
    const absolute = path.resolve(this.rootDir, relPath);
    const relative = path.relative(this.rootDir, absolute);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error(`Path escapes workspace root: ${relPath}`);
    }
    return absolute;
  }

  private async readGitHead(): Promise<string | null> {
    try {
      const { stdout } = await execFileAsync("git", [
        "-C",
        this.rootDir,
        "rev-parse",
        "HEAD"
      ]);
      const head = stdout.trim();
      return head || null;
    } catch {
      return null;
    }
  }
}
