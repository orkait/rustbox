import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { RustboxIndexer } from "./indexer.js";
import type { SymbolKind } from "./types.js";

const rootDir = path.resolve(process.env.RUSTBOX_ROOT ?? process.cwd());
const indexer = new RustboxIndexer(rootDir);

function asTextResponse(payload: unknown, isError = false): {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
} {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2)
      }
    ],
    ...(isError ? { isError: true } : {})
  };
}

async function withFreshIndex<T>(handler: () => Promise<T>): Promise<T> {
  await indexer.refreshIfNeeded();
  return handler();
}

async function main(): Promise<void> {
  const server = new McpServer({
    name: "rustbox-mcp",
    version: "0.1.0"
  });

  server.tool(
    "refresh_index",
    "Force a full re-index of the rustbox repository.",
    {
      force: z.boolean().optional().default(true)
    },
    async ({ force }) => {
      try {
        const result = await indexer.refreshIfNeeded(force);
        return asTextResponse(result);
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  server.tool(
    "index_status",
    "Return current indexing metadata and freshness details.",
    {},
    async () => {
      try {
        await indexer.refreshIfNeeded();
        return asTextResponse(indexer.getStatus());
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  server.tool(
    "repo_map",
    "Summarize repository structure, symbol inventory, and high-signal files.",
    {
      maxFiles: z.number().int().min(1).max(200).optional().default(30)
    },
    async ({ maxFiles }) => {
      try {
        const result = await withFreshIndex(async () => indexer.getRepoMap(maxFiles));
        return asTextResponse(result);
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  server.tool(
    "semantic_search",
    "Search chunks semantically with lightweight ranking over the local index.",
    {
      query: z.string().min(1),
      limit: z.number().int().min(1).max(40).optional().default(8),
      pathPrefix: z.string().optional(),
      includeContent: z.boolean().optional().default(false)
    },
    async ({ query, limit, pathPrefix, includeContent }) => {
      try {
        const result = await withFreshIndex(async () =>
          indexer.searchSemantic(query, limit, pathPrefix, includeContent)
        );
        return asTextResponse({ query, limit, matches: result });
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  server.tool(
    "symbol_search",
    "Find Rust symbols by name/signature and optional kind.",
    {
      query: z.string().min(1),
      kind: z
        .enum([
          "module",
          "function",
          "struct",
          "enum",
          "trait",
          "impl",
          "const",
          "static",
          "type"
        ])
        .optional(),
      limit: z.number().int().min(1).max(100).optional().default(20)
    },
    async ({ query, kind, limit }) => {
      try {
        const parsedKind = kind as SymbolKind | undefined;
        const result = await withFreshIndex(async () =>
          indexer.searchSymbols(query, parsedKind, limit)
        );
        return asTextResponse({ query, kind: parsedKind ?? null, limit, matches: result });
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  server.tool(
    "open_file_span",
    "Open a bounded line span from a workspace-relative file path.",
    {
      path: z.string().min(1),
      startLine: z.number().int().min(1).optional().default(1),
      endLine: z.number().int().min(1).optional().default(120)
    },
    async ({ path: filePath, startLine, endLine }) => {
      try {
        const result = await withFreshIndex(async () =>
          indexer.openFileSpan(filePath, startLine, endLine)
        );
        return asTextResponse(result);
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  server.tool(
    "git_recent_changes",
    "Return recent commits and touched paths for freshness-aware retrieval.",
    {
      limit: z.number().int().min(1).max(50).optional().default(10)
    },
    async ({ limit }) => {
      try {
        const result = await withFreshIndex(async () => indexer.getRecentChanges(limit));
        return asTextResponse(result);
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  server.tool(
    "dependency_trace",
    "Heuristic dependency view for a symbol (definitions, callers, callees, references).",
    {
      symbol: z.string().min(1),
      limit: z.number().int().min(1).max(100).optional().default(30)
    },
    async ({ symbol, limit }) => {
      try {
        const result = await withFreshIndex(async () =>
          Promise.resolve(indexer.traceDependency(symbol, limit))
        );
        return asTextResponse(result);
      } catch (error) {
        return asTextResponse(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[rustbox-mcp] ready: root=${rootDir}`);
}

main().catch((error) => {
  console.error(
    `[rustbox-mcp] fatal: ${error instanceof Error ? error.stack ?? error.message : String(error)}`
  );
  process.exit(1);
});
