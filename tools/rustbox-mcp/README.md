# rustbox-mcp

Local MCP server for `rustbox` with fast, token-efficient code retrieval.

## Why this exists

This server avoids loading the full repository into prompt context by exposing focused MCP tools:

- `repo_map` for fast structural overview
- `semantic_search` for ranked retrieval by intent
- `symbol_search` for Rust symbol lookup
- `open_file_span` for bounded file reads
- `dependency_trace` for heuristic caller/callee/reference tracing
- `git_recent_changes` for freshness checks

The index auto-refreshes when files or `git HEAD` change.

## Setup (WSL)

```bash
cd /mnt/c/codingFiles/orkait/rustbox/tools/rustbox-mcp
npm install
npm run build
```

## Run

```bash
cd /mnt/c/codingFiles/orkait/rustbox/tools/rustbox-mcp
RUSTBOX_ROOT=/mnt/c/codingFiles/orkait/rustbox npm start
```

## Smoke test

```bash
cd /mnt/c/codingFiles/orkait/rustbox/tools/rustbox-mcp
RUSTBOX_ROOT=/mnt/c/codingFiles/orkait/rustbox npm run smoke
```

## Codex MCP config example

Add an MCP entry pointing at the built server:

```toml
[mcp_servers.rustbox]
command = "node"
args = ["/mnt/c/codingFiles/orkait/rustbox/tools/rustbox-mcp/dist/server.js"]
env = { RUSTBOX_ROOT = "/mnt/c/codingFiles/orkait/rustbox" }
```

After editing MCP config, restart Codex.
