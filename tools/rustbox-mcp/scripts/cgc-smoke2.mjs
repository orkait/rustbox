import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "/mnt/c/codingFiles/orkait/rustbox/scripts/mcp/start-cgc-mcp.sh",
  args: [],
  env: { ...process.env },
});

const client = new Client(
  { name: "cgc-smoke", version: "0.1.0" },
  { capabilities: {} }
);

try {
  await client.connect(transport);

  const tools = await client.listTools();
  console.log("TOOLS_COUNT", tools.tools.length);

  const repos = await client.callTool({
    name: "list_indexed_repositories",
    arguments: {},
  });
  console.log("REPOS", JSON.stringify(repos.content?.[0] ?? null));

  const overall = await client.callTool({
    name: "get_repository_stats",
    arguments: {},
  });
  console.log("OVERALL", JSON.stringify(overall.content?.[0] ?? null));

  const stats = await client.callTool({
    name: "get_repository_stats",
    arguments: { repo_path: "/mnt/c/codingFiles/orkait/rustbox" },
  });
  console.log("STATS", JSON.stringify(stats.content?.[0] ?? null));
} finally {
  await client.close();
}
