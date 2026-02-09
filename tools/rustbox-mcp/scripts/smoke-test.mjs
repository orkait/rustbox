import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const rootDir = process.env.RUSTBOX_ROOT ?? "/mnt/c/codingFiles/orkait/rustbox";

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/server.js"],
  env: {
    ...process.env,
    RUSTBOX_ROOT: rootDir
  }
});

const client = new Client(
  { name: "rustbox-mcp-smoke", version: "0.1.0" },
  { capabilities: {} }
);

try {
  await client.connect(transport);
  const tools = await client.listTools();
  const toolNames = tools.tools.map((tool) => tool.name);
  console.log(`TOOLS:${toolNames.join(",")}`);

  const repoMap = await client.callTool({
    name: "repo_map",
    arguments: { maxFiles: 3 }
  });
  const content =
    repoMap.content && repoMap.content[0] && repoMap.content[0].type === "text"
      ? repoMap.content[0].text
      : "";
  console.log(`REPO_MAP_SNIPPET:${content.slice(0, 220).replace(/\n/g, " ")}`);
} finally {
  await client.close();
}
