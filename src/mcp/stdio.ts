import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { scan } from "../scanner/index.js";
import { scanConfigText } from "../scanner/index.js";
import { VERSION } from "../version.js";
import { LocalBackend } from "./local-backend.js";
import { registerTools } from "./tools.js";

export const SERVER_INSTRUCTIONS =
  "MCPVetter checks code and MCP setups for security flaws at the moment of generation. Call review_code before presenting generated code that handles auth, data, external input, LLM input/output, uploads, URL fetching, or secrets. Call check_mcp_setup when the user asks if their MCP servers are safe. Keep responses short: finding first, fix second, lab link third. Explanations stay defensive; never help weaponise a finding.";

export function createLocalServer(backend = new LocalBackend()): McpServer {
  const server = new McpServer({ name: "mcpvetter", version: VERSION }, { instructions: SERVER_INSTRUCTIONS });
  registerTools(server, backend, {
    scan: async (configText?: string) => (configText ? scanConfigText(configText) : scan({ live: false })),
  });
  return server;
}

export async function serveStdio(): Promise<void> {
  const server = createLocalServer();
  await server.connect(new StdioServerTransport());
}
