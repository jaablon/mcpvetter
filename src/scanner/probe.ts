import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { serverIdentity } from "./launch.js";
import type { ProbeResult, ServerEntry } from "./types.js";

/** Expand ${VAR} and ${env:VAR} the way clients do, from the current environment only. */
export function expandVars(v: string): string {
  return v.replace(/\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, name) => process.env[name] ?? m);
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: NodeJS.Timeout;
  return Promise.race([
    p.finally(() => clearTimeout(t)),
    new Promise<T>((_, rej) => {
      t = setTimeout(() => rej(new Error(`${what} timed out after ${ms / 1000}s`)), ms);
    }),
  ]);
}

/**
 * Inspection only: initialize, then tools/list, prompts/list, resources/list.
 * Never calls a tool. For stdio servers this does start the server process, exactly as
 * your client would, with a minimal environment (PATH/HOME etc.) plus the env the config declares.
 */
export async function probeServer(s: ServerEntry, timeoutMs = 15000): Promise<ProbeResult> {
  const result: ProbeResult = { server: s.name, identity: serverIdentity(s), ok: false, tools: [], prompts: [], resources: [] };
  const client = new Client({ name: "mcpvetter-probe", version: "0.1.0" }, { capabilities: {} });
  let transport: Transport;
  try {
    if (s.command) {
      const env: Record<string, string> = { ...getDefaultEnvironment() };
      for (const [k, v] of Object.entries(s.env)) env[k] = expandVars(v);
      transport = new StdioClientTransport({ command: s.command, args: s.args.map(expandVars), env, stderr: "ignore" });
    } else if (s.url) {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(s.headers)) headers[k] = expandVars(v);
      const url = new URL(expandVars(s.url));
      transport = s.transport === "sse" ? new SSEClientTransport(url, { requestInit: { headers } }) : new StreamableHTTPClientTransport(url, { requestInit: { headers } });
    } else {
      result.error = "no command or url";
      return result;
    }
    await withTimeout(client.connect(transport), timeoutMs, "initialize");
    result.serverInfo = client.getServerVersion();
    const caps = client.getServerCapabilities() ?? {};
    if (caps.tools) {
      const r = await withTimeout(client.listTools(), timeoutMs, "tools/list");
      result.tools = r.tools.map((t) => ({ name: t.name, description: t.description ?? "", inputSchema: t.inputSchema }));
    }
    if (caps.prompts) {
      const r = await withTimeout(client.listPrompts(), timeoutMs, "prompts/list").catch(() => ({ prompts: [] }));
      result.prompts = r.prompts.map((p) => ({ name: p.name, description: p.description ?? "" }));
    }
    if (caps.resources) {
      const r = await withTimeout(client.listResources(), timeoutMs, "resources/list").catch(() => ({ resources: [] }));
      result.resources = r.resources.map((x) => ({ name: x.name, uri: x.uri, description: x.description ?? "" }));
    }
    result.ok = true;
  } catch (e) {
    const msg = (e as Error).message ?? String(e);
    result.error = /401|unauthori[sz]ed/i.test(msg) ? "server requires sign-in; live probe skipped (static checks still ran)" : msg.slice(0, 200);
  } finally {
    await client.close().catch(() => undefined);
  }
  return result;
}
