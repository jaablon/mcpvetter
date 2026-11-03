import { readFileSync } from "node:fs";
import type { ConfigFile, ServerEntry, Transport } from "./types.js";

/** Strip // and /* *\/ comments and trailing commas (VS Code settings are JSONC). String-aware. */
export function stripJsonc(text: string): string {
  let out = "";
  let i = 0;
  let inStr = false;
  while (i < text.length) {
    const c = text[i];
    const n = text[i + 1];
    if (inStr) {
      out += c;
      if (c === "\\") {
        out += n ?? "";
        i += 2;
        continue;
      }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
      i++;
    } else if (c === "/" && n === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (c === "/" && n === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
    } else {
      out += c;
      i++;
    }
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function asStringRecord(v: unknown): Record<string, string> {
  if (!v || typeof v !== "object" || Array.isArray(v)) return {};
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (val === null || val === undefined) continue;
    out[k] = typeof val === "string" ? val : JSON.stringify(val);
  }
  return out;
}

function toEntry(
  name: string,
  raw: unknown,
  source: string,
  client: string,
  scope: ServerEntry["scope"],
): ServerEntry | { error: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { error: `server "${name}" is not an object` };
  }
  const r = raw as Record<string, unknown>;
  const url = (r.url ?? r.serverUrl ?? r.httpUrl) as unknown;
  const command = r.command as unknown;
  if (typeof command !== "string" && typeof url !== "string") {
    return { error: `server "${name}" has neither a command nor a url` };
  }
  let args: string[] = [];
  if (Array.isArray(r.args)) args = r.args.map((a) => (typeof a === "string" ? a : JSON.stringify(a)));
  else if (typeof r.args === "string") args = [r.args];

  const declared = typeof r.type === "string" ? r.type.toLowerCase() : typeof r.transport === "string" ? r.transport.toLowerCase() : "";
  let transport: Transport = "unknown";
  if (typeof command === "string") transport = "stdio";
  else if (declared === "sse") transport = "sse";
  else if (typeof url === "string") transport = "http";

  return {
    name,
    source,
    client,
    scope,
    transport,
    command: typeof command === "string" ? command : undefined,
    args,
    env: asStringRecord(r.env),
    url: typeof url === "string" ? url : undefined,
    headers: asStringRecord(r.headers),
    disabled: r.disabled === true || r.enabled === false,
    raw,
  };
}

/** Find every server map in a parsed config, regardless of which client wrote it. */
function serverMaps(json: Record<string, unknown>): { label?: string; map: Record<string, unknown> }[] {
  const maps: { label?: string; map: Record<string, unknown> }[] = [];
  const push = (m: unknown, label?: string) => {
    if (m && typeof m === "object" && !Array.isArray(m)) maps.push({ label, map: m as Record<string, unknown> });
  };
  push(json.mcpServers);
  push(json.servers);
  push(json["mcp.servers"]);
  if (json.mcp && typeof json.mcp === "object") push((json.mcp as Record<string, unknown>).servers);
  // ~/.claude.json keeps per-project ("local scope") servers under projects.<path>.mcpServers
  if (json.projects && typeof json.projects === "object") {
    for (const [p, proj] of Object.entries(json.projects as Record<string, unknown>)) {
      if (proj && typeof proj === "object") push((proj as Record<string, unknown>).mcpServers, p);
    }
  }
  return maps;
}

export interface ParseOutcome {
  file: ConfigFile;
  /** False when the file parsed but contains no MCP section at all (e.g. editor settings). */
  hasMcp: boolean;
  entryErrors: string[];
}

export function parseConfigText(
  text: string,
  source: string,
  client = "Unknown",
  scope: ServerEntry["scope"] = "pasted",
): ParseOutcome {
  const file: ConfigFile = { path: source, client, scope, servers: [] };
  let json: unknown;
  try {
    json = JSON.parse(stripJsonc(text));
  } catch (e) {
    file.error = `could not parse JSON: ${(e as Error).message}`;
    return { file, hasMcp: true, entryErrors: [] };
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    file.error = "config root is not a JSON object";
    return { file, hasMcp: true, entryErrors: [] };
  }
  let maps = serverMaps(json as Record<string, unknown>);
  // A pasted bare server map: { "name": { "command": ... } }
  if (maps.length === 0 && scope === "pasted") {
    const values = Object.values(json as Record<string, unknown>);
    if (values.length && values.every((v) => v && typeof v === "object" && ("command" in (v as object) || "url" in (v as object)))) {
      maps = [{ map: json as Record<string, unknown> }];
    }
  }
  const entryErrors: string[] = [];
  for (const { label, map } of maps) {
    const src = label ? `${source} (project ${label})` : source;
    for (const [name, raw] of Object.entries(map)) {
      const e = toEntry(name, raw, src, client, scope);
      if ("error" in e) entryErrors.push(`${src}: ${e.error}`);
      else file.servers.push(e);
    }
  }
  return { file, hasMcp: maps.length > 0, entryErrors };
}

export function parseConfigFile(path: string, client: string, scope: "user" | "project"): ParseOutcome {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    return {
      file: { path, client, scope, servers: [], error: `could not read file: ${(e as Error).message}` },
      hasMcp: true,
      entryErrors: [],
    };
  }
  if (!text.trim()) return { file: { path, client, scope, servers: [] }, hasMcp: false, entryErrors: [] };
  return parseConfigText(text, path, client, scope);
}
