import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence, findSecret, isPlaceholder, maskValue, SECRET_NAME_RE } from "../../engine/redact.js";

const RUNNERS = new Set(["npx", "bunx", "pnpx", "uvx", "pipx"]);
const SHELLS = /^(?:sh|bash|zsh|dash|fish|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i;
const LOOPBACK = /^https?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(?::|\/|$)/i;

interface ServerDef {
  name: string;
  command?: string;
  args: string[];
  env: Record<string, string>;
  headers: Record<string, string>;
  url?: string;
}

/** Find the first balanced {...} JSON object in the text and parse it (tolerates // comments and trailing commas). */
function parseJsonish(code: string): unknown {
  const start = code.indexOf("{");
  if (start < 0) return undefined;
  let depth = 0;
  let inStr: string | null = null;
  for (let i = start; i < code.length; i++) {
    const ch = code[i];
    if (inStr) {
      if (ch === "\\") i++;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"') inStr = ch;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) {
        const raw = code
          .slice(start, i + 1)
          .replace(/^\s*\/\/.*$/gm, "")
          .replace(/,(\s*[}\]])/g, "$1");
        try {
          return JSON.parse(raw);
        } catch {
          return undefined;
        }
      }
    }
  }
  return undefined;
}

function asStrMap(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (v && typeof v === "object" && !Array.isArray(v)) {
    for (const [k, val] of Object.entries(v)) if (typeof val === "string") out[k] = val;
  }
  return out;
}

function collectServers(cfg: unknown): ServerDef[] {
  if (!cfg || typeof cfg !== "object") return [];
  const root = cfg as Record<string, unknown>;
  const containers = [root.mcpServers, root.servers, (root.mcp as Record<string, unknown> | undefined)?.servers, root["mcp.servers"]];
  const out: ServerDef[] = [];
  for (const c of containers) {
    if (!c || typeof c !== "object") continue;
    for (const [name, raw] of Object.entries(c as Record<string, unknown>)) {
      if (!raw || typeof raw !== "object") continue;
      const s = raw as Record<string, unknown>;
      out.push({
        name,
        command: typeof s.command === "string" ? s.command : undefined,
        args: Array.isArray(s.args) ? s.args.filter((a): a is string => typeof a === "string") : [],
        env: asStrMap(s.env),
        headers: asStrMap(s.headers),
        url: typeof s.url === "string" ? s.url : typeof s.serverUrl === "string" ? s.serverUrl : undefined,
      });
    }
  }
  return out;
}

function lineOf(lines: string[], needle: string, fallback: number): number {
  const i = lines.findIndex((l) => l.includes(needle));
  return i >= 0 ? i + 1 : fallback;
}

/** First positional argument (the package) for npx/uvx style runners. */
function packageArg(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--from" || a === "-p" || a === "--package") return args[i + 1];
    if (a.startsWith("-")) continue;
    return a;
  }
  return undefined;
}

function pinned(pkg: string, runner: string): boolean {
  if (/^(?:https?:|git\+|github:|file:|\.{0,2}\/)/.test(pkg)) return false;
  if (runner === "uvx" || runner === "pipx") return /==\d|@\d/.test(pkg);
  const at = pkg.lastIndexOf("@");
  if (at <= 0) return false;
  const version = pkg.slice(at + 1);
  return /^\d+\.\d+\.\d+/.test(version);
}

export const codeMcpConfig: Rule<CodeContext> = {
  id: "CODE-MCPCFG-001",
  title: "Risky MCP server configuration",
  severity: "high",
  confidence: "high",
  evidenceKind: "static",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  why:
    "An MCP server runs with your user's permissions and its tool descriptions go straight into the model's context. An unpinned package can change under you on the next launch, a key pasted into the config is readable by anything that reads the file, and a plain-HTTP or shell-wrapped server is an easy place for someone else's code to run.",
  fix:
    "Pin every package to an exact version (npx -y @scope/server@1.2.3, uvx package==1.2.3), reference secrets as ${ENV_VAR} instead of pasting values, use https:// for remote servers, launch the server binary directly instead of through sh -c, and re-scan after every update.",
  method:
    "Parses MCP configuration JSON found in the snippet (mcpServers, servers, mcp.servers) and flags: npx/bunx/uvx/pipx packages without an exact version (including @latest); secret-looking values in env, headers or args (known key formats, or long mixed values under a key/token/secret name) that are not ${VAR} references; remote url values over http:// to a non-loopback host; and commands run through a shell (sh/bash/cmd/powershell with -c, or a pipe to sh).",
  check(ctx) {
    if (!/mcpServers|"servers"\s*:|mcp\.servers/.test(ctx.code)) return [];
    const servers = collectServers(parseJsonish(ctx.code));
    const hits: Hit[] = [];
    for (const s of servers) {
      const nameLine = lineOf(ctx.lines, `"${s.name}"`, 1);
      const cmd = s.command?.split(/[\\/]/).pop() ?? "";
      if (RUNNERS.has(cmd)) {
        const pkg = packageArg(s.args);
        if (pkg && !pinned(pkg, cmd)) {
          hits.push({
            evidence: evidence(`${s.name}: ${s.command} ${s.args.join(" ")}`),
            location: { line: lineOf(ctx.lines, pkg, nameLine), server: s.name },
            severity: "medium",
            fixDetail: `Package "${pkg}" is not pinned to an exact version.`,
          });
        }
      }
      const homeRoot = s.args.find((a) => /^(?:\/|~\/?|\$HOME\/?|\$\{HOME\}\/?|\/Users\/[^/]+\/?|\/home\/[^/]+\/?|[A-Za-z]:\\(?:Users\\[^\\]+\\?)?)$/.test(a));
      if (homeRoot && /filesystem|file-?system|fs-?server|server-fs/i.test(`${s.name} ${s.args.join(" ")}`)) {
        hits.push({
          evidence: evidence(`${s.name}: ${s.command} ${s.args.join(" ")}`),
          location: { line: lineOf(ctx.lines, homeRoot, nameLine), server: s.name },
          severity: "medium",
          fixDetail: `The filesystem server can read "${homeRoot}" (your whole disk or home directory); limit it to the project folder it needs.`,
        });
      }
      const shellWrapped = (SHELLS.test(cmd) && s.args.some((a) => /^(?:-c|\/c|-Command)$/i.test(a))) || s.args.some((a) => /\|\s*(?:ba|z)?sh\b|curl\s+[^|]*\|/.test(a));
      if (shellWrapped) {
        hits.push({
          evidence: evidence(`${s.name}: ${s.command} ${s.args.join(" ")}`),
          location: { line: lineOf(ctx.lines, s.args[0] ?? s.name, nameLine), server: s.name },
          fixDetail: "The server is launched through a shell; run the server executable directly.",
        });
      }
      if (s.url && /^http:\/\//i.test(s.url) && !LOOPBACK.test(s.url)) {
        hits.push({
          evidence: evidence(`${s.name}: ${s.url}`),
          location: { line: lineOf(ctx.lines, s.url, nameLine), server: s.name },
          fixDetail: "Remote server uses plain http://; traffic and tokens can be read or altered in transit.",
        });
      }
      const secretPairs: [string, string][] = [
        ...Object.entries(s.env),
        ...Object.entries(s.headers),
        ...s.args.map((a, i): [string, string] => [s.args[i - 1] ?? `arg${i}`, a]),
      ];
      for (const [key, value] of secretPairs) {
        if (isPlaceholder(value)) continue;
        const bearer = value.replace(/^Bearer\s+/i, "");
        const known = findSecret(value);
        const named = SECRET_NAME_RE.test(key) && !isPlaceholder(bearer) && bearer.length >= 12 && /\d/.test(bearer) && /[A-Za-z]/.test(bearer) && !/^https?:/.test(bearer);
        if (!known && !named) continue;
        hits.push({
          evidence: evidence(`${s.name}: ${key}=${maskValue(value)}`),
          location: { line: lineOf(ctx.lines, key, nameLine), server: s.name },
          fixDetail: `A literal secret is stored in the config (${key}); reference it as \${${/^[A-Z_][A-Z0-9_]*$/.test(key) ? key : "ENV_VAR"}} and rotate the exposed value.`,
        });
      }
    }
    return hits;
  },
};
