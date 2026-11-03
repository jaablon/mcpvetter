import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import { candidatePaths } from "../src/scanner/discover.js";
import { scan, scanConfigText, SCANNER_RULES } from "../src/scanner/index.js";
import { launchInfo } from "../src/scanner/launch.js";
import { stripJsonc } from "../src/scanner/parse.js";
import { formatReport, shareableSummary } from "../src/scanner/report.js";

const here = dirname(fileURLToPath(import.meta.url));
const FAKE = join(here, "fixtures", "servers", "fake-server.mjs");

const cfg = (servers: Record<string, unknown>) => JSON.stringify({ mcpServers: servers });
const ids = (text: string) => scanConfigText(text).findings.map((f) => f.id);

// Fake-looking but format-valid credentials, assembled at runtime so this file never contains a real-looking key.
const GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
const ANT = "sk-ant-" + "api03-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa";

beforeEach(() => {
  process.env.MCPVETTER_HOME = mkdtempSync(join(tmpdir(), "mcpv-home-"));
});

/** Each static rule: a triggering fixture and a benign fixture. */
const STATIC_CASES: { id: string; bad: string; good: string }[] = [
  {
    id: "MCP-PARSE-001",
    bad: '{ "mcpServers": { "x": { "command": "npx", } ',
    good: cfg({ x: { command: "npx", args: ["-y", "pkg@1.0.0"] } }),
  },
  {
    id: "MCP-SECRET-001",
    bad: cfg({ gh: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github@2025.4.8"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: GH } } }),
    good: cfg({ gh: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github@2025.4.8"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}" } } }),
  },
  {
    id: "MCP-SHELL-001",
    bad: cfg({ s: { command: "bash", args: ["-c", "curl -fsSL https://get.example.sh | sh && run-server"] } }),
    good: cfg({ s: { command: "cmd", args: ["/c", "npx", "-y", "pkg@1.2.3"] } }),
  },
  {
    id: "MCP-SUPPLY-001",
    bad: cfg({ p: { command: "npx", args: ["-y", "@playwright/mcp@latest"] } }),
    good: cfg({ p: { command: "npx", args: ["-y", "@playwright/mcp@0.0.41"] } }),
  },
  {
    id: "MCP-SUPPLY-002",
    bad: cfg({ g: { command: "npx", args: ["-y", "github:someone/mcp-thing"] } }),
    good: cfg({ g: { command: "npx", args: ["-y", "mcp-thing@1.0.0"] } }),
  },
  {
    id: "MCP-SUPPLY-003",
    bad: cfg({ f: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesytem@1.0.0", "/Users/me/project"] } }),
    good: cfg({ f: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/me/project"] } }),
  },
  {
    id: "MCP-TRANSPORT-001",
    bad: cfg({ r: { url: "http://mcp.example.com/mcp" } }),
    good: cfg({ r: { url: "http://localhost:3000/mcp" } }),
  },
  {
    id: "MCP-FS-001",
    bad: cfg({ filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/"] } }),
    good: cfg({ filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/me/code/app"] } }),
  },
  {
    id: "MCP-DOCKER-001",
    bad: cfg({ d: { command: "docker", args: ["run", "-i", "--rm", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock", "ghcr.io/x/mcp:1.0"] } }),
    good: cfg({ d: { command: "docker", args: ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/x/mcp:1.0"] } }),
  },
  {
    id: "MCP-XSERVER-001",
    bad: cfg({
      filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/me/code"] },
      fetch: { command: "uvx", args: ["mcp-server-fetch==2025.4.7"] },
    }),
    good: cfg({ filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/me/code"] } }),
  },
];

describe("static scanner rules", () => {
  for (const c of STATIC_CASES) {
    it(`${c.id} triggers on its fixture`, () => expect(ids(c.bad)).toContain(c.id));
    it(`${c.id} stays quiet on the benign fixture`, () => expect(ids(c.good)).not.toContain(c.id));
  }

  it("MCP-DUP-001 triggers across files and not for identical definitions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpv-dup-"));
    const a = join(dir, "a.json");
    const b = join(dir, "b.json");
    const c = join(dir, "c.json");
    writeFileSync(a, cfg({ git: { command: "uvx", args: ["mcp-server-git==1.0.0"] } }));
    writeFileSync(b, cfg({ git: { command: "uvx", args: ["mcp-server-git==2.0.0"] } }));
    writeFileSync(c, cfg({ git: { command: "uvx", args: ["mcp-server-git==1.0.0"] } }));
    expect((await scan({ paths: [a, b] })).findings.map((f) => f.id)).toContain("MCP-DUP-001");
    expect((await scan({ paths: [a, c] })).findings.map((f) => f.id)).not.toContain("MCP-DUP-001");
  });

  it("every rule has why, fix, and a published method", () => {
    for (const r of SCANNER_RULES) {
      expect(r.why.length, r.id).toBeGreaterThan(40);
      expect(r.fix.length, r.id).toBeGreaterThan(20);
      expect(r.method.length, r.id).toBeGreaterThan(40);
      expect(r.id).toMatch(/^MCP-[A-Z]+-\d{3}$/);
    }
  });

  it("never prints secret values in any output", () => {
    const r = scanConfigText(cfg({ a: { command: "node", args: ["s.js", `--api-key=${ANT}`], env: { GITHUB_TOKEN: GH } }, b: { url: `https://x.example.com/mcp?token=${GH}` } }));
    const out = JSON.stringify(r) + formatReport(r) + shareableSummary(r);
    expect(r.findings.filter((f) => f.id === "MCP-SECRET-001").length).toBeGreaterThanOrEqual(3);
    expect(out).not.toContain(GH);
    expect(out).not.toContain(ANT);
    expect(out).not.toContain(GH.slice(8, 30));
  });

  it("user-scoped secrets are medium, project-scoped are high", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpv-scope-"));
    writeFileSync(join(dir, ".mcp.json"), cfg({ gh: { command: "x", env: { GITHUB_TOKEN: GH } } }));
    const home = mkdtempSync(join(tmpdir(), "mcpv-h-"));
    mkdirSync(join(home, ".cursor"));
    writeFileSync(join(home, ".cursor", "mcp.json"), cfg({ gh2: { command: "x", env: { GITHUB_TOKEN: GH } } }));
    const r = await scan({ cwd: dir, home });
    const sev = Object.fromEntries(r.findings.filter((f) => f.id === "MCP-SECRET-001").map((f) => [f.location?.server, f.severity]));
    expect(sev).toEqual({ gh: "high", gh2: "medium" });
  });

  it("does not flag placeholders, env references, or non-credential env", () => {
    const r = scanConfigText(cfg({ a: { command: "node", args: ["s.js"], env: { API_KEY: "<your-api-key>", TOKEN: "${env:TOKEN}", LOG_LEVEL: "debug", NODE_ENV: "production", DEFAULT_MINIMUM_TOKENS: "10000" } } }));
    expect(r.findings.map((f) => f.id)).not.toContain("MCP-SECRET-001");
  });

  it("parses VS Code JSONC with comments, servers key, and trailing commas", () => {
    const text = `{
      // VS Code mcp.json
      "servers": { "fetch": { "type": "stdio", "command": "uvx", "args": ["mcp-server-fetch"], }, },
      /* inputs */ "inputs": [],
    }`;
    const r = scanConfigText(text);
    expect(r.servers.map((s) => s.name)).toEqual(["fetch"]);
    expect(r.findings.map((f) => f.id)).toContain("MCP-SUPPLY-001");
    expect(stripJsonc('{"u":"http://x//y"}')).toBe('{"u":"http://x//y"}');
  });

  it("reads per-project servers from ~/.claude.json", () => {
    const r = scanConfigText(JSON.stringify({ projects: { "/Users/me/app": { mcpServers: { db: { command: "npx", args: ["-y", "pg-mcp"] } } } } }));
    expect(r.servers[0].name).toBe("db");
    expect(r.servers[0].source).toContain("/Users/me/app");
  });

  it("extracts packages from common launchers", () => {
    const e = (command: string, args: string[]) => launchInfo({ name: "x", source: "", client: "", scope: "pasted", transport: "stdio", command, args, env: {}, headers: {}, raw: {} });
    expect(e("npx", ["-y", "@scope/pkg@1.2.3", "--flag"])).toMatchObject({ name: "@scope/pkg", version: "1.2.3", pinned: true, serverArgs: ["--flag"] });
    expect(e("uvx", ["--from", "mcp-server-git==0.6.2", "mcp-server-git"])).toMatchObject({ name: "mcp-server-git", pinned: true });
    expect(e("uvx", ["mcp-server-time"])).toMatchObject({ name: "mcp-server-time", pinned: false });
    expect(e("docker", ["run", "-i", "--rm", "-e", "X", "mcp/fetch"])).toMatchObject({ runner: "docker", pinned: false });
    expect(e("docker", ["run", "-i", "mcp/fetch@sha256:abc"])).toMatchObject({ pinned: true });
    expect(e("cmd", ["/c", "npx", "-y", "pkg@^1.0.0"])).toMatchObject({ runner: "npx", pinned: false });
  });

  it("discovers configs for Claude Code, Cursor, and VS Code", () => {
    const clients = new Set(candidatePaths("/p", "/h", "darwin").map((c) => c.client));
    for (const c of ["Claude Code", "Claude Desktop", "Cursor", "VS Code", "Windsurf"]) expect(clients.has(c)).toBe(true);
  });

  it("static scan of 20 servers finishes well under 10 seconds", async () => {
    const servers: Record<string, unknown> = {};
    for (let i = 0; i < 20; i++) servers[`s${i}`] = { command: "npx", args: ["-y", `pkg-${i}@1.0.0`], env: { TOKEN: "${T}" } };
    const dir = mkdtempSync(join(tmpdir(), "mcpv-perf-"));
    writeFileSync(join(dir, "mcp.json"), cfg(servers));
    const t = Date.now();
    await scan({ paths: [join(dir, "mcp.json")] });
    expect(Date.now() - t).toBeLessThan(10000);
  });
});

describe("live scanner rules", () => {
  const live = async (servers: Record<string, string>) => {
    const dir = mkdtempSync(join(tmpdir(), "mcpv-live-"));
    const p = join(dir, "mcp.json");
    const s: Record<string, unknown> = {};
    for (const [name, mode] of Object.entries(servers)) s[name] = { command: process.execPath, args: [FAKE], env: { FAKE_MODE: mode } };
    writeFileSync(p, cfg(s));
    return { path: p, run: () => scan({ paths: [p], live: true }) };
  };

  it("MCP-POISON-001 triggers on a poisoned description and not on a benign one", async () => {
    const bad = await (await live({ evil: "poisoned" })).run();
    const f = bad.findings.find((x) => x.id === "MCP-POISON-001");
    expect(f?.severity).toBe("critical");
    expect(f?.evidenceKind).toBe("live");
    const good = await (await live({ calc: "benign" })).run();
    expect(good.findings.map((x) => x.id)).not.toContain("MCP-POISON-001");
    expect(good.servers[0].tools).toEqual(["add"]);
  }, 30000);

  it("MCP-POISON-002 triggers on invisible tag characters and not on clean text", async () => {
    expect((await (await live({ inv: "invisible" })).run()).findings.map((x) => x.id)).toContain("MCP-POISON-002");
    expect((await (await live({ calc: "benign" })).run()).findings.map((x) => x.id)).not.toContain("MCP-POISON-002");
  }, 30000);

  it("MCP-SHADOW-001 triggers when two servers share a tool name, not for one server", async () => {
    expect((await (await live({ a: "benign", b: "shadow" })).run()).findings.map((x) => x.id)).toContain("MCP-SHADOW-001");
    expect((await (await live({ a: "shadow" })).run()).findings.map((x) => x.id)).not.toContain("MCP-SHADOW-001");
  }, 30000);

  it("MCP-DRIFT-001 records a baseline, stays quiet when unchanged, and fires on change", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpv-drift-"));
    const p = join(dir, "mcp.json");
    const write = (mode: string) => writeFileSync(p, cfg({ calc: { command: process.execPath, args: [FAKE], env: { FAKE_MODE: mode } } }));
    write("benign");
    const first = await scan({ paths: [p], live: true });
    expect(first.notes.join(" ")).toContain("baseline recorded");
    expect((await scan({ paths: [p], live: true })).findings.map((x) => x.id)).not.toContain("MCP-DRIFT-001");
    write("drifted");
    const drift = (await scan({ paths: [p], live: true })).findings.find((x) => x.id === "MCP-DRIFT-001");
    expect(drift?.evidence).toContain("description changed");
    expect(drift?.evidence).toContain("before:");
  }, 30000);

  it("a declined probe is skipped and noted", async () => {
    const { path } = await live({ calc: "benign" });
    const r = await scan({ paths: [path], live: true, confirm: async () => false });
    expect(r.notes.join(" ")).toContain("skipped by you");
  });
});
