import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { redact, maskValue } from "../engine/redact.js";
import { sortFindings, toFinding, type Finding, type Rule } from "../engine/types.js";
import { VERSION } from "../version.js";
import { discover } from "./discover.js";
import { fingerprint, loadBaseline, saveBaseline, stateDir } from "./fingerprint.js";
import { parseConfigFile, parseConfigText } from "./parse.js";
import { probeServer } from "./probe.js";
import { LIVE_RULES } from "./rules/live.js";
import { STATIC_RULES } from "./rules/static.js";
import type { ConfigFile, ProbeResult, ScanContext, ScanResult, ServerEntry, Suppression } from "./types.js";

export const SCANNER_RULES: Rule<ScanContext>[] = [...STATIC_RULES, ...LIVE_RULES];

export function runRules(ctx: ScanContext, rules: Rule<ScanContext>[] = SCANNER_RULES): Finding[] {
  const out: Finding[] = [];
  for (const rule of rules) {
    if (rule.evidenceKind === "live" && ctx.live.length === 0) continue;
    for (const hit of rule.check(ctx)) out.push(toFinding(rule, hit));
  }
  return sortFindings(out);
}

/** Redact secret-shaped args and credential-like URL parts before anything is reported. */
export function redactArg(a: string): string {
  const r = redact(a).replace(/^(--?(?:api[-_]?key|token|secret|password|access[-_]?token)=)(.+)$/i, (_, k, v) => k + maskValue(v));
  return r.length > 120 ? r.slice(0, 117) + "…" : r;
}

export function redactUrl(u?: string): string | undefined {
  if (!u) return u;
  try {
    const url = new URL(u);
    if (url.password) url.password = "****";
    for (const [k, v] of url.searchParams) if (/key|token|secret|auth|password/i.test(k)) url.searchParams.set(k, maskValue(v));
    return redact(url.toString());
  } catch {
    return redact(u);
  }
}

function reportServer(s: ServerEntry, tools?: string[]): ScanResult["servers"][number] {
  return { name: s.name, client: s.client, source: s.source, transport: s.transport, command: s.command, args: s.args.map(redactArg), envNames: Object.keys(s.env), url: redactUrl(s.url), tools };
}

const suppressionsPath = () => join(stateDir(), "suppressions.json");

export function loadSuppressions(): Suppression[] {
  try {
    return JSON.parse(readFileSync(suppressionsPath(), "utf8"));
  } catch {
    return [];
  }
}

export function addSuppression(s: Omit<Suppression, "createdAt">): void {
  const all = loadSuppressions().filter((x) => !(x.id === s.id && x.server === s.server));
  all.push({ ...s, createdAt: new Date().toISOString() });
  mkdirSync(dirname(suppressionsPath()), { recursive: true });
  writeFileSync(suppressionsPath(), JSON.stringify(all, null, 2));
}

function applySuppressions(findings: Finding[], sup: Suppression[]): { active: Finding[]; suppressed: Finding[] } {
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    const s = sup.find((x) => x.id === f.id && (x.server === "*" || x.server === f.location?.server));
    if (s) suppressed.push({ ...f, suppressed: { reason: s.reason } });
    else active.push(f);
  }
  return { active, suppressed };
}

export interface ScanOptions {
  cwd?: string;
  home?: string;
  /** Explicit config paths (skips discovery when given). */
  paths?: string[];
  live?: boolean;
  /** Called before each live probe; return false to skip that server. */
  confirm?: (s: ServerEntry) => Promise<boolean>;
  /** Record a fingerprint baseline for servers that have none (first approved probe). */
  recordBaseline?: boolean;
  useSuppressions?: boolean;
  onProgress?: (msg: string) => void;
}

export function loadFiles(opts: Pick<ScanOptions, "cwd" | "home" | "paths">): { files: ConfigFile[]; parseErrors: ScanContext["parseErrors"] } {
  const candidates = opts.paths?.length
    ? opts.paths.map((p) => ({ path: p, client: "Explicit path", scope: "project" as const }))
    : discover(opts.cwd, opts.home);
  const files: ConfigFile[] = [];
  const parseErrors: ScanContext["parseErrors"] = [];
  for (const c of candidates) {
    const out = parseConfigFile(c.path, c.client, c.scope);
    if (!out.hasMcp && !opts.paths?.length) continue;
    files.push(out.file);
    for (const e of out.entryErrors) parseErrors.push({ source: c.path, message: e });
  }
  return { files, parseErrors };
}

export async function scan(opts: ScanOptions = {}): Promise<ScanResult> {
  const started = Date.now();
  const { files, parseErrors } = loadFiles(opts);
  const servers = files.flatMap((f) => f.servers);
  const notes: string[] = [];
  const live: ProbeResult[] = [];
  const baseline = loadBaseline();

  if (opts.live) {
    for (const s of servers.filter((x) => !x.disabled)) {
      if (opts.confirm && !(await opts.confirm(s))) {
        notes.push(`${s.name}: live probe skipped by you`);
        continue;
      }
      opts.onProgress?.(`probing ${s.name}…`);
      const r = await probeServer(s);
      if (!r.ok) notes.push(`${s.name}: ${r.error}`);
      live.push(r);
    }
  }

  const ctx: ScanContext = { files, parseErrors, servers, live: live.filter((l) => l.ok), baseline };
  const all = runRules(ctx);

  if (opts.live && opts.recordBaseline !== false) {
    let changed = false;
    for (const p of ctx.live) {
      if (!baseline[p.identity]) {
        baseline[p.identity] = fingerprint(p);
        changed = true;
        notes.push(`${p.server}: fingerprint baseline recorded (${p.tools.length} tools)`);
      }
    }
    if (changed) saveBaseline(baseline);
  }

  const { active, suppressed } = opts.useSuppressions === false ? { active: all, suppressed: [] } : applySuppressions(all, loadSuppressions());
  if (files.length === 0) notes.push("No MCP configuration found in the standard locations. Pass a path with --config <file>.");

  return {
    version: VERSION,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    live: !!opts.live,
    files: files.map((f) => ({ path: f.path, client: f.client, scope: f.scope, servers: f.servers.length, error: f.error })),
    servers: servers.map((s) => reportServer(s, live.find((l) => l.server === s.name && l.ok)?.tools.map((t) => t.name))),
    findings: active,
    suppressed,
    notes,
  };
}

/** Static scan of pasted config text (used by the remote MCP, which cannot read local files). */
export function scanConfigText(text: string, source = "<pasted>"): ScanResult {
  const started = Date.now();
  const out = parseConfigText(text, source, "Pasted", "pasted");
  const ctx: ScanContext = {
    files: [out.file],
    parseErrors: out.entryErrors.map((m) => ({ source, message: m })),
    servers: out.file.servers,
    live: [],
    baseline: {},
  };
  const findings = runRules(ctx);
  return {
    version: VERSION,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    live: false,
    files: [{ path: source, client: "Pasted", scope: "pasted", servers: out.file.servers.length, error: out.file.error }],
    servers: out.file.servers.map((s) => reportServer(s)),
    findings,
    suppressed: [],
    notes: out.file.servers.length === 0 && !out.file.error ? ["No MCP servers found in the pasted text."] : [],
  };
}

export { probeServer } from "./probe.js";
export { fingerprint, loadBaseline, saveBaseline } from "./fingerprint.js";
export type * from "./types.js";
