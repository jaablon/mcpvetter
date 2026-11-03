#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { reviewCode } from "./code/review.js";
import { getRuleMeta, allRuleMetas } from "./engine/registry.js";
import { atOrAbove, SEVERITY_ORDER, type Severity } from "./engine/types.js";
import { LocalBackend, apiConfig } from "./mcp/local-backend.js";
import { fingerprint, loadBaseline, saveBaseline, stateDir } from "./scanner/fingerprint.js";
import { addSuppression, loadFiles, redactArg, redactUrl, scan } from "./scanner/index.js";
import { probeServer } from "./scanner/probe.js";
import { formatFinding, formatReport, shareableSummary } from "./scanner/report.js";
import { VERSION } from "./version.js";

const HELP = `mcpvetter ${VERSION}: audit your MCP servers and AI-generated code

Usage:
  mcpvetter scan [--live] [--yes] [--config <file>]... [--json [file]] [--summary] [--fail-on <severity>]
  mcpvetter list [--config <file>]...          Inventory only, no findings
  mcpvetter explain <ID>                       Explain a finding ID (e.g. MCP-POISON-001)
  mcpvetter rules                              List every rule and what it checks
  mcpvetter suppress <ID> --server <name> --reason "<why>"
  mcpvetter accept <server> --reason "<why>"   Accept a server's new tool fingerprint after drift
  mcpvetter review <file>... [--json] [--fail-on <severity>]   Review code (needs an API key)
  mcpvetter auth <api-key>                     Save your API key to ~/.mcpvetter/config.json
  mcpvetter serve                              Run as a local MCP server over stdio

Exit codes: 0 = no findings at or above --fail-on (default high), 1 = findings at or above it, 2 = could not complete.
Static scans are local and offline. Nothing is sent anywhere unless you configure an API key.
--live starts each configured server (exactly as your AI client would) to read its tool list. It asks first.`;

function severityArg(v: unknown): Severity {
  const s = String(v ?? "high").toLowerCase() as Severity;
  if (!SEVERITY_ORDER.includes(s)) throw new Error(`--fail-on must be one of ${SEVERITY_ORDER.join(", ")}`);
  return s;
}

async function ask(q: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const a = (await rl.question(q)).trim().toLowerCase();
  rl.close();
  return a === "y" || a === "yes";
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      live: { type: "boolean" },
      yes: { type: "boolean", short: "y" },
      config: { type: "string", multiple: true },
      json: { type: "boolean" },
      out: { type: "string", short: "o" },
      summary: { type: "boolean" },
      "fail-on": { type: "string" },
      server: { type: "string" },
      reason: { type: "string" },
      language: { type: "string" },
    },
  });
  // `--json out.json` form: treat a following .json positional as the output file.
  let jsonOut = values.out;
  if (values.json && !jsonOut && positionals[0]?.endsWith(".json") && cmd === "scan") jsonOut = positionals.shift();
  const origin = apiConfig().origin;

  switch (cmd) {
    case "scan": {
      const failOn = severityArg(values["fail-on"]);
      const r = await scan({
        paths: values.config,
        live: values.live,
        confirm: values.live
          ? async (s) => {
              if (values.yes) return true;
              const what = s.command ? `run "${[s.command, ...s.args.map(redactArg)].join(" ").slice(0, 100)}"` : `connect to ${redactUrl(s.url)}`;
              return ask(`Probe "${s.name}"? This will ${what} and list its tools (no tool is called). [y/N] `);
            }
          : undefined,
        onProgress: (m) => process.stderr.write(`${m}\n`),
      });
      if (values.json) {
        const body = JSON.stringify(r, null, 2);
        if (jsonOut) writeFileSync(jsonOut, body);
        else process.stdout.write(body + "\n");
      }
      if (!values.json || jsonOut) console.log(values.summary ? shareableSummary(r) : formatReport(r, origin));
      if (r.files.length && r.files.every((f) => f.error)) return 2;
      return r.findings.some((f) => atOrAbove(f.severity, failOn)) ? 1 : 0;
    }
    case "list": {
      const { files } = loadFiles({ paths: values.config });
      if (!files.length) console.log("No MCP configuration found. Pass --config <file>.");
      for (const f of files) {
        console.log(`${f.client} · ${f.path}${f.error ? `  (error: ${f.error})` : ""}`);
        for (const s of f.servers) {
          const launch = redactUrl(s.url) ?? [s.command, ...s.args.map(redactArg)].join(" ");
          console.log(`  - ${s.name} [${s.transport}${s.disabled ? ", disabled" : ""}] ${launch.slice(0, 100)}${Object.keys(s.env).length ? `  env: ${Object.keys(s.env).join(", ")}` : ""}`);
        }
      }
      return 0;
    }
    case "explain": {
      const id = positionals[0]?.toUpperCase();
      const m = id ? getRuleMeta(id) : undefined;
      if (!m) {
        console.error(`Unknown ID "${positionals[0] ?? ""}". Run "mcpvetter rules" for the list.`);
        return 2;
      }
      console.log(`${m.id}: ${m.title}\nDefault severity: ${m.severity} · confidence ${m.confidence} · ${m.evidenceKind}\n\nWhy it matters: ${m.why}\n\nFix: ${m.fix}\n\nWhat this rule checks: ${m.method}${m.lab ? `\n\nLab: ${origin}/labs/${m.lab}` : ""}`);
      return 0;
    }
    case "rules": {
      for (const m of allRuleMetas()) console.log(`${m.id.padEnd(18)} ${m.severity.padEnd(9)} ${m.title}`);
      console.log(`\nFull methods: ${origin}/rules`);
      return 0;
    }
    case "suppress": {
      const id = positionals[0]?.toUpperCase();
      if (!id || !getRuleMeta(id) || !values.server || !values.reason) {
        console.error('Usage: mcpvetter suppress <ID> --server <name|*> --reason "<why>"');
        return 2;
      }
      addSuppression({ id, server: values.server, reason: values.reason });
      console.log(`Suppressed ${id} on ${values.server}. It will still be listed under "Suppressed" in every report.`);
      return 0;
    }
    case "accept": {
      const name = positionals[0];
      if (!name || !values.reason) {
        console.error('Usage: mcpvetter accept <server> --reason "<why>"');
        return 2;
      }
      const s = loadFiles({ paths: values.config }).files.flatMap((f) => f.servers).find((x) => x.name === name);
      if (!s) {
        console.error(`No configured server named "${name}".`);
        return 2;
      }
      const p = await probeServer(s);
      if (!p.ok) {
        console.error(`Could not probe ${name}: ${p.error}`);
        return 2;
      }
      const b = loadBaseline();
      b[p.identity] = { ...fingerprint(p), acceptedReason: values.reason };
      saveBaseline(b);
      mkdirSync(stateDir(), { recursive: true });
      writeFileSync(join(stateDir(), "accept.log"), `${new Date().toISOString()}\t${name}\t${values.reason.replace(/\s+/g, " ")}\n`, { flag: "a" });
      console.log(`Accepted new fingerprint for ${name} (${p.tools.length} tools). Reason logged to ~/.mcpvetter/accept.log.`);
      return 0;
    }
    case "review": {
      if (!positionals.length) {
        console.error("Usage: mcpvetter review <file>...");
        return 2;
      }
      const failOn = severityArg(values["fail-on"]);
      const backend = new LocalBackend();
      const a = await backend.authorize("review_code");
      if (!a.allowed) {
        console.error(a.message);
        return 2;
      }
      let worst = false;
      const all = [];
      for (const file of positionals) {
        const findings = reviewCode(readFileSync(file, "utf8"), { filename: file, language: values.language }).map((f) => ({ ...f, location: { ...f.location, file } }));
        all.push(...findings);
        if (findings.some((f) => atOrAbove(f.severity, failOn))) worst = true;
        if (!values.json) {
          console.log(`■ ${file}: ${findings.length ? `${findings.length} finding(s)` : "no findings"}`);
          for (const f of findings) console.log(formatFinding(f, origin) + "\n");
        }
      }
      await backend.recordHistory("review_code", all.map((f) => ({ id: f.id, severity: f.severity })));
      if (values.json) console.log(JSON.stringify({ version: VERSION, findings: all }, null, 2));
      return worst ? 1 : 0;
    }
    case "auth": {
      const key = positionals[0];
      if (!key || !/^mcpv_(?:live|test)_[A-Za-z0-9]{16,}$/.test(key)) {
        console.error(`Usage: mcpvetter auth <api-key>  (get one at ${origin}/account)`);
        return 2;
      }
      mkdirSync(stateDir(), { recursive: true });
      const p = join(stateDir(), "config.json");
      let cfg: Record<string, unknown> = {};
      try {
        cfg = JSON.parse(readFileSync(p, "utf8"));
      } catch {
        /* new file */
      }
      writeFileSync(p, JSON.stringify({ ...cfg, apiKey: key }, null, 2), { mode: 0o600 });
      console.log("Saved. The local MCP server and `mcpvetter review` will use this key.");
      return 0;
    }
    case "serve": {
      const { serveStdio } = await import("./mcp/stdio.js");
      await serveStdio();
      return -1; // keep running
    }
    case "--version":
    case "-v":
    case "version":
      console.log(VERSION);
      return 0;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      return 0;
    default:
      console.error(`Unknown command "${cmd}".\n\n${HELP}`);
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    if (code >= 0) process.exitCode = code;
  },
  (e) => {
    console.error(`mcpvetter: ${(e as Error).message}`);
    process.exitCode = 2;
  },
);
