import { SEVERITY_ORDER, type Finding, type Severity } from "../engine/types.js";
import type { ScanResult } from "./types.js";

const useColor = () => !!process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, s: string) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV_COLOR: Record<Severity, string> = { critical: "1;31", high: "31", medium: "33", low: "36" };
const sevLabel = (s: Severity) => paint(SEV_COLOR[s], `[${s.toUpperCase()}]`);

function wrap(text: string, indent: string, width = 92): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width - indent.length) {
      lines.push(line.trim());
      line = w;
    } else line += " " + w;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.map((l) => indent + l).join("\n");
}

export function formatFinding(f: Finding, origin?: string): string {
  const where = [f.location?.server && `server: ${f.location.server}`, f.location?.tool && `tool: ${f.location.tool}`, f.location?.line && `line ${f.location.line}`, f.location?.file && !f.location.file.startsWith("<") && `file: ${f.location.file.replace(process.env.HOME ?? "~~", "~")}`]
    .filter(Boolean)
    .join("  ");
  const out = [
    `${sevLabel(f.severity)} ${paint("1", f.title)}  ${paint("2", `${f.id} · confidence ${f.confidence} · ${f.evidenceKind}`)}`,
    where ? `    ${where}` : "",
    `    Evidence: ${f.evidence}`,
    wrap(`Why it matters: ${f.why}`, "    "),
    wrap(`Fix: ${f.fix}`, "    "),
  ];
  if (f.lab && origin) out.push(`    Learn the fix: ${origin}/labs/${f.lab}`);
  if (f.suppressed) out.push(`    Suppressed: ${f.suppressed.reason}`);
  return out.filter(Boolean).join("\n");
}

export function counts(findings: Finding[]): Record<Severity, number> {
  const c = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  for (const f of findings) c[f.severity]++;
  return c;
}

export function formatReport(r: ScanResult, origin?: string): string {
  const out: string[] = [];
  out.push(paint("1", `MCPVetter ${r.version}`) + paint("2", `  ${r.live ? "static + live" : "static"} scan · ${r.files.length} config file(s) · ${r.servers.length} server(s) · ${r.durationMs} ms`));
  out.push("");
  // Group by server, worst first.
  const groups = new Map<string, Finding[]>();
  for (const f of r.findings) {
    const key = f.location?.server ?? f.location?.file ?? "(config)";
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  const rank = (fs: Finding[]) => Math.min(...fs.map((f) => SEVERITY_ORDER.indexOf(f.severity)));
  const sorted = [...groups].sort((a, b) => rank(a[1]) - rank(b[1]));
  for (const [server, fs] of sorted) {
    out.push(paint("1", `■ ${server}`));
    for (const f of fs) out.push(formatFinding(f, origin), "");
  }
  const clean = r.servers.filter((s) => !groups.has(s.name)).map((s) => s.name);
  if (clean.length) out.push(paint("32", `✓ No findings: ${clean.join(", ")}`), "");
  if (r.suppressed.length) {
    out.push(paint("1", `Suppressed (${r.suppressed.length}), listed so a shared report cannot hide them:`));
    for (const f of r.suppressed) out.push(`  ${f.id} on ${f.location?.server ?? "?"}: ${f.suppressed?.reason}`);
    out.push("");
  }
  for (const n of r.notes) out.push(paint("2", `note: ${n}`));
  const c = counts(r.findings);
  out.push("");
  out.push(`Summary: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low${r.live ? "" : "  (run with --live to also inspect tool descriptions)"}`);
  return out.join("\n");
}

/** Shareable summary: counts, top fixes, scope. No code, no secret values, no file paths. */
export function shareableSummary(r: ScanResult): string {
  const c = counts(r.findings);
  const top = [...new Map(r.findings.map((f) => [f.id, f])).values()].slice(0, 5);
  return [
    `MCPVetter ${r.version} scan (${r.live ? "static + live" : "static"}), ${r.startedAt.slice(0, 10)}`,
    `Scope: ${r.servers.length} MCP servers across ${new Set(r.files.map((f) => f.client)).size} client(s)`,
    `Findings: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low${r.suppressed.length ? `, ${r.suppressed.length} suppressed` : ""}`,
    ...(top.length ? ["Top fixes:", ...top.map((f) => `  - ${f.id} ${f.title}: ${f.fix.split(". ")[0]}.`)] : ["No findings."]),
  ].join("\n");
}
