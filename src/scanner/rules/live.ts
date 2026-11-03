import { evidence } from "../../engine/redact.js";
import type { Hit, Rule } from "../../engine/types.js";
import { diffFingerprints, fingerprint } from "../fingerprint.js";
import type { ProbeResult, ScanContext } from "../types.js";

interface Described {
  server: string;
  kind: "tool" | "prompt" | "resource" | "parameter";
  name: string;
  text: string;
}

/** Every piece of text the model reads from a server: tool, parameter, prompt, resource descriptions. */
export function describedItems(p: ProbeResult): Described[] {
  const items: Described[] = [];
  for (const t of p.tools) {
    items.push({ server: p.server, kind: "tool", name: t.name, text: t.description });
    const props = (t.inputSchema as { properties?: Record<string, { description?: unknown }> } | undefined)?.properties ?? {};
    for (const [k, v] of Object.entries(props)) {
      if (typeof v?.description === "string") items.push({ server: p.server, kind: "parameter", name: `${t.name}.${k}`, text: v.description });
    }
  }
  for (const pr of p.prompts) items.push({ server: p.server, kind: "prompt", name: pr.name, text: pr.description });
  for (const r of p.resources) items.push({ server: p.server, kind: "resource", name: r.name, text: r.description });
  return items.filter((i) => i.text);
}

/** Strong signals: any one is enough. Each is an instruction aimed at the model, not documentation for a human. */
const STRONG: { re: RegExp; label: string }[] = [
  { re: /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|other)\s+(?:instructions|prompts|rules)/i, label: "tells the model to ignore its instructions" },
  { re: /\b(?:do\s+not|don't|never)\s+(?:tell|mention|inform|reveal|show|disclose|notify)\b[^.]{0,40}\b(?:user|human)/i, label: "tells the model to hide something from the user" },
  { re: /\b(?:without|before)\s+(?:telling|informing|asking|notifying)\s+the\s+user\b/i, label: "tells the model to act without the user knowing" },
  { re: /(?:~|\$HOME|%USERPROFILE%)?[\\/]\.(?:ssh|aws|gnupg|kube|docker)\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.npmrc\b|\.netrc\b|\bcredentials\.json\b/i, label: "references credential files" },
  { re: /\b(?:read|cat|open|include|attach|pass|send|upload)\b[^.]{0,60}\b(?:mcp\.json|claude_desktop_config|\.env\b|\.cursor[\\/]mcp|\.claude\.json)/i, label: "asks the model to read MCP or env config" },
  { re: /\b(?:send|post|forward|upload|exfiltrate|transmit)\b[^.]{0,60}\b(?:to|at)\s+(?:https?:\/\/|[a-z0-9-]+\.[a-z]{2,}\/|\S+@\S+\.)/i, label: "asks the model to send data to an outside address" },
  { re: /\b(?:instead\s+of|rather\s+than)\s+(?:using\s+)?(?:the\s+)?[`"']?[\w.-]+[`"']?\s+tool\b[^.]{0,40}\b(?:always\s+)?(?:use|call)\b/i, label: "steers the model away from another tool" },
  { re: /\bwhen\s+(?:the\s+)?(?:user|model|assistant)\s+(?:calls?|uses?)\s+(?:the\s+)?[`"']?[\w.-]+[`"']?\s+tool\b/i, label: "rewrites how another tool behaves" },
];

/** Medium signals: two or more together, or one plus a hidden-instruction wrapper. */
const MEDIUM: { re: RegExp; label: string }[] = [
  { re: /<\s*(?:important|instructions?|system|secret|hidden|admin)\s*>/i, label: "hidden-instruction tag" },
  { re: /\b(?:this\s+is\s+)?(?:very\s+|extremely\s+)?important\s*[:!]/i, label: "urgent override wording" },
  { re: /\byou\s+(?:must|should)\s+(?:always|first|immediately)\s+(?:call|use|run|read|invoke)\b/i, label: "forces a tool call" },
  { re: /\b(?:side\s*note|sidenote)\b/i, label: "sidenote smuggling" },
  { re: /\b(?:the\s+user|they)\s+(?:will\s+not|won't|should\s+not|must\s+not)\s+(?:see|know|notice)/i, label: "concealment" },
  { re: /\bas\s+an?\s+(?:ai|assistant|language\s+model)\b/i, label: "addresses the model directly" },
  { re: /\b(?:system\s+prompt|developer\s+message)\b/i, label: "references the system prompt" },
];

export function poisonSignals(text: string): { strong: string[]; medium: string[] } {
  return {
    strong: STRONG.filter((s) => s.re.test(text)).map((s) => s.label),
    medium: MEDIUM.filter((s) => s.re.test(text)).map((s) => s.label),
  };
}

function excerptAround(text: string, labels: string[]): string {
  for (const s of [...STRONG, ...MEDIUM]) {
    if (!labels.includes(s.label)) continue;
    const m = text.match(s.re);
    if (m && m.index !== undefined) return evidence(text.slice(Math.max(0, m.index - 40), m.index + m[0].length + 60), 180);
  }
  return evidence(text, 180);
}

export const poisonRule: Rule<ScanContext> = {
  id: "MCP-POISON-001",
  title: "Tool description contains hidden instructions to the model",
  severity: "critical",
  confidence: "high",
  evidenceKind: "live",
  why: "The model reads every tool description as trusted context, even for tools it never calls. A description that tells it to read secrets, hide actions from you, or override other tools can hijack the whole session without you seeing anything in the chat.",
  fix: "Remove this server from your config now. If you used it, check what other tools it could have steered (file reads, network sends) and rotate any credentials those tools could reach. Report the server to its registry listing.",
  method: "Connects to each approved server, lists tools, prompts, and resources, and checks every description (including parameter descriptions) for instructions aimed at the model: ignore previous instructions, hide something from the user, read credential or MCP config files, send data to an outside address, or steer the model away from another tool. One strong signal gives Critical/High confidence; two medium signals (hidden-instruction tags, urgent override wording, forced tool calls, concealment) give High/Medium.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const p of ctx.live) {
      for (const item of describedItems(p)) {
        const { strong, medium } = poisonSignals(item.text);
        if (strong.length) {
          hits.push({ evidence: `${item.kind} ${item.name}: ${strong.join("; ")}: "${excerptAround(item.text, strong)}"`, location: { server: p.server, tool: item.name } });
        } else if (medium.length >= 2) {
          hits.push({ evidence: `${item.kind} ${item.name}: ${medium.join("; ")}: "${excerptAround(item.text, medium)}"`, location: { server: p.server, tool: item.name }, severity: "high", confidence: "medium" });
        }
      }
    }
    return hits;
  },
};

const INVISIBLE = /[\u{E0000}-\u{E007F}​-‏‪-‮⁠-⁤⁦-⁩﻿­]/u;

export const invisibleRule: Rule<ScanContext> = {
  id: "MCP-POISON-002",
  title: "Invisible characters hidden in tool metadata",
  severity: "high",
  confidence: "high",
  evidenceKind: "live",
  why: "Unicode tag characters, zero-width characters, and direction overrides are invisible in most UIs but still read by the model. There is no legitimate reason for them in a tool description, and they are a known way to smuggle instructions past human review.",
  fix: "Treat the server as untrusted: remove it, or pin a version whose metadata is clean and report the issue to the publisher.",
  method: "Scans tool names, descriptions, parameter descriptions, prompts, and resources for Unicode tag characters (U+E0000 to U+E007F), zero-width characters, bidirectional overrides and isolates, word joiners, BOM, and soft hyphens. Evidence shows the code points, not the hidden text.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const p of ctx.live) {
      const items = [...describedItems(p), ...p.tools.map((t) => ({ server: p.server, kind: "tool" as const, name: t.name, text: t.name }))];
      for (const item of items) {
        if (!INVISIBLE.test(item.text)) continue;
        const cps = [...new Set([...item.text].filter((ch) => INVISIBLE.test(ch)).map((ch) => `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`))];
        const tagCount = [...item.text].filter((ch) => (ch.codePointAt(0) ?? 0) >= 0xe0000 && (ch.codePointAt(0) ?? 0) <= 0xe007f).length;
        hits.push({
          evidence: `${item.kind} ${item.name}: ${cps.slice(0, 6).join(", ")}${tagCount ? ` (${tagCount} tag characters encode hidden text)` : ""}`,
          location: { server: p.server, tool: item.name },
          severity: tagCount ? "critical" : "high",
        });
      }
    }
    return hits;
  },
};

export const shadowRule: Rule<ScanContext> = {
  id: "MCP-SHADOW-001",
  title: "Two servers expose a tool with the same name",
  severity: "high",
  confidence: "medium",
  evidenceKind: "live",
  why: "When two servers offer the same tool name, the model can call the wrong one. A malicious server can register the name of a trusted tool (send_email, read_file) to intercept calls and data meant for the real one.",
  fix: "Disable one of the servers, or confirm both are trusted and that your client namespaces tool names per server.",
  method: "Compares tool names across every live-probed server (case-insensitive) and reports each name exposed by more than one server.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const owners = new Map<string, Set<string>>();
    for (const p of ctx.live) for (const t of p.tools) owners.set(t.name.toLowerCase(), new Set([...(owners.get(t.name.toLowerCase()) ?? []), p.server]));
    return [...owners]
      .filter(([, s]) => s.size > 1)
      .map(([tool, s]) => ({ evidence: `tool "${tool}" exposed by: ${[...s].join(", ")}`, location: { server: [...s].join(" + "), tool } }));
  },
};

export const driftRule: Rule<ScanContext> = {
  id: "MCP-DRIFT-001",
  title: "Server's tools changed since you approved them",
  severity: "high",
  confidence: "high",
  evidenceKind: "live",
  why: "A server can look clean when you install it and change its tool descriptions or permissions later. That silent change (a rug pull) is exactly what no one re-reviews, and the model trusts the new text immediately.",
  fix: "Review the before/after below. If you did not expect it, pin the server to the last version you trusted. If the change is fine, accept the new fingerprint with: mcpvetter accept <server> --reason \"...\"",
  method: "On the first approved live probe, stores a local fingerprint (SHA-256 of each tool's name, description, and input schema, plus prompts and resources) in ~/.mcpvetter/fingerprints.json. Later probes compare against it and classify drift: tool added, description changed, schema changed (High); prompts/resources changed (Medium); tool removed (Low). A changed description that also trips MCP-POISON-001 is Critical. Fingerprints never leave your machine.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const p of ctx.live) {
      if (!p.ok) continue;
      const before = ctx.baseline[p.identity];
      if (!before) continue;
      for (const d of diffFingerprints(before, fingerprint(p))) {
        const poisoned = d.after ? poisonSignals(d.after).strong.length > 0 : false;
        const severity = poisoned ? "critical" : d.kind === "tool-removed" ? "low" : d.kind.endsWith("s-changed") && !d.tool ? "medium" : "high";
        const ev =
          d.kind === "description-changed"
            ? `${d.tool}: description changed. before: "${evidence(d.before ?? "(not stored)", 80)}" after: "${evidence(d.after ?? "", 80)}"`
            : `${d.kind}${d.tool ? `: ${d.tool}` : ""} (baseline ${before.recordedAt.slice(0, 10)})`;
        hits.push({ evidence: ev, location: { server: p.server, tool: d.tool }, severity });
      }
    }
    return hits;
  },
};

export const LIVE_RULES: Rule<ScanContext>[] = [poisonRule, invisibleRule, shadowRule, driftRule];
