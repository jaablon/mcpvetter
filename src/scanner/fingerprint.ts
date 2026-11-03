import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ProbeResult, ServerFingerprint } from "./types.js";

export function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`)
    .join(",")}}`;
}

export const sha = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 32);

export function fingerprint(p: ProbeResult, keepDescriptions = true): ServerFingerprint {
  return {
    identity: p.identity,
    server: p.server,
    version: p.serverInfo?.version,
    recordedAt: new Date().toISOString(),
    tools: p.tools
      .map((t) => ({
        name: t.name,
        descriptionHash: sha(t.description),
        schemaHash: sha(stableStringify(t.inputSchema ?? {})),
        hash: sha(stableStringify({ n: t.name, d: t.description, s: t.inputSchema ?? {} })),
        // Kept locally so drift alerts can show a before/after diff. Never uploaded.
        description: keepDescriptions ? t.description : undefined,
      }))
      .sort((a, b) => a.name.localeCompare(b.name)),
    promptsHash: sha(stableStringify(p.prompts)),
    resourcesHash: sha(stableStringify(p.resources.map((r) => ({ n: r.name, u: r.uri, d: r.description })))),
  };
}

export function stateDir(): string {
  return process.env.MCPVETTER_HOME ?? join(homedir(), ".mcpvetter");
}

const baselinePath = () => join(stateDir(), "fingerprints.json");

export function loadBaseline(): Record<string, ServerFingerprint> {
  try {
    return JSON.parse(readFileSync(baselinePath(), "utf8"));
  } catch {
    return {};
  }
}

export function saveBaseline(b: Record<string, ServerFingerprint>): void {
  const p = baselinePath();
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(b, null, 2), { mode: 0o600 });
}

export type DriftKind = "tool-added" | "tool-removed" | "description-changed" | "schema-changed" | "prompts-changed" | "resources-changed";

export interface Drift {
  kind: DriftKind;
  tool?: string;
  before?: string;
  after?: string;
}

export function diffFingerprints(before: ServerFingerprint, after: ServerFingerprint): Drift[] {
  const out: Drift[] = [];
  const b = new Map(before.tools.map((t) => [t.name, t]));
  const a = new Map(after.tools.map((t) => [t.name, t]));
  for (const [name, t] of a) {
    const old = b.get(name);
    if (!old) out.push({ kind: "tool-added", tool: name });
    else {
      if (old.descriptionHash !== t.descriptionHash) out.push({ kind: "description-changed", tool: name, before: old.description, after: t.description });
      if (old.schemaHash !== t.schemaHash) out.push({ kind: "schema-changed", tool: name });
    }
  }
  for (const name of b.keys()) if (!a.has(name)) out.push({ kind: "tool-removed", tool: name });
  if (before.promptsHash !== after.promptsHash) out.push({ kind: "prompts-changed" });
  if (before.resourcesHash !== after.resourcesHash) out.push({ kind: "resources-changed" });
  return out;
}
