import type { Finding } from "../engine/types.js";

export type Transport = "stdio" | "http" | "sse" | "unknown";

export interface ServerEntry {
  name: string;
  /** Config file this entry came from ("<pasted>" for pasted text). */
  source: string;
  client: string;
  /** user = lives in the home directory; project = lives in a project and is likely committed. */
  scope: "user" | "project" | "pasted";
  transport: Transport;
  command?: string;
  args: string[];
  /** Values are kept in memory for checks only. Reports use envNames + redacted evidence. */
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
  disabled?: boolean;
  raw: unknown;
}

export interface ConfigFile {
  path: string;
  client: string;
  scope: "user" | "project" | "pasted";
  servers: ServerEntry[];
  error?: string;
}

export interface ProbedTool {
  name: string;
  description: string;
  inputSchema: unknown;
}

export interface ProbeResult {
  server: string;
  identity: string;
  ok: boolean;
  error?: string;
  serverInfo?: { name?: string; version?: string };
  tools: ProbedTool[];
  prompts: { name: string; description: string }[];
  resources: { name: string; uri: string; description: string }[];
}

export interface ToolFingerprint {
  name: string;
  hash: string;
  descriptionHash: string;
  schemaHash: string;
  description?: string;
}

export interface ServerFingerprint {
  identity: string;
  server: string;
  version?: string;
  recordedAt: string;
  tools: ToolFingerprint[];
  promptsHash: string;
  resourcesHash: string;
  acceptedReason?: string;
}

export interface ScanContext {
  files: ConfigFile[];
  /** Entry-level parse problems (file-level ones live on ConfigFile.error). */
  parseErrors: { source: string; message: string }[];
  servers: ServerEntry[];
  live: ProbeResult[];
  baseline: Record<string, ServerFingerprint>;
}

export interface Suppression {
  id: string;
  server: string;
  reason: string;
  createdAt: string;
}

export interface ScanResult {
  version: string;
  startedAt: string;
  durationMs: number;
  live: boolean;
  files: { path: string; client: string; scope: string; servers: number; error?: string }[];
  servers: {
    name: string;
    client: string;
    source: string;
    transport: Transport;
    command?: string;
    args: string[];
    envNames: string[];
    url?: string;
    tools?: string[];
  }[];
  findings: Finding[];
  suppressed: Finding[];
  notes: string[];
}
