import { readFileSync } from "node:fs";
import { join } from "node:path";
import { stateDir } from "../scanner/fingerprint.js";
import { VERSION } from "../version.js";
import { PaywallError, type Authorization, type Backend, type GatedTool, type HistoryItem } from "./backend.js";

export const DEFAULT_ORIGIN = "https://mcpvetter.com";

export function apiConfig(): { key?: string; origin: string } {
  let file: { apiKey?: string; origin?: string } = {};
  try {
    file = JSON.parse(readFileSync(join(stateDir(), "config.json"), "utf8"));
  } catch {
    /* no config */
  }
  return {
    key: process.env.MCPVETTER_API_KEY || file.apiKey || undefined,
    origin: (process.env.MCPVETTER_ORIGIN || file.origin || DEFAULT_ORIGIN).replace(/\/+$/, ""),
  };
}

const FREE_WITHOUT_KEY: GatedTool[] = ["check_mcp_setup", "explain_finding"];

/**
 * Backend for the local stdio server and CLI. Analysis always runs on this machine;
 * the API is only used for the license check, lab/pattern content, and rule-ID history.
 * Without an API key, it makes no network requests at all.
 */
export class LocalBackend implements Backend {
  readonly mode = "local" as const;
  readonly origin: string;
  private readonly key?: string;

  constructor(cfg = apiConfig()) {
    this.origin = cfg.origin;
    this.key = cfg.key;
  }

  get hasKey(): boolean {
    return !!this.key;
  }

  private async call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T | undefined> {
    if (!this.key) throw new PaywallError(`This needs a free MCPVetter account. Create one and copy your API key at ${this.origin}/account, then set MCPVETTER_API_KEY in this server's env.`, `${this.origin}/account`);
    const res = await fetch(`${this.origin}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.key}`, "content-type": "application/json", "user-agent": `mcpvetter/${VERSION}` },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    if (res.status === 404) return undefined;
    const json = (await res.json().catch(() => ({}))) as { message?: string; upgradeUrl?: string; error?: string };
    if (res.status === 402) throw new PaywallError(json.message ?? "This needs a paid plan.", json.upgradeUrl ?? `${this.origin}/pricing`);
    if (res.status === 401) throw new PaywallError(`Your MCPVetter API key was rejected. Get a new one at ${this.origin}/account.`, `${this.origin}/account`);
    if (!res.ok) throw new Error(json.message ?? json.error ?? `API error ${res.status}`);
    return json as T;
  }

  async authorize(tool: GatedTool): Promise<Authorization> {
    if (!this.key) {
      if (FREE_WITHOUT_KEY.includes(tool)) return { allowed: true, plan: "free", remaining: null };
      return { allowed: false, plan: "free", remaining: 0, message: `${tool} needs an MCPVetter account (free tier available). Get an API key at ${this.origin}/account and set MCPVETTER_API_KEY.` };
    }
    try {
      return (await this.call<Authorization>("POST", "/api/v1/authorize", { tool })) ?? { allowed: false, plan: "free", remaining: 0, message: "Authorization failed." };
    } catch (e) {
      if (e instanceof PaywallError) return { allowed: false, plan: "free", remaining: 0, message: `${e.message}${e.upgradeUrl ? ` ${e.upgradeUrl}` : ""}` };
      // Scanner tools stay usable offline; paid tools need the license check.
      if (FREE_WITHOUT_KEY.includes(tool)) return { allowed: true, plan: "free", remaining: null };
      return { allowed: false, plan: "free", remaining: 0, message: `Could not reach ${this.origin} to check your plan: ${(e as Error).message}` };
    }
  }

  async recordHistory(tool: GatedTool, findings: HistoryItem[]): Promise<void> {
    if (!this.key) return;
    // Rule IDs and severities only. Never code, evidence, paths, or server names.
    await this.call("POST", "/api/v1/history", { tool, findings: findings.slice(0, 200).map((f) => ({ id: f.id, severity: f.severity })) }).catch(() => undefined);
  }

  getLab = (id: string) => this.call<any>("GET", `/api/v1/labs/${encodeURIComponent(id)}`);
  listLabs = async () => (await this.call<any>("GET", "/api/v1/labs"))?.labs ?? [];
  recordLabResult = async (id: string, passed: boolean) => {
    await this.call("POST", `/api/v1/labs/${encodeURIComponent(id)}/result`, { passed });
  };
  getPattern = (id: string) => this.call<any>("GET", `/api/v1/patterns/${encodeURIComponent(id)}`);
  listPatterns = async () => (await this.call<any>("GET", "/api/v1/patterns"))?.patterns ?? [];
  getExplanation = async (ruleId: string) => (this.key ? this.call<any>("GET", `/api/v1/explain/${encodeURIComponent(ruleId)}`) : undefined);
  teamPosture = () => this.call<any>("GET", "/api/v1/team/posture");
}
