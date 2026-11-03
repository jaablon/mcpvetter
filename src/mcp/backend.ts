import type { Finding, Severity } from "../engine/types.js";

export type Plan = "free" | "pro" | "team";

export type GatedTool =
  | "review_code"
  | "explain_finding"
  | "secure_pattern"
  | "start_lab"
  | "check_lab"
  | "check_mcp_setup"
  | "team_posture";

export interface Authorization {
  allowed: boolean;
  plan: Plan;
  /** Remaining calls today for quota-limited tools on Free; null = unlimited. */
  remaining: number | null;
  /** Shown to the user when not allowed (upgrade / sign-in instructions). */
  message?: string;
}

/** Lab check spec: pass = none of mustNotTrigger rules fire AND every mustMatch regex matches. */
export interface LabCheck {
  mustNotTrigger: string[];
  mustMatch: { re: string; flags?: string; hint: string }[];
  mustNotMatch?: { re: string; flags?: string; hint: string }[];
  /** Parts of the original app that must still be present, so a fragment cannot pass. */
  mustKeep?: { re: string; flags?: string; hint: string }[];
  /** Minimum non-whitespace characters: the submission must be the whole fixed snippet. */
  minChars?: number;
}

export interface Lab {
  id: string;
  number: number;
  title: string;
  free: boolean;
  minutes: number;
  ruleIds: string[];
  pattern: string;
  summary: string;
  language: string;
  /** Vulnerable snippet in the style an AI assistant would actually generate. */
  vulnerable: string;
  /** The context: what this code is supposed to do. */
  scenario: string;
  steps: string[];
  hints: string[];
  check: LabCheck;
  /** Reference solution (served only after a pass or on request for paid users). */
  solution: string;
  version: number;
}

export interface PatternExample {
  stack: string;
  language: string;
  secure: string;
  insecure: string;
  notes?: string;
}

export interface Pattern {
  id: string;
  title: string;
  free: boolean;
  summary: string;
  /** Keywords used to match free-text requests like "parameterised query in Node". */
  keywords: string[];
  examples: PatternExample[];
  checklist: string[];
  version: number;
}

export interface Explanation {
  ruleId: string;
  plain: string;
  /** Defensive-level description of how the flaw is triggered in general terms. */
  howItIsTriggered: string;
  reviewerReason: string;
  lab?: string;
  pattern?: string;
}

export interface TeamPosture {
  team: string;
  periodDays: number;
  members: number;
  codeFindingsByRule: { id: string; count: number }[];
  mcpRiskByCategory: { category: string; count: number }[];
  labs: { assigned: number; completed: number };
}

export interface HistoryItem {
  id: string;
  severity: Severity;
}

/**
 * Everything the MCP tools need from "the account". The local stdio server implements this
 * over HTTPS with an API key; the remote server implements it directly against its database.
 * One tool contract, two transports.
 */
export interface Backend {
  readonly mode: "local" | "remote";
  authorize(tool: GatedTool): Promise<Authorization>;
  recordHistory(tool: GatedTool, findings: HistoryItem[]): Promise<void>;
  getLab(id: string): Promise<Lab | undefined>;
  listLabs(): Promise<Pick<Lab, "id" | "number" | "title" | "free" | "ruleIds" | "minutes">[]>;
  recordLabResult(id: string, passed: boolean): Promise<void>;
  getPattern(id: string): Promise<Pattern | undefined>;
  listPatterns(): Promise<Pick<Pattern, "id" | "title" | "free" | "keywords">[]>;
  getExplanation(ruleId: string): Promise<Explanation | undefined>;
  teamPosture(): Promise<TeamPosture | undefined>;
  /** Base URL for links (pricing, labs, rules pages). */
  origin: string;
}

export type { Finding };

/**
 * Thrown by Backend content methods (getLab/getPattern/getExplanation/teamPosture) when the
 * item exists but the account's plan does not include it. The tools layer renders `message`.
 */
export class PaywallError extends Error {
  constructor(
    message: string,
    public readonly upgradeUrl?: string,
  ) {
    super(message);
    this.name = "PaywallError";
  }
}
