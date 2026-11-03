export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "high" | "medium" | "low";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(s);
}

export function atOrAbove(s: Severity, threshold: Severity): boolean {
  return severityRank(s) >= severityRank(threshold);
}

export interface Location {
  file?: string;
  line?: number;
  server?: string;
  tool?: string;
}

/** The v1.2 Section 4 finding format. Every finding, no exceptions. */
export interface Finding {
  /** Stable rule ID, e.g. MCP-POISON-001. */
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** static = from config / declared metadata / source text; live = observed over a connection. */
  evidenceKind: "static" | "live";
  /** Exact triggering excerpt, secrets redacted. */
  evidence: string;
  location?: Location;
  why: string;
  fix: string;
  lab?: string;
  pattern?: string;
  suppressed?: { reason: string };
}

/** A single hit produced by a rule's check function. Rule metadata fills the rest. */
export interface Hit {
  evidence: string;
  location?: Location;
  severity?: Severity;
  confidence?: Confidence;
  /** Optional extra sentence appended to the rule's fix. */
  fixDetail?: string;
}

export interface RuleMeta {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  why: string;
  fix: string;
  /** Published method: exactly what the rule checks and how (rendered on /rules). */
  method: string;
  lab?: string;
  pattern?: string;
  evidenceKind: "static" | "live";
}

export interface Rule<Ctx> extends RuleMeta {
  check(ctx: Ctx): Hit[];
}

export function toFinding(rule: RuleMeta, hit: Hit): Finding {
  return {
    id: rule.id,
    title: rule.title,
    severity: hit.severity ?? rule.severity,
    confidence: hit.confidence ?? rule.confidence,
    evidenceKind: rule.evidenceKind,
    evidence: hit.evidence,
    location: hit.location,
    why: rule.why,
    fix: hit.fixDetail ? `${rule.fix} ${hit.fixDetail}` : rule.fix,
    lab: rule.lab,
    pattern: rule.pattern,
  };
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.id.localeCompare(b.id) ||
      (a.location?.line ?? 0) - (b.location?.line ?? 0),
  );
}

/** Code review context. */
export interface CodeContext {
  code: string;
  language: string;
  filename?: string;
  lines: string[];
}
