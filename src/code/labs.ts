import type { Finding } from "../engine/types.js";
import type { LabCheck } from "../mcp/backend.js";
import { reviewCode } from "./review.js";

export interface LabResult {
  passed: boolean;
  failures: string[];
  findings: Finding[];
}

/**
 * Verify a lab submission: none of the lab's rules may still fire, every required secure
 * pattern must be present, no forbidden pattern may remain, and the submission must still be
 * the lab's app (minimum size plus mustKeep markers), not a one-line fragment.
 */
export function checkLab(check: LabCheck, code: string, language?: string): LabResult {
  const findings = reviewCode(code, { language });
  const failures: string[] = [];
  if (!code.trim()) failures.push("The submission is empty. Paste your fixed version of the lab code.");
  else if (check.minChars && code.replace(/\s+/g, "").length < check.minChars) {
    failures.push("This looks like a fragment. Submit the whole fixed snippet from the lab, not just the changed line.");
  }
  for (const m of check.mustKeep ?? []) {
    if (!new RegExp(m.re, m.flags ?? "").test(code)) failures.push(m.hint);
  }
  for (const id of check.mustNotTrigger) {
    for (const f of findings.filter((x) => x.id === id)) {
      failures.push(`${f.id} still triggers${f.location?.line ? ` on line ${f.location.line}` : ""}: ${f.title}. ${f.evidence}`);
    }
  }
  for (const m of check.mustMatch) {
    if (!new RegExp(m.re, m.flags ?? "").test(code)) failures.push(m.hint);
  }
  for (const m of check.mustNotMatch ?? []) {
    if (new RegExp(m.re, m.flags ?? "").test(code)) failures.push(m.hint);
  }
  return { passed: failures.length === 0, failures, findings };
}
