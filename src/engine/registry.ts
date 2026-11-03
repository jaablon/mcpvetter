import { CODE_RULES } from "../code/review.js";
import { SCANNER_RULES } from "../scanner/index.js";
import type { RuleMeta } from "./types.js";

/** Rule metadata only (no check functions), in published order: scanner rules then code rules. */
export function allRuleMetas(): RuleMeta[] {
  return [...SCANNER_RULES, ...CODE_RULES].map(({ check: _check, ...meta }) => meta);
}

export function getRuleMeta(id: string): RuleMeta | undefined {
  return allRuleMetas().find((r) => r.id === id);
}
