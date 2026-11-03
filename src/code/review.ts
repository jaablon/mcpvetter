import { sortFindings, toFinding, type CodeContext, type Finding, type Rule } from "../engine/types.js";
import { codeAuth } from "./rules/auth.js";
import { codeIdor } from "./rules/idor.js";
import { codeLlmOutput } from "./rules/llmout.js";
import { codeMcpConfig } from "./rules/mcpcfg.js";
import { codePromptInjection } from "./rules/prompt.js";
import { codeSecret } from "./rules/secret.js";
import { codeSqli } from "./rules/sqli.js";
import { codeSsrf } from "./rules/ssrf.js";
import { codeUpload } from "./rules/upload.js";
import { codeXss } from "./rules/xss.js";

export const CODE_RULES: Rule<CodeContext>[] = [
  codeSecret,
  codeSqli,
  codePromptInjection,
  codeLlmOutput,
  codeAuth,
  codeIdor,
  codeXss,
  codeSsrf,
  codeUpload,
  codeMcpConfig,
];

const EXT: Record<string, string> = {
  js: "javascript", mjs: "javascript", cjs: "javascript", jsx: "javascript",
  ts: "typescript", tsx: "typescript", mts: "typescript", cts: "typescript",
  py: "python", json: "json", jsonc: "json", html: "html", vue: "javascript",
  svelte: "javascript", ejs: "html", hbs: "html", jinja: "html", j2: "html",
};

const ALIASES: Record<string, string> = {
  js: "javascript", node: "javascript", nodejs: "javascript", javascript: "javascript", jsx: "javascript",
  ts: "typescript", typescript: "typescript", tsx: "typescript",
  py: "python", python: "python", python3: "python",
  json: "json", jsonc: "json", html: "html", jinja: "html", jinja2: "html",
};

export function detectLanguage(code: string, hint?: string, filename?: string): string {
  if (hint) {
    const h = ALIASES[hint.toLowerCase().trim()];
    if (h) return h;
  }
  const ext = filename?.split(".").pop()?.toLowerCase();
  if (ext && EXT[ext]) return EXT[ext];
  const t = code.trim();
  if (/^[{[]/.test(t)) {
    try {
      JSON.parse(t);
      return "json";
    } catch {
      if (/"mcpServers"|"servers"\s*:/.test(t) && !/\b(?:const|function|def|import)\b/.test(t)) return "json";
    }
  }
  if (/^\s*(?:def |class \w+.*:\s*$|import \w+\s*$|from [\w.]+ import |@app\.|if __name__ ==)/m.test(code)) return "python";
  if (/^\s*<(?:!doctype|html|div|template|body)/i.test(t)) return "html";
  if (/:\s*(?:string|number|boolean)\b|\binterface \w+|\bimport type\b|<\w+>\(/.test(code)) return "typescript";
  return "javascript";
}

/** Run every code rule on a snippet. Findings are deduped per rule + line and sorted worst-first. */
export function reviewCode(code: string, opts: { language?: string; filename?: string } = {}): Finding[] {
  const language = detectLanguage(code, opts.language, opts.filename);
  const ctx: CodeContext = { code, language, filename: opts.filename, lines: code.split(/\r?\n/) };
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const rule of CODE_RULES) {
    let hits;
    try {
      hits = rule.check(ctx);
    } catch {
      continue; // a rule bug must never break the whole review
    }
    for (const hit of hits) {
      const key = `${rule.id}:${hit.location?.line ?? 0}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const f = toFinding(rule, hit);
      if (opts.filename) f.location = { ...f.location, file: opts.filename };
      findings.push(f);
    }
  }
  return sortFindings(findings);
}
