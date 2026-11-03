import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { interpolations, isCommentLine, llmTainted, logicalLines, requestTainted } from "../taint.js";

const SANITIZED_RE =
  /DOMPurify\.sanitize|sanitizeHtml|sanitize_html|bleach\.clean|escapeHtml|escape_html|html\.escape|markupsafe\.escape|\bescape\s*\(|he\.encode|encodeURIComponent|xss\s*\(|filterXSS/;

interface Sink {
  re: RegExp;
  arg: (line: string) => string | undefined;
  /** Only flag when the value is request-tainted (for sinks where unknown-origin values are common). */
  needTaint?: boolean;
  /** DOM sinks are checked on physical lines; unknown-origin values there are reported at low confidence. */
  dom?: boolean;
}

const after = (re: RegExp) => (line: string) => line.match(re)?.[1];

const SINKS: Sink[] = [
  { re: /\.(?:innerHTML|outerHTML)\s*\+?=/, arg: after(/\.(?:innerHTML|outerHTML)\s*\+?=\s*(.+)$/), dom: true },
  { re: /insertAdjacentHTML\s*\(/, arg: after(/insertAdjacentHTML\s*\([^,]+,\s*(.+)$/), dom: true },
  { re: /document\.write(?:ln)?\s*\(/, arg: after(/document\.write(?:ln)?\s*\((.+)$/), dom: true },
  { re: /dangerouslySetInnerHTML/, arg: after(/__html\s*:\s*([^}]+)/) },
  { re: /v-html\s*=/, arg: after(/v-html\s*=\s*["']([^"']+)/) },
  { re: /\{\{[^}]*\|\s*safe\s*\}\}/, arg: after(/\{\{\s*([^|}]+)\|\s*safe/) },
  { re: /\{\{\{[^}]+\}\}\}/, arg: after(/\{\{\{\s*([^}]+)\}\}\}/) },
  { re: /<%-\s*[^%]+%>/, arg: after(/<%-\s*([^%]+)%>/) },
  { re: /\b(?:Markup|mark_safe)\s*\(/, arg: after(/\b(?:Markup|mark_safe)\s*\((.+)$/) },
  { re: /\brender_template_string\s*\(/, arg: after(/render_template_string\s*\((.+)$/), needTaint: true },
  { re: /\b(?:res\.send|res\.write|res\.end|HttpResponse|HTMLResponse|make_response)\s*\(\s*(?:f?["'`]|["'`]).*<\/?[a-z][^>]*>/i, arg: (l) => l, needTaint: true },
  { re: /^\s*return\s+f["'].*<\/?[a-z][^>]*>/i, arg: (l) => l, needTaint: true },
];

/** A value that is only a string literal (no variables) cannot carry user data. */
function literalOnly(expr: string): boolean {
  const e = expr.trim().replace(/[;,)]*\s*$/, "");
  return /^(["'])(?:(?!\1).)*\1$/.test(e) || (/^`[^`]*`$/.test(e) && !e.includes("${"));
}

/** arg calls a helper defined in the snippet whose body sanitizes, e.g. renderMarkdown(x) { return DOMPurify.sanitize(...) }. */
function callsSanitizingHelper(ctx: CodeContext, arg: string): boolean {
  for (const m of arg.matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)) {
    const name = m[1];
    const def = ctx.lines.findIndex((l) =>
      new RegExp(`(?:function\\s+${name}\\b|(?:const|let|var)\\s+${name}\\s*=|def\\s+${name}\\b)`).test(l),
    );
    if (def >= 0 && SANITIZED_RE.test(ctx.lines.slice(def, def + 8).join("\n"))) return true;
  }
  return false;
}

export const codeXss: Rule<CodeContext> = {
  id: "CODE-XSS-001",
  title: "Unsanitised value rendered as HTML (XSS)",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  lab: "lab-07-xss",
  pattern: "output-encoding",
  why:
    "Inserting a value into the page as raw HTML lets any markup inside it run in your users' browsers. A comment, profile field or URL parameter containing a script can steal sessions, act as the user, or rewrite the page.",
  fix:
    "Render values as text: textContent in the DOM, normal {value} interpolation in React, {{ value }} without |safe in Jinja, <%= %> in EJS. If you really need HTML (for example rendered markdown), sanitize it with DOMPurify.sanitize() or bleach.clean() using an allowlist right before inserting it.",
  method:
    "Flags values written to raw-HTML sinks (innerHTML, outerHTML, insertAdjacentHTML, document.write, dangerouslySetInnerHTML, v-html, Jinja |safe, Handlebars {{{ }}}, EJS <%- %>, Markup / mark_safe) unless the value is a plain string literal or passes through DOMPurify, sanitize-html, bleach, html.escape or an escape helper on the same line. HTML strings built with request input and returned from res.send / HttpResponse / render_template_string are flagged only when the input is traceable to the request. Confidence is high for request-derived values; values of unknown origin are medium for template opt-outs (dangerouslySetInnerHTML, v-html, |safe, Markup) and low for DOM sinks. Model output reaching these sinks is reported by CODE-LLMOUT-001 instead.",
  check(ctx) {
    const hits: Hit[] = [];
    const evaluate = (line: string, next: string, lineNo: number, dom: boolean) => {
      if (isCommentLine(line) || SANITIZED_RE.test(line)) return;
      for (const sink of SINKS) {
        if (!!sink.dom !== dom || !sink.re.test(line)) continue;
        let arg = (sink.arg(line) ?? line).trim();
        if (!arg && dom) arg = next.trim();
        if (SANITIZED_RE.test(arg) || literalOnly(arg) || callsSanitizingHelper(ctx, arg)) break;
        if (llmTainted(ctx, arg)) break;
        const exprs = sink.needTaint ? interpolations(line) : [arg];
        const tainted = exprs.some((e) => requestTainted(ctx, e)) || requestTainted(ctx, arg);
        if (sink.needTaint && !tainted) break;
        hits.push({ evidence: evidence(line), location: { line: lineNo }, confidence: tainted ? "high" : dom ? "low" : "medium" });
        break;
      }
    };
    ctx.lines.forEach((line, i) => evaluate(line, ctx.lines[i + 1] ?? "", i + 1, true));
    for (const ll of logicalLines(ctx.lines)) evaluate(ll.text, "", ll.index + 1, false);
    return hits;
  },
};
