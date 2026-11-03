import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { isCommentLine, llmTainted } from "../taint.js";

const SANITIZED_RE =
  /DOMPurify\.sanitize|sanitizeHtml|sanitize_html|bleach\.clean|escapeHtml|escape_html|html\.escape|markupsafe\.escape|\bescape\s*\(|shlex\.quote|validator\.escape|\.textContent\s*=|\.innerText\s*=/;

interface Sink {
  re: RegExp;
  kind: string;
  /** Extract the expression that flows into the sink. */
  arg: (line: string) => string | undefined;
}

const after = (re: RegExp) => (line: string) => line.match(re)?.[1];

const SINKS: Sink[] = [
  { kind: "HTML (innerHTML)", re: /\.(?:innerHTML|outerHTML)\s*\+?=/, arg: after(/\.(?:innerHTML|outerHTML)\s*\+?=\s*(.+)$/) },
  { kind: "HTML (insertAdjacentHTML)", re: /insertAdjacentHTML\s*\(/, arg: after(/insertAdjacentHTML\s*\([^,]+,\s*(.+)$/) },
  { kind: "HTML (document.write)", re: /document\.write(?:ln)?\s*\(/, arg: after(/document\.write(?:ln)?\s*\((.+)$/) },
  { kind: "HTML (dangerouslySetInnerHTML)", re: /dangerouslySetInnerHTML/, arg: after(/__html\s*:\s*([^}]+)/) },
  { kind: "HTML (v-html)", re: /v-html\s*=/, arg: after(/v-html\s*=\s*["']([^"']+)/) },
  { kind: "HTML (Markup / mark_safe)", re: /\b(?:Markup|mark_safe)\s*\(/, arg: after(/\b(?:Markup|mark_safe)\s*\((.+)$/) },
  { kind: "code execution (eval)", re: /(?<![\w.])(?:eval|exec|Function)\s*\(|new\s+Function\s*\(|vm\.run\w*\s*\(/, arg: after(/(?:eval|exec|Function|vm\.run\w*)\s*\((.+)$/) },
  { kind: "shell command", re: /(?:(?<![\w.])|\b(?:child_process|childProcess|cp)\.)(?:execSync|exec|spawnSync|spawn|execFileSync)\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|subprocess\.\w+\s*\(.*shell\s*=\s*True/, arg: after(/(?:execSync|exec|spawnSync|spawn|execFileSync|os\.system|os\.popen|subprocess\.\w+)\s*\((.+)$/) },
  { kind: "SQL query", re: /(?:\.\s*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)|cursor\.execute|\b(?:db|database|conn|connection|sqlite|pool|client)\.exec)\s*\(/, arg: after(/(?:query|execute|raw|exec|\$queryRawUnsafe|\$executeRawUnsafe)\s*\((.+)$/) },
  { kind: "file path", re: /\b(?:writeFileSync|writeFile|unlinkSync|rmSync)\s*\(|\bopen\s*\([^)]*["'][wa]/, arg: after(/(?:writeFileSync|writeFile|unlinkSync|rmSync|open)\s*\(([^,]+)/) },
];

export const codeLlmOutput: Rule<CodeContext> = {
  id: "CODE-LLMOUT-001",
  title: "Model output used as trusted HTML, SQL, code or shell",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  lab: "lab-04-llm-output",
  pattern: "llm-output-handling",
  why:
    "A model's output is shaped by whatever it read, including user text, web pages and documents that may contain injected instructions. Rendering it as HTML, running it as SQL or code, or passing it to a shell gives anyone who can influence the model a path to script injection, data loss or command execution.",
  fix:
    "Treat model output as untrusted user input. Render it as text (textContent, or a markdown renderer with raw HTML disabled followed by DOMPurify), never pass it to eval, exec or a shell, and if the model chooses an action, have it return structured data that you validate against an allowlist before running a fixed, parameterized operation.",
  method:
    "Tracks variables assigned from model responses (choices[0].message.content, content[0].text, output_text, generateText, .invoke(...).content, or variables named like llm_output / completion / aiResponse) and flags them when they reach an HTML sink (innerHTML, insertAdjacentHTML, document.write, dangerouslySetInnerHTML, v-html, Markup), eval / exec / new Function, a shell call (exec, execSync, spawn, os.system, subprocess with shell=True), a raw SQL call, or a file write path. Lines that pass the value through DOMPurify, sanitize-html, bleach, html.escape or shlex.quote are not flagged.",
  check(ctx) {
    const hits: Hit[] = [];
    ctx.lines.forEach((line, i) => {
      if (isCommentLine(line) || SANITIZED_RE.test(line)) return;
      for (const sink of SINKS) {
        if (!sink.re.test(line)) continue;
        const arg = sink.arg(line) ?? line;
        if (!llmTainted(ctx, arg)) continue;
        hits.push({
          evidence: evidence(line),
          location: { line: i + 1 },
          confidence: "high",
          fixDetail: `Sink: ${sink.kind}.`,
        });
        break;
      }
    });
    return hits;
  },
};
