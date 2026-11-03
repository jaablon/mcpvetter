/**
 * Minimal intra-snippet taint tracking shared by the CODE-* rules.
 *
 * Two source kinds:
 *  - request: data an outside user controls (HTTP request fields, CLI input, route params)
 *  - llm: text produced by a language model
 *
 * Propagation is assignment-based and flow-insensitive (two passes over the snippet), which
 * is deliberately simple: it is used to raise confidence, not to prove reachability.
 */
import type { CodeContext } from "../engine/types.js";

export const REQUEST_SOURCE_RE =
  /\b(?:req|request|ctx\.request|ctx)\s*\.\s*(?:body|query|params|headers|cookies|args|form|values|files|json|get_json\s*\(|data\b|path_params|query_params)|\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters)|\bsearchParams\s*\.\s*get\s*\(|\bformData\s*\.\s*get\s*\(|\bsys\.argv|(?<![.\w])input\s*\(|\bprocess\.argv/;

/** Variable names that by convention hold end-user text. */
export const USER_NAME_RE =
  /^(?:user_?input|user_?message|user_?msg|user_?query|user_?text|user_?prompt|user_?question|user_?content|message_?from_?user|query_?text|question|search_?term|comment_?body)$/i;

export const LLM_SOURCE_RE =
  /choices\s*\[\s*0\s*\]\s*(?:\.\s*message\s*)?\.\s*(?:content|text)\b|\.content\s*\[\s*0\s*\]\s*\.\s*text\b|\.output_text\b|\bgenerateText\s*\(|\.invoke\s*\([^)]*\)\s*\.\s*content\b|\bcompletion\s*\.\s*(?:text|content)\b/;

export const LLM_NAME_RE =
  /^(?:(?:llm|model|ai|gpt|claude|openai|anthropic|chat|assistant|completion|generated)_?(?:output|response|reply|text|answer|result|html|sql|code|command|content|message)|completion|generated_?(?:text|html|sql|code)?|answer_?html|ai_?html)$/i;

const ASSIGN_RES: RegExp[] = [
  // JS: const|let|var x = ..., also with type annotation
  /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(.+)$/,
  // JS destructuring: const { a, b: c } = ... / const [a, b] = ...
  /^\s*(?:const|let|var)\s+([{[][^=]*[}\]])\s*=\s*(.+)$/,
  // Python / plain reassignment: x = ... (not ==), optional annotation
  /^\s*([A-Za-z_][\w]*)\s*(?::\s*[\w[\], .|]+)?=(?!=)\s*(.+)$/,
  // Python tuple unpack: a, b = ...
  /^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)+)\s*=(?!=)\s*(.+)$/,
];

export interface Taint {
  request: Set<string>;
  llm: Set<string>;
}

function namesFromLhs(lhs: string): string[] {
  if (/^[{[]/.test(lhs)) {
    // destructuring: take the local binding names (after ':' if renamed)
    return lhs
      .replace(/^[{[]|[}\]]$/g, "")
      .split(",")
      .map((p) => p.split("=")[0].trim())
      .map((p) => (p.includes(":") ? p.split(":")[1].trim() : p))
      .map((p) => p.replace(/^\.\.\./, ""))
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p));
  }
  return lhs
    .split(",")
    .map((s) => s.trim())
    .filter((s) => /^[A-Za-z_$][\w$]*$/.test(s));
}

function identifiers(expr: string): string[] {
  return expr.match(/[A-Za-z_$][\w$]*/g) ?? [];
}

export function mentions(expr: string, vars: Set<string>): boolean {
  if (vars.size === 0) return false;
  // ignore property names after a dot: obj.userInput is not the variable userInput
  const cleaned = expr.replace(/\.\s*[A-Za-z_$][\w$]*/g, ".");
  return identifiers(cleaned).some((id) => vars.has(id));
}

/** Route path parameters: Flask <int:id>, FastAPI {id}, plus the handler's parameter names. */
function routeParams(lines: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!/@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route)\s*\(/.test(l)) continue;
    for (const m of l.matchAll(/<(?:\w+:)?(\w+)>/g)) out.push(m[1]);
    for (const m of l.matchAll(/\{(\w+)(?::[^}]*)?\}/g)) out.push(m[1]);
  }
  return out;
}

const cache = new WeakMap<CodeContext, Taint>();

export function computeTaint(ctx: CodeContext): Taint {
  const hit = cache.get(ctx);
  if (hit) return hit;
  const request = new Set<string>(routeParams(ctx.lines));
  const llm = new Set<string>();
  // function parameters named like user text
  for (const m of ctx.code.matchAll(/(?:function\s*\w*|def\s+\w+|=>|\w+)\s*\(([^)]*)\)/g)) {
    for (const p of m[1].split(",")) {
      const name = p.trim().replace(/[:=].*$/, "").replace(/^\.\.\./, "").trim();
      if (USER_NAME_RE.test(name)) request.add(name);
      if (LLM_NAME_RE.test(name)) llm.add(name);
    }
  }
  for (let pass = 0; pass < 3; pass++) {
    for (const line of ctx.lines) {
      for (const re of ASSIGN_RES) {
        const m = line.match(re);
        if (!m) continue;
        const names = namesFromLhs(m[1]);
        const rhs = m[2];
        const fromReq = REQUEST_SOURCE_RE.test(rhs) || mentions(rhs, request);
        const fromLlm = LLM_SOURCE_RE.test(rhs) || mentions(rhs, llm) || namedLlm(rhs);
        for (const n of names) {
          if (fromReq) request.add(n);
          if (fromLlm) llm.add(n);
          if (USER_NAME_RE.test(n)) request.add(n);
          if (LLM_NAME_RE.test(n) && !fromReq) llm.add(n);
        }
        break;
      }
    }
  }
  const t = { request, llm };
  cache.set(ctx, t);
  return t;
}

export function requestTainted(ctx: CodeContext, expr: string): boolean {
  return REQUEST_SOURCE_RE.test(expr) || mentions(expr, computeTaint(ctx).request);
}

/** Bare identifiers (not properties) whose names say they hold model output. */
function namedLlm(expr: string): boolean {
  const cleaned = expr.replace(/\.\s*[A-Za-z_$][\w$]*/g, ".");
  return identifiers(cleaned).some((id) => LLM_NAME_RE.test(id));
}

export function llmTainted(ctx: CodeContext, expr: string): boolean {
  return LLM_SOURCE_RE.test(expr) || mentions(expr, computeTaint(ctx).llm) || namedLlm(expr);
}

/** Expressions interpolated into string literals on a line: ${...}, f-string {...}, concatenation, .format(), %. */
export function interpolations(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(/\$\{([^}]+)\}/g)) out.push(m[1]);
  // Python f-strings
  for (const m of line.matchAll(/\b[rbfRBF]*[fF][rbRB]*(["'])((?:(?!\1).)*)\1/g)) {
    for (const inner of m[2].matchAll(/\{([^{}]+)\}/g)) out.push(inner[1].split(/[!:]/)[0]);
  }
  for (const m of line.matchAll(/\bf"""(.*)/g)) for (const inner of m[1].matchAll(/\{([^{}]+)\}/g)) out.push(inner[1]);
  // concatenation with a string literal on either side
  for (const m of line.matchAll(/["'`]\s*\+\s*([A-Za-z_$][\w$.[\]()'"]*)/g)) out.push(m[1]);
  for (const m of line.matchAll(/([A-Za-z_$][\w$.[\]()]*)\s*\+\s*["'`]/g)) out.push(m[1]);
  // .format(...) and % formatting
  for (const m of line.matchAll(/["']\s*\.format\s*\(([^)]*)\)/g)) out.push(m[1]);
  for (const m of line.matchAll(/["']\s*%\s*(\(?[^,;]+)/g)) out.push(m[1]);
  return out;
}

export function isCommentLine(line: string): boolean {
  return /^\s*(?:\/\/|#(?!!)|\*|\/\*|<!--)/.test(line);
}

/** Lines i-before .. i+after, clamped, joined. */
export function windowText(lines: string[], i: number, before: number, after: number): string {
  return lines.slice(Math.max(0, i - before), Math.min(lines.length, i + after + 1)).join("\n");
}

export interface LogicalLine {
  text: string;
  /** 0-based index of the first physical line. */
  index: number;
}

/**
 * Merge multi-line template literals and Python triple-quoted strings (plus the statement
 * line that opens them) into one logical line, so that rules see `SELECT ... ${x}` together.
 */
export function logicalLines(lines: string[]): LogicalLine[] {
  const out: LogicalLine[] = [];
  let buf: string[] = [];
  let start = 0;
  let open: "`" | '"""' | "'''" | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!open) {
      start = i;
      buf = [line];
    } else {
      buf.push(line);
    }
    // recompute open-state over this line
    let j = 0;
    while (j < line.length) {
      if (open === "`") {
        const k = line.indexOf("`", j);
        if (k === -1) break;
        if (line[k - 1] === "\\") { j = k + 1; continue; }
        open = null; j = k + 1;
      } else if (open) {
        const k = line.indexOf(open, j);
        if (k === -1) break;
        open = null; j = k + 3;
      } else {
        const rest = line.slice(j);
        const m = rest.match(/`|"""|'''|\/\/|#/);
        if (!m || m.index === undefined) break;
        const tok = m[0];
        if (tok === "//" || tok === "#") {
          // comment start only if not inside a normal quote; approximate by counting quotes before it
          const before = rest.slice(0, m.index);
          if ((before.match(/"/g)?.length ?? 0) % 2 === 0 && (before.match(/'/g)?.length ?? 0) % 2 === 0) break;
          j += m.index + tok.length;
          continue;
        }
        open = tok as "`" | '"""' | "'''";
        j += m.index + tok.length;
      }
    }
    if (!open) out.push({ text: buf.join(" "), index: start });
  }
  if (open && buf.length) out.push({ text: buf.join(" "), index: start });
  return out;
}

/** Test and fixture files: lower the bar for noise-prone rules. */
export function isTestFile(filename?: string): boolean {
  return (
    !!filename &&
    /(?:^|[\\/])(?:tests?|__tests__|spec|fixtures?)[\\/]|\.(?:test|spec)\.[jt]sx?$|(?:^|[\\/])test_\w+\.py$|_test\.py$/.test(filename)
  );
}
