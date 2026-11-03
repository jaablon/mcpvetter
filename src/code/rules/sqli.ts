import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { interpolations, isCommentLine, isTestFile, logicalLines, requestTainted } from "../taint.js";

const SQL_KEYWORD_RE = /\b(?:SELECT\s+[\w*,\s.]+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE\s+\w+|ORDER\s+BY|DROP\s+TABLE)\b/i;

/** Bound-parameter placeholders: when present, interpolation is often an identifier list (still worth a look, lower confidence). */
const PLACEHOLDER_RE = /=\s*(?:\?|%s|\$\d+|:\w+)/;

export const SQL_SINK_RE =
  /(?:\.\s*(?:query|execute|executemany|executescript|exec|raw|run|all|get|prepare|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)|\bcursor\.execute|\bexecute|\btext)\s*\(/;

/** Does the line build a string by interpolation in an unsafe way (ignores tagged templates like sql`...`). */
function dynamicSql(line: string): boolean {
  if (!SQL_KEYWORD_RE.test(line)) return false;
  // untagged template literal with ${}
  for (const m of line.matchAll(/(?:^|[^\w$.])`([^`]*)`?/g)) {
    if (m[1].includes("${") && SQL_KEYWORD_RE.test(m[1])) return true;
  }
  // f-string whose own text contains SQL
  for (const m of line.matchAll(/\b[rbRB]*[fF][rbRB]*("""|"|')((?:(?!\1).)*)/g)) {
    if (/\{[^}]+\}/.test(m[2]) && SQL_KEYWORD_RE.test(m[2])) return true;
  }
  // concatenation, .format() or % applied to a string literal that itself contains SQL
  const sqlLit = `(["'])(?:(?!\\1).)*?${SQL_KEYWORD_RE.source.replace(/^\\b|\\b$/g, "")}(?:(?!\\1).)*\\1`;
  if (new RegExp(`${sqlLit}\\s*(?:\\+|%\\s*[\\w(]|\\.format\\s*\\()`, "i").test(line)) return true;
  if (new RegExp(`[A-Za-z_$)\\]]\\s*\\+\\s*${sqlLit}`, "i").test(line)) return true;
  return false;
}

export const codeSqli: Rule<CodeContext> = {
  id: "CODE-SQLI-001",
  title: "SQL query built from string interpolation",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  lab: "lab-02-sqli",
  pattern: "parameterized-queries",
  why:
    "When values are pasted into the SQL text, the database cannot tell data from commands. Input containing quotes or SQL keywords can change what the query does, including reading or deleting other users' data.",
  fix:
    "Pass values as bound parameters instead of building the string: db.query(\"SELECT * FROM users WHERE id = $1\", [id]) in Node, cursor.execute(\"SELECT * FROM users WHERE id = %s\", (id,)) in Python, or use your ORM's query builder. Tagged templates such as sql`...${id}` that parameterize automatically are also safe.",
  method:
    "Finds string literals that contain SQL (SELECT ... FROM, INSERT INTO, UPDATE ... SET, DELETE FROM, WHERE) and are built with an untagged template literal, f-string, concatenation, .format() or % formatting. Reports when that string is passed to a query/execute/raw call on the same line or through a variable. Confidence is high when an interpolated value comes from request input in the same snippet, low when the query also uses bound placeholders (interpolation is then usually an identifier list) or the file is a test, and medium otherwise. Tagged templates (sql`...`, Prisma.sql) and placeholder arguments are not flagged.",
  check(ctx) {
    const hits: Hit[] = [];
    const builtVars = new Map<string, { index: number; tainted: boolean; text: string }>();
    const logical = logicalLines(ctx.lines);
    logical.forEach((ll, n) => {
      const line = ll.text;
      if (isCommentLine(line) || !dynamicSql(line)) return;
      const tainted = interpolations(line).some((e) => requestTainted(ctx, e));
      const assign = line.match(/^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*\w+\s*)?(?:=|\+=)(?!=)/);
      const prev = n > 0 ? logical[n - 1].text : "";
      if (SQL_SINK_RE.test(line) || (SQL_SINK_RE.test(prev) && /\(\s*$/.test(prev))) {
        hits.push({ evidence: evidence(line), location: { line: ll.index + 1 }, confidence: tainted ? "high" : PLACEHOLDER_RE.test(line) || isTestFile(ctx.filename) ? "low" : "medium" });
      } else if (assign) {
        const existing = builtVars.get(assign[1]);
        builtVars.set(assign[1], { index: existing?.index ?? ll.index, tainted: tainted || !!existing?.tainted, text: existing?.text ?? line });
      }
    });
    for (const [name, def] of builtVars) {
      const re = new RegExp(
        `(?:query|execute|executemany|executescript|exec|raw|run|all|get|prepare|\\$queryRawUnsafe|\\$executeRawUnsafe|unsafe|text)\\s*\\(\\s*(?:text\\s*\\(\\s*)?${name.replace(/\$/g, "\\$")}\\b`,
      );
      ctx.lines.forEach((line, i) => {
        if (i === def.index || isCommentLine(line) || !re.test(line)) return;
        hits.push({
          evidence: evidence(`${def.text.trim()} ... ${line.trim()}`),
          location: { line: def.index + 1 },
          confidence: def.tainted ? "high" : PLACEHOLDER_RE.test(def.text) || isTestFile(ctx.filename) ? "low" : "medium",
        });
      });
    }
    return hits;
  },
};
