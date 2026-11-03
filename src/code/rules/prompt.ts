import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { interpolations, isCommentLine, logicalLines, requestTainted } from "../taint.js";

/** The current line assigns or passes a system/developer prompt. */
const SYSTEM_ASSIGN_RE =
  /(?:\bsystem|system_?prompt|systemPrompt|system_?message|systemMessage|\binstructions|\bpreamble)["']?\s*[:=]\s*(?:[rbRB]*[fF][rbRB]*["']|`|["'(]|\w+\s*\()|SystemMessage\s*\(/i;

const ROLE_RE = /role\s*["']?\s*[:=]\s*["'](\w+)["']/g;

const INSTRUCTION_PHRASE_RE =
  /\b(?:you are (?:a|an|the)\b|your (?:task|job|role) is|instructions?:|follow these|respond (?:only|with|in)|do not (?:reveal|mention|answer)|always (?:respond|answer|reply)|act as\b|rules?:)/i;

/** Delimited user data: <tag>${x}</tag>, """{x}""", ```{x}``` or JSON.stringify(x). */
function delimited(line: string, expr: string): boolean {
  const e = expr.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return (
    new RegExp(`<[a-z_][\\w-]*>\\s*(?:\\$\\{|\\{)\\s*${e}\\s*\\}\\s*</`, "i").test(line) ||
    new RegExp(`(?:"""|\`\`\`|'''|"{3})\\s*(?:\\$\\{|\\{)\\s*${e}`).test(line) ||
    new RegExp(`JSON\\.stringify\\(\\s*${e}|json\\.dumps\\(\\s*${e}`).test(line)
  );
}

export const codePromptInjection: Rule<CodeContext> = {
  id: "CODE-PROMPTI-001",
  title: "User input mixed into model instructions (prompt injection)",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  lab: "lab-03-prompt-injection",
  pattern: "llm-input-handling",
  why:
    "When text from a user is pasted into the system prompt or into the instructions themselves, the model cannot tell your rules apart from the user's words. A user can write text that reads like new instructions and override what the feature is supposed to do, leak the prompt, or misuse any tools the model can call.",
  fix:
    "Keep the system prompt static. Send user text as a separate user message, wrap it in clear delimiters (for example <user_input>...</user_input>), tell the model that content inside the delimiters is data and never instructions, and give the model only the tools and data it needs for this request.",
  method:
    "Flags a string that interpolates request-controlled input (request fields, route params, or variables named like user_input / userMessage) when the string is a system or developer prompt (role: \"system\", system=, systemPrompt, instructions, SystemMessage), at high confidence. Also flags a prompt string that contains instruction phrasing (\"You are a\", \"Your task is\", \"Instructions:\") and interpolates such input without delimiters, at medium confidence. User input sent as its own user-role message, or wrapped in XML-style tags, triple quotes, or JSON.stringify, is not flagged.",
  check(ctx) {
    const hits: Hit[] = [];
    const logical = logicalLines(ctx.lines);
    logical.forEach((ll, n) => {
      const line = ll.text;
      if (isCommentLine(line)) return;
      const tainted = interpolations(line).filter((e) => requestTainted(ctx, e));
      if (tainted.length === 0) return;
      const context = [logical[n - 2]?.text ?? "", logical[n - 1]?.text ?? "", line].join("\n");
      const lastIsSystem = (ms: RegExpMatchArray[]) => ms.length > 0 && /^(?:system|developer)$/i.test(ms[ms.length - 1][1]);
      const lineRoles = [...line.matchAll(ROLE_RE)];
      const inSystem = lineRoles.length
        ? lastIsSystem(lineRoles)
        : SYSTEM_ASSIGN_RE.test(line) || lastIsSystem([...context.matchAll(ROLE_RE)]);
      const undelimited = tainted.filter((e) => !delimited(line, e));
      if (inSystem) {
        // a system prompt with user data inside it is a finding even if delimited
        hits.push({ evidence: evidence(line), location: { line: ll.index + 1 }, confidence: "high" });
      } else if (INSTRUCTION_PHRASE_RE.test(line) && undelimited.length > 0) {
        hits.push({ evidence: evidence(line), location: { line: ll.index + 1 }, confidence: "medium" });
      }
    });
    return hits;
  },
};
