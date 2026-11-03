import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { checkLab } from "../code/labs.js";
import { reviewCode } from "../code/review.js";
import { getRuleMeta } from "../engine/registry.js";
import type { Finding } from "../engine/types.js";
import { counts } from "../scanner/report.js";
import type { ScanResult } from "../scanner/types.js";
import { PaywallError, type Backend, type GatedTool, type Pattern } from "./backend.js";

type Text = { content: { type: "text"; text: string }[]; isError?: boolean };
const text = (t: string, isError = false): Text => ({ content: [{ type: "text", text: t }], ...(isError ? { isError } : {}) });

export interface ToolOptions {
  /** Local mode: scan the machine's MCP configs. Remote mode: scan pasted config text. */
  scan?: (configText?: string) => Promise<ScanResult>;
}

function renderFindings(findings: Finding[], origin: string, max = 8): string {
  return findings
    .slice(0, max)
    .map((f, i) => {
      const where = f.location?.line ? ` (line ${f.location.line})` : f.location?.server ? ` (server ${f.location.server})` : "";
      const lines = [
        `${i + 1}. **[${f.severity.toUpperCase()}] ${f.title}**${where} · ${f.id} · confidence ${f.confidence}`,
        `   Evidence: \`${f.evidence.replace(/`/g, "'")}\``,
        `   Fix: ${f.fix}`,
      ];
      if (f.lab) lines.push(`   Lab: start_lab("${f.lab}") or ${origin}/labs/${f.lab}`);
      return lines.join("\n");
    })
    .join("\n\n");
}

async function gate(backend: Backend, tool: GatedTool): Promise<Text | undefined> {
  const a = await backend.authorize(tool);
  if (!a.allowed) return text(a.message ?? `This needs an MCPVetter plan that includes ${tool}. See ${backend.origin}/pricing`);
  return undefined;
}

async function guarded(fn: () => Promise<Text>): Promise<Text> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof PaywallError || (e as Error)?.name === "PaywallError") {
      const pe = e as PaywallError;
      return text(`${pe.message}${pe.upgradeUrl ? `\nUpgrade: ${pe.upgradeUrl}` : ""}`);
    }
    return text(`MCPVetter error: ${(e as Error).message}`, true);
  }
}

export function matchPattern(request: string, list: Pick<Pattern, "id" | "title" | "keywords">[]): string | undefined {
  const q = request.toLowerCase();
  let best: { id: string; score: number } | undefined;
  for (const p of list) {
    let score = q.includes(p.id.replace(/-/g, " ")) || q.includes(p.id) ? 5 : 0;
    for (const k of p.keywords) if (q.includes(k.toLowerCase())) score += k.includes(" ") ? 3 : 2;
    for (const w of p.title.toLowerCase().split(/\W+/)) if (w.length > 3 && q.includes(w)) score += 1;
    if (score > 0 && (!best || score > best.score)) best = { id: p.id, score };
  }
  return best?.id;
}

function stackOf(request: string, stack?: string): string | undefined {
  const s = `${stack ?? ""} ${request}`.toLowerCase();
  if (/python|django|flask|fastapi|\bpy\b/.test(s)) return "python";
  if (/node|express|next|react|typescript|javascript|\bts\b|\bjs\b|nest|hono/.test(s)) return "node";
  return undefined;
}

export function registerTools(server: McpServer, backend: Backend, opts: ToolOptions = {}): void {
  const o = backend.origin;

  server.registerTool(
    "review_code",
    {
      title: "Review code for security flaws",
      description:
        "Check a code snippet for security flaws before presenting or committing it. Call this before showing the user any generated code that handles authentication, sessions, database queries, user or LLM input, HTML rendering, file uploads, outbound URL fetches, secrets, or MCP configuration. Returns prioritised findings, each with evidence, a concrete fix, and a 5-minute lab. Analysis is static and deterministic; it checks at the moment of generation and is not a guarantee.",
      inputSchema: {
        code: z.string().min(1).max(200_000).describe("The code to review (a snippet or a whole file)."),
        language: z.string().optional().describe("javascript, typescript, python, or json. Detected if omitted."),
        filename: z.string().optional().describe("Optional file name, used for language detection only."),
        ai_generated: z.boolean().optional().describe("True if an AI assistant produced this code."),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ code, language, filename }) =>
      guarded(async () => {
        const blocked = await gate(backend, "review_code");
        if (blocked) return blocked;
        const findings = reviewCode(code, { language, filename });
        await backend.recordHistory("review_code", findings.map((f) => ({ id: f.id, severity: f.severity })));
        if (!findings.length) {
          return text("No issues found by MCPVetter's code rules. These are static checks for common AI-generated flaws (secrets, injection, unsafe LLM output, auth, IDOR, XSS, SSRF, uploads, MCP config), not a full audit.");
        }
        const c = counts(findings);
        const where = backend.mode === "local" ? "Analysed on this machine; the code was not uploaded." : "Analysed in memory on the MCPVetter server; the code was not stored.";
        return text(
          `${findings.length} finding(s): ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low. ${where}\n\n${renderFindings(findings, o)}${findings.length > 8 ? `\n\n…and ${findings.length - 8} more.` : ""}\n\nFor a deeper explanation call explain_finding with the ID. For the secure version call secure_pattern.`,
        );
      }),
  );

  server.registerTool(
    "explain_finding",
    {
      title: "Explain a security finding",
      description:
        "Explain an MCPVetter finding in plain English: why it matters, how the flaw is triggered (in general, defensive terms), why a code reviewer would block it, and how to fix it. Call this when the user asks what a finding ID (like CODE-SQLI-001 or MCP-POISON-001) means or why it matters.",
      inputSchema: { id: z.string().describe("Finding ID, e.g. CODE-SQLI-001 or MCP-SECRET-001.") },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ id }) =>
      guarded(async () => {
        const ruleId = id.trim().toUpperCase().match(/(?:MCP|CODE)-[A-Z]+-\d{3}/)?.[0];
        const meta = ruleId ? getRuleMeta(ruleId) : undefined;
        if (!meta || !ruleId) return text(`Unknown finding ID "${id}". All rules and their methods: ${o}/rules`);
        const blocked = await gate(backend, "explain_finding");
        if (blocked) return text(`**${meta.id}: ${meta.title}**\n\n${meta.why}\n\nFix: ${meta.fix}\n\n${blocked.content[0].text}`);
        const ex = await backend.getExplanation(ruleId).catch(() => undefined);
        const parts = [
          `**${meta.id}: ${meta.title}** (default severity ${meta.severity})`,
          ex?.plain ?? meta.why,
          ex?.howItIsTriggered ? `How it is triggered: ${ex.howItIsTriggered}` : "",
          ex?.reviewerReason ? `Why a reviewer would block this: ${ex.reviewerReason}` : "",
          `Fix: ${meta.fix}`,
          `What MCPVetter checks: ${meta.method}`,
          meta.lab ? `Practice the fix: start_lab("${meta.lab}")` : "",
          meta.pattern ? `Secure pattern: secure_pattern("${meta.pattern}")` : "",
        ];
        return text(parts.filter(Boolean).join("\n\n"));
      }),
  );

  server.registerTool(
    "secure_pattern",
    {
      title: "Get the secure version of a coding pattern",
      description:
        'Return a vetted secure code example for a pattern in the user\'s stack, the insecure version to avoid, and a reviewer checklist. Call this when writing code for: database queries, secrets/API keys, login and sessions, rendering user content as HTML, sending user input to an LLM, using LLM output, file uploads, fetching URLs/webhooks, or configuring MCP servers. Example requests: "parameterised query in Node", "safe handling of LLM output in Python".',
      inputSchema: {
        request: z.string().describe("What you need, e.g. 'parameterized query in Node' or a pattern id like 'url-fetching'."),
        stack: z.string().optional().describe("Optional stack hint: node, python, express, django, fastapi, next..."),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ request, stack }) =>
      guarded(async () => {
        const blocked = await gate(backend, "secure_pattern");
        if (blocked) return blocked;
        const list = await backend.listPatterns();
        const id = list.find((p) => p.id === request.trim())?.id ?? matchPattern(request, list);
        if (!id) return text(`No pattern matched "${request}". Available: ${list.map((p) => p.id).join(", ")}`);
        const p = await backend.getPattern(id);
        if (!p) return text(`Pattern ${id} not found.`);
        const want = stackOf(request, stack);
        const ex = p.examples.find((e) => e.stack.toLowerCase().includes(want ?? "~")) ?? p.examples.find((e) => e.language === want) ?? p.examples[0];
        const others = p.examples.filter((e) => e !== ex).map((e) => e.stack);
        return text(
          [
            `**${p.title}** (pattern ${p.id} v${p.version})`,
            p.summary,
            ex ? `Secure (${ex.stack}):\n\`\`\`${ex.language}\n${ex.secure}\n\`\`\`` : "",
            ex ? `Avoid:\n\`\`\`${ex.language}\n${ex.insecure}\n\`\`\`` : "",
            ex?.notes ?? "",
            `Reviewer checklist:\n${p.checklist.map((c) => `- [ ] ${c}`).join("\n")}`,
            others.length ? `Also available for: ${others.join(", ")} (pass stack).` : "",
          ]
            .filter(Boolean)
            .join("\n\n"),
        );
      }),
  );

  server.registerTool(
    "start_lab",
    {
      title: "Start a 5-minute secure-coding lab",
      description:
        "Start a short hands-on lab that fixes one vulnerability in realistic AI-generated code. Call this when the user wants to learn how to fix a finding, or after review_code reports a finding with a lab. Pass a lab id (lab-02-sqli) or a finding id (CODE-SQLI-001). Then help the user fix the snippet and submit it with check_lab.",
      inputSchema: {
        lab_id: z.string().optional().describe("Lab id, e.g. lab-02-sqli. Omit to list labs."),
        finding_id: z.string().optional().describe("Finding id; the matching lab is opened."),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ lab_id, finding_id }) =>
      guarded(async () => {
        const blocked = await gate(backend, "start_lab");
        if (blocked) return blocked;
        let id = lab_id?.trim();
        if (!id && finding_id) id = getRuleMeta(finding_id.trim().toUpperCase())?.lab;
        if (!id) {
          const labs = await backend.listLabs();
          return text(`Labs:\n${labs.map((l) => `- ${l.id}: ${l.title} (${l.minutes} min${l.free ? ", free" : ""})`).join("\n")}\n\nStart one with start_lab(lab_id).`);
        }
        const lab = await backend.getLab(id);
        if (!lab) return text(`No lab "${id}". Call start_lab with no arguments to list labs.`);
        return text(
          [
            `**Lab ${lab.number}: ${lab.title}** (~${lab.minutes} min)`,
            lab.summary,
            `Scenario: ${lab.scenario}`,
            `Vulnerable code:\n\`\`\`${lab.language}\n${lab.vulnerable}\n\`\`\``,
            `Steps:\n${lab.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}`,
            `When the fix is ready, call check_lab with lab_id "${lab.id}" and the full fixed code. Ask for a hint any time; there are ${lab.hints.length}.`,
            `Hints (reveal one at a time, only if asked):\n${lab.hints.map((h, i) => `${i + 1}. ${h}`).join("\n")}`,
          ].join("\n\n"),
        );
      }),
  );

  server.registerTool(
    "check_lab",
    {
      title: "Check a lab solution",
      description: "Verify a fixed snippet for a lab started with start_lab. Runs the lab's security checks on the code and records progress. Call this when the user says their lab fix is ready.",
      inputSchema: {
        lab_id: z.string().describe("The lab id, e.g. lab-02-sqli."),
        code: z.string().min(1).max(50_000).describe("The complete fixed code."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ lab_id, code }) =>
      guarded(async () => {
        const blocked = await gate(backend, "check_lab");
        if (blocked) return blocked;
        const lab = await backend.getLab(lab_id.trim());
        if (!lab) return text(`No lab "${lab_id}".`);
        const r = checkLab(lab.check, code, lab.language);
        await backend.recordLabResult(lab.id, r.passed);
        if (r.passed) {
          return text(`✅ Lab ${lab.number} passed: ${lab.title}. Progress saved.\n\nReference solution for comparison:\n\`\`\`${lab.language}\n${lab.solution}\n\`\`\``);
        }
        return text(`Not yet. ${r.failures.length} check(s) still failing:\n${r.failures.map((f) => `- ${f}`).join("\n")}\n\nFix and call check_lab again.`);
      }),
  );

  server.registerTool(
    "check_mcp_setup",
    {
      title: "Audit MCP server setup",
      description:
        backend.mode === "local"
          ? "Audit the MCP servers configured on this machine (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI) for leaked secrets, unpinned or look-alike packages, risky launch commands, unencrypted remote servers, over-broad file access, and dangerous server combinations. Call this when the user asks whether their MCP setup or a server is safe. Static and local; for tool-description poisoning run `npx mcpvetter scan --live` in a terminal."
          : "Audit an MCP configuration for leaked secrets, unpinned or look-alike packages, risky launch commands, unencrypted remote servers, over-broad file access, and dangerous server combinations. This remote server cannot read your files: pass the JSON of your MCP config (mcp.json, .mcp.json, claude_desktop_config.json). Secret values are redacted in the output and the config is not stored.",
      inputSchema: {
        config: z.string().max(200_000).optional().describe(backend.mode === "local" ? "Optional pasted config JSON; omit to scan this machine." : "MCP config JSON to audit."),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ config }) =>
      guarded(async () => {
        if (!opts.scan) return text("MCP setup scanning is not available on this server.");
        if (backend.mode === "remote" && !config) return text("Paste your MCP config JSON as `config` (from ~/.cursor/mcp.json, .mcp.json, or claude_desktop_config.json). For a full local scan including live tool inspection run: npx mcpvetter scan --live");
        const blocked = await gate(backend, "check_mcp_setup");
        if (blocked) return blocked;
        const r = await opts.scan(config);
        await backend.recordHistory("check_mcp_setup", r.findings.map((f) => ({ id: f.id, severity: f.severity })));
        const c = counts(r.findings);
        const head = `${r.servers.length} MCP server(s) in ${r.files.length} config file(s): ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low.`;
        if (!r.findings.length) return text(`${head}\nNo findings from static checks.${r.notes.length ? `\n${r.notes.join("\n")}` : ""}\nFor tool-description poisoning and drift checks run: npx mcpvetter scan --live`);
        return text(`${head}\n\n${renderFindings(r.findings, o, 10)}${r.notes.length ? `\n\nNotes:\n${r.notes.map((n) => `- ${n}`).join("\n")}` : ""}${r.suppressed.length ? `\n\n${r.suppressed.length} suppressed finding(s) not shown.` : ""}`);
      }),
  );

  server.registerTool(
    "team_posture",
    {
      title: "Team security posture",
      description: "Team plan: aggregated, de-identified counts of recurring code findings, MCP risk by category, and lab completion for the user's team over the last 30 days. No code or per-developer detail. Call this when a team lead asks how exposed the team is or which flaws keep recurring.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () =>
      guarded(async () => {
        const blocked = await gate(backend, "team_posture");
        if (blocked) return blocked;
        const p = await backend.teamPosture();
        if (!p) return text(`No team found for this account. Team plan: ${o}/pricing`);
        const fmt = (xs: { id?: string; category?: string; count: number }[]) => (xs.length ? xs.map((x) => `- ${x.id ?? x.category}: ${x.count}`).join("\n") : "- none");
        return text(
          `**${p.team}**, last ${p.periodDays} days, ${p.members} member(s)\n\nRecurring code findings:\n${fmt(p.codeFindingsByRule)}\n\nMCP risk by category:\n${fmt(p.mcpRiskByCategory)}\n\nLabs: ${p.labs.completed} completed of ${p.labs.assigned} started.`,
        );
      }),
  );
}
