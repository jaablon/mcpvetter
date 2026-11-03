import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { isCommentLine, llmTainted, requestTainted } from "../taint.js";

const FETCH_RE =
  /(?<![\w.])(?:fetch|got|ky|needle|superagent|urlopen)\s*\(|\baxios(?:\.(?:get|post|put|patch|delete|head|request))?\s*\(|\bhttps?\.(?:get|request)\s*\(|\brequests\.(?:get|post|put|patch|delete|head|request)\s*\(|\bhttpx\.(?:get|post|put|patch|delete|head|request|AsyncClient\(\)\.get)\s*\(|\b(?:client|session|http_client)\.(?:get|post|put|request)\s*\(|urllib\.request\.urlopen\s*\(|\bfile_get_contents\s*\(/;

/** Evidence of a destination allowlist / validation somewhere in the snippet. */
const ALLOWLIST_RE =
  /allow(?:ed)?_?(?:hosts?|list|domains?|origins?|urls?)|ALLOW(?:ED)?_(?:HOSTS?|DOMAINS?|URLS?)|allowlist|whitelist|isAllowed\w*\s*\(|is_allowed\w*\s*\(|validate_?(?:url|host|destination)|assertSafeUrl|safe_?url|is_?private|isPrivate|ipaddr|ip_address\(|private_ips|block_?private/i;

function firstArg(line: string): string {
  const m = line.match(FETCH_RE);
  if (!m || m.index === undefined) return "";
  const rest = line.slice(m.index + m[0].length);
  let depth = 0;
  let out = "";
  for (const ch of rest) {
    if ("([{".includes(ch)) depth++;
    if (")]}".includes(ch)) {
      if (depth === 0) break;
      depth--;
    }
    if (ch === "," && depth === 0) break;
    out += ch;
  }
  return out.trim();
}

/** fetch(`https://api.fixed.com/users/${id}`) has a fixed host: not SSRF. */
function fixedHost(arg: string): boolean {
  return /^(?:f?["'`])https?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/|["'`]|$)/.test(arg) || /^(?:f?["'`])\//.test(arg);
}

export const codeSsrf: Rule<CodeContext> = {
  id: "CODE-SSRF-001",
  title: "Server fetches a user-supplied URL (SSRF)",
  severity: "high",
  confidence: "high",
  evidenceKind: "static",
  lab: "lab-08-ssrf",
  pattern: "url-fetching",
  why:
    "If the server requests whatever URL a user provides, the user can point it at internal addresses such as cloud metadata endpoints, admin panels or databases that are not reachable from the internet. The response, or even its timing, can leak credentials and internal data.",
  fix:
    "Only fetch destinations you expect: parse the URL, require https, check the hostname against an allowlist, resolve DNS and reject private, loopback and link-local addresses, and disable redirects (or re-check every redirect target). For webhooks, validate the URL when it is saved and again when it is called.",
  method:
    "Flags outbound HTTP calls (fetch, axios, got, http.get, requests, httpx, urllib urlopen, client.get) whose URL argument is request input or model output in the same snippet. Calls whose URL starts with a fixed scheme and host (only the path varies) are not flagged, and no finding is raised when the snippet contains a destination allowlist or private-address check.",
  check(ctx) {
    if (ALLOWLIST_RE.test(ctx.code)) return [];
    const hits: Hit[] = [];
    ctx.lines.forEach((line, i) => {
      if (isCommentLine(line) || !FETCH_RE.test(line)) return;
      const arg = firstArg(line);
      if (!arg || fixedHost(arg)) return;
      const urlExpr = arg.replace(/^\{\s*url\s*:\s*/, "");
      if (requestTainted(ctx, urlExpr) || llmTainted(ctx, urlExpr)) {
        hits.push({ evidence: evidence(line), location: { line: i + 1 } });
      }
    });
    return hits;
  },
};
