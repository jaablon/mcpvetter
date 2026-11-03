import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { computeTaint, isCommentLine, isTestFile, REQUEST_SOURCE_RE, windowText } from "../taint.js";

const LOOKUP_RE =
  /\b(?:findById|findByPk|findOne|findUnique|findUniqueOrThrow|findFirst|findOneBy|get_object_or_404|get_or_404|getById|query\.get|objects\.get|session\.get|db\.get)\s*\(|\.filter_by\s*\(|\.filter\s*\(\s*\w+\.id\s*==|WHERE\s+(?:\w+\.)?id\s*=\s*(?:\$\d|\?|%s|:\w+|\$\{)/i;

/** Signals that the handler scopes the record to the caller. */
const OWNERSHIP_RE =
  /\b(?:require_\w+|ensure_\w+|check_\w*(?:access|member|permission|owner)\w*|membership|is_member|Depends\(\s*\w*(?:user|auth|member|org|owner)\w*|req\.user|request\.user|current_user|currentUser|session\.user(?:Id)?|ctx\.state\.user|req\.auth|auth\.uid|getServerSession|auth\(\)|authorize|can\s*\(|permission|policy|has_?access|ensureOwner|assertOwner|forbidden|Forbidden|403)\b/;

/** Scoping column names; count as ownership only when the value is not itself request input. */
const SCOPE_NAME_RE = /\b(owner_?[iI]d|user_?[iI]d|account_?[iI]d|tenant_?[iI]d|org_?[iI]d|organizationId|created_?[bB]y)\b/g;

function scoped(ctx: CodeContext, text: string, requestVars: Set<string>): boolean {
  if (OWNERSHIP_RE.test(text)) return true;
  for (const m of text.matchAll(SCOPE_NAME_RE)) {
    if (!requestVars.has(m[1])) return true;
  }
  return false;
}

/** IDOR is a web-request flaw: only analyse snippets that look like request handlers. */
const WEB_HANDLER_RE =
  /@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|api_route)\s*\(|\b(?:app|router|server)\.(?:get|post|put|patch|delete|all|route)\s*\(|\breq\.(?:params|query|body)|\brequest\.(?:args|form|json|view_args|match_info|path_params)|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b/;

const ID_NAME_RE = /^(?:id|pk|\w*[iI]d|\w*_id|uuid|slug)$/;

export const codeIdor: Rule<CodeContext> = {
  id: "CODE-IDOR-001",
  title: "Record fetched by request ID with no ownership check (IDOR)",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  lab: "lab-06-idor",
  pattern: "auth-sessions",
  why:
    "The endpoint loads a record using an ID taken straight from the request and returns or changes it without checking that it belongs to the caller. Any signed-in user can change the ID in the URL or body and read or modify someone else's data.",
  fix:
    "Scope the lookup to the authenticated user, for example findFirst({ where: { id, userId: req.user.id } }) or Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404(), and return 404 when nothing matches. For shared resources, check an explicit permission before returning the record.",
  method:
    "Flags a record lookup (findById, findUnique, findFirst, findOne, get_object_or_404, query.get, filter_by, or SQL WHERE id = ?) whose ID argument comes from request input or a route parameter, when no ownership or authorization signal (req.user, current_user, request.user, userId, ownerId, tenantId, an authorize/permission call, or a 403) appears within the surrounding handler (8 lines before, 12 after). Only snippets that look like web request handlers are analysed, and test files are skipped. Confidence is medium because ownership can be enforced elsewhere, such as in middleware or row-level security.",
  check(ctx) {
    if (isTestFile(ctx.filename) || !WEB_HANDLER_RE.test(ctx.code)) return [];
    const hits: Hit[] = [];
    const taint = computeTaint(ctx);
    ctx.lines.forEach((line, i) => {
      if (isCommentLine(line) || !LOOKUP_RE.test(line)) return;
      const args = line.slice(line.search(LOOKUP_RE));
      const fromRequest =
        REQUEST_SOURCE_RE.test(args) ||
        (args.match(/[A-Za-z_$][\w$]*/g) ?? []).some((id) => taint.request.has(id) && ID_NAME_RE.test(id));
      // the lookup may also reference an id variable on a nearby SQL params line
      const nearbyParams = !fromRequest && /WHERE/i.test(args) && windowText(ctx.lines, i, 0, 2).match(/\[\s*([A-Za-z_$][\w$.]*)\s*\]|\(\s*([A-Za-z_]\w*)\s*,\s*\)/);
      const viaParams = nearbyParams && [nearbyParams[1], nearbyParams[2]].some((v) => v && (REQUEST_SOURCE_RE.test(v) || taint.request.has(v)));
      if (!fromRequest && !viaParams) return;
      if (scoped(ctx, windowText(ctx.lines, i, 8, 12), taint.request)) return;
      hits.push({ evidence: evidence(line), location: { line: i + 1 } });
    });
    return hits;
  },
};
