import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { isCommentLine, windowText } from "../taint.js";

interface Check {
  re: RegExp;
  detail: string;
  confidence: "high" | "medium" | "low";
  severity?: "critical" | "high" | "medium";
  /** Return true to suppress this hit given the whole snippet and line index. */
  unless?: (ctx: CodeContext, i: number) => boolean;
  lang?: "js" | "python";
}

const isPy = (ctx: CodeContext) => ctx.language === "python";

const CHECKS: Check[] = [
  {
    re: /\bjwt\.decode\s*\(/,
    lang: "js",
    detail: "jwt.decode() only parses the token; it does not check the signature. Use jwt.verify(token, secret, { algorithms: [\"HS256\"] }).",
    confidence: "high",
    unless: (ctx) => /\bjwt\.verify\s*\(|jwtVerify\s*\(/.test(ctx.code),
  },
  {
    re: /verify_signature["']?\s*:\s*False|\bverify\s*=\s*False|options\s*=\s*\{[^}]*["']verify_signature["']\s*:\s*False/,
    lang: "python",
    detail: "Signature verification is disabled. Remove the option and pass algorithms=[\"HS256\"] (or your algorithm) to jwt.decode().",
    confidence: "high",
  },
  {
    re: /algorithms?\s*[:=]\s*\[?\s*["']none["']/i,
    detail: "The \"none\" algorithm accepts unsigned tokens. Allow only the algorithm you sign with.",
    confidence: "high",
    severity: "critical",
  },
  {
    re: /\bjwt\.sign\s*\(/,
    detail: "Token is signed without an expiry. Add { expiresIn: \"15m\" } (or a short lifetime that fits) and refresh tokens server-side.",
    confidence: "medium",
    severity: "medium",
    unless: (ctx, i) => /expiresIn|\bexp\s*:/.test(windowText(ctx.lines, i, 6, 4)),
  },
  {
    re: /\bjwt\.encode\s*\(/,
    lang: "python",
    detail: "Token is created without an \"exp\" claim. Include \"exp\": datetime.now(timezone.utc) + timedelta(minutes=15).",
    confidence: "medium",
    severity: "medium",
    unless: (ctx, i) => /["']exp["']|\bexp\s*=/.test(windowText(ctx.lines, i, 8, 3)),
  },
  {
    re: /\b\w*pass(?:word|wd)\w*["']?\]?(?:\.\w+|\[["']\w+["']\])*\s*(?:===?|!==?)\s*[\w.[\]"']*pass(?:word|wd)/i,
    detail: "Passwords are compared as plain text, which means they are stored unhashed. Store a bcrypt/argon2 hash and compare with bcrypt.compare() / argon2.verify() / check_password_hash().",
    confidence: "high",
    unless: (ctx, i) => /hash|bcrypt|argon|scrypt|compare|confirm|repeat|again|new_?password\s*[!=]==?\s*confirm/i.test(ctx.lines[i]),
  },
  {
    re: /(?:createHash\s*\(\s*["'](?:md5|sha1|sha256)["']|hashlib\.(?:md5|sha1|sha256)\s*\(|\bmd5\s*\(|\bsha1\s*\()/i,
    detail: "Fast hashes (MD5, SHA-1, SHA-256) are not password hashes; leaked hashes can be cracked quickly. Use bcrypt, scrypt or argon2 with a per-user salt.",
    confidence: "high",
    unless: (ctx, i) => !/pass(?:word|wd)|pwd/i.test(windowText(ctx.lines, i, 1, 1)),
  },
  {
    re: /localStorage\.getItem\s*\(\s*["'](?:isLoggedIn|loggedIn|isAdmin|is_admin|role|isAuthenticated|authenticated|admin)["']\s*\)/,
    detail: "Access is decided by a value in localStorage that the user can edit. Enforce authorization on the server for every request.",
    confidence: "high",
  },
  {
    re: /\b(?:httpOnly|httponly)\s*:\s*false|\bsecure\s*:\s*false|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|httponly\s*=\s*False/,
    detail: "Session cookie is missing HttpOnly or Secure. Set httpOnly: true, secure: true and sameSite: \"lax\" (or stricter).",
    confidence: "medium",
    severity: "medium",
  },
];

export const codeAuth: Rule<CodeContext> = {
  id: "CODE-AUTH-001",
  title: "Weak authentication or session handling",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  lab: "lab-05-auth",
  pattern: "auth-sessions",
  why:
    "Login and session code that looks finished can still let anyone in: tokens that are never verified or never expire, passwords stored in plain text or with fast hashes, and access decisions made in the browser. These flaws turn one leaked token or database dump into full account takeover.",
  fix:
    "Verify every token's signature with a fixed algorithm, give tokens a short expiry, hash passwords with bcrypt or argon2, set session cookies HttpOnly and Secure, and make every authorization decision on the server.",
  method:
    "Flags: jwt.decode() in JavaScript when the snippet never calls jwt.verify(); PyJWT decode with verify_signature False; the \"none\" algorithm; jwt.sign() / jwt.encode() without an expiry nearby; equality comparison between two password values (no hash or compare call on the line); MD5/SHA-1/SHA-256 next to the word password; authorization flags read from localStorage; session cookies with httpOnly or secure set to false.",
  check(ctx) {
    const hits: Hit[] = [];
    ctx.lines.forEach((line, i) => {
      if (isCommentLine(line)) return;
      for (const c of CHECKS) {
        if (c.lang === "js" && isPy(ctx)) continue;
        if (c.lang === "python" && !isPy(ctx)) continue;
        if (!c.re.test(line)) continue;
        if (c.unless?.(ctx, i)) continue;
        hits.push({ evidence: evidence(line), location: { line: i + 1 }, confidence: c.confidence, severity: c.severity, fixDetail: c.detail });
        break;
      }
    });
    return hits;
  },
};
