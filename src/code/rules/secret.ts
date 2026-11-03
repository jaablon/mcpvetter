import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { isTestFile } from "../taint.js";
import { evidence, findSecret, isPlaceholder, maskValue, SECRET_NAME_RE } from "../../engine/redact.js";

const ASSIGNED_LITERAL_RE =
  /([A-Za-z_$][\w$.-]*)["']?\s*(?:=|:|=>|:=)\s*(?:new\s+\w+\(\s*)?(["'`])([^"'`\s]{8,})\2/g;

/** Values that are public by design (analytics beacons, publishable keys, OAuth client IDs). */
const PUBLIC_VALUE_RE = /data-cf-beacon|publishable|\bpk_(?:live|test)_|site_?key|NEXT_PUBLIC_|VITE_|PUBLIC_|measurement_?id|client_?id|gtag\(|recaptcha/i;

const ENV_LOOKUP_RE = /process\.env|os\.environ|getenv|import\.meta\.env|Deno\.env|config\(|secrets\./;

function looksRandom(v: string): boolean {
  if (/^https?:\/\//i.test(v)) return false;
  if (/^[./~]/.test(v) || /\.(?:json|pem|key|txt|env|ya?ml)$/i.test(v)) return false;
  if (!/[A-Za-z]/.test(v) || !/\d/.test(v)) return false;
  if (/^[A-Z][A-Z0-9_]+$/.test(v)) return false; // looks like an env var name
  return v.length >= 12;
}

export const codeSecret: Rule<CodeContext> = {
  id: "CODE-SECRET-001",
  title: "Hard-coded credential in source code",
  severity: "high",
  confidence: "high",
  evidenceKind: "static",
  lab: "lab-01-secrets",
  pattern: "secret-handling",
  why:
    "A credential written into source code ends up in git history, build artifacts, logs and every copy of the repository. Anyone who can read the code can use the key, and deleting the line later does not remove it from history.",
  fix:
    "Rotate the credential first, because it should be treated as exposed. Then load it from the environment or a secret manager (process.env.NAME, os.environ[\"NAME\"]) and keep the value in an untracked .env file or your platform's secret store.",
  method:
    "Flags string literals that match the format of a known provider credential (Anthropic, OpenAI, AWS, GitHub, Slack, Stripe, Google, Hugging Face, private key blocks, database URLs with passwords) at high confidence. Also flags a literal of 12+ characters mixing letters and digits that is assigned to a name containing key, secret, token, password or credential, at medium confidence. Placeholders (<...>, ${VAR}, your-key, changeme, xxx), environment lookups, and values that are public by design (publishable keys, analytics beacons, client IDs) are ignored; in test and fixture files only known provider formats are flagged.",
  check(ctx) {
    const hits: Hit[] = [];
    // test fixtures routinely contain throwaway passwords; only provider-format keys are flagged there
    const testFile = isTestFile(ctx.filename);
    ctx.lines.forEach((line, i) => {
      const known = findSecret(line);
      if (known) {
        hits.push({ evidence: evidence(line), location: { line: i + 1 }, confidence: "high", fixDetail: `Detected format: ${known.name}.` });
        return;
      }
      if (ENV_LOOKUP_RE.test(line) || testFile) return;
      if (PUBLIC_VALUE_RE.test(line)) return;
      for (const m of line.matchAll(ASSIGNED_LITERAL_RE)) {
        const name = m[1];
        const value = m[3];
        if (!SECRET_NAME_RE.test(name) || /author|oauth_?(?:url|endpoint)|tokeni[sz]er/i.test(name) || /(?:_url|_uri|_path|_file|_name|_type|_header|_endpoint|url|uri|path|file|name|type|header|endpoint)$/i.test(name)) continue;
        if (isPlaceholder(value) || !looksRandom(value)) continue;
        hits.push({
          evidence: evidence(line.replace(value, maskValue(value))),
          location: { line: i + 1 },
          confidence: "medium",
        });
        break;
      }
    });
    return hits;
  },
};
