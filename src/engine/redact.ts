/**
 * Secret detection and redaction. Shared by the scanner (config values) and code review.
 * Patterns are deliberately specific: a generic "long random string" rule produces
 * false positives, and false positives are what kill this product.
 */
export interface SecretPattern {
  name: string;
  re: RegExp;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: "Anthropic API key", re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: "OpenAI API key", re: /sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  { name: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ },
  { name: "GitHub fine-grained token", re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "Private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { name: "Notion token", re: /\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b/ },
  { name: "Linear API key", re: /\blin_api_[A-Za-z0-9]{32,}\b/ },
  { name: "Supabase/JWT service key", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/ },
  { name: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}\b/ },
  { name: "Database URL with password", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:/@]+:[^\s@/]{3,}@/ },
];

/** Names that indicate a credential when paired with a literal, non-placeholder value. */
export const SECRET_NAME_RE = /(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth|credential|private[_-]?key|access[_-]?key)/i;

const PLACEHOLDER_RE =
  /^(?:<[^>]*>|\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_]+%|x{3,}|\*{3,}|\.{3}|your[-_ ].*|changeme|example|placeholder|todo|none|null|true|false|test|dummy|redacted|\{\{.*\}\})$/i;

export function isPlaceholder(value: string): boolean {
  const v = value.trim().replace(/^["']|["']$/g, "");
  return v.length < 8 || PLACEHOLDER_RE.test(v) || /^(?:env:|op:\/\/|vault:|secret:)/i.test(v);
}

export function findSecret(value: string): SecretPattern | undefined {
  return SECRET_PATTERNS.find((p) => p.re.test(value));
}

/** Show the first 4 characters and the length; never the secret. */
export function maskValue(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}…[redacted ${value.length} chars]`;
}

export function redact(text: string): string {
  let out = text;
  for (const p of SECRET_PATTERNS) {
    const g = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
    out = out.replace(g, (m) => maskValue(m));
  }
  return out;
}

export function truncate(text: string, max = 200): string {
  const t = text.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
}

/** Redact then truncate: the only way evidence should ever be produced. */
export function evidence(text: string, max = 200): string {
  return truncate(redact(text), max);
}
