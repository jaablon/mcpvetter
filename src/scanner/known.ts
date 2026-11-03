/**
 * Curated list of widely used MCP server packages. Used only as a reference for
 * typosquat detection: a name that is *almost* one of these, but not exactly, is suspicious.
 * Being on this list is not an endorsement.
 */
export const KNOWN_PACKAGES: string[] = [
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-gitlab",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-brave-search",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-slack",
  "@modelcontextprotocol/server-sequential-thinking",
  "@modelcontextprotocol/server-everything",
  "@modelcontextprotocol/server-gdrive",
  "@modelcontextprotocol/server-google-maps",
  "@modelcontextprotocol/server-redis",
  "@modelcontextprotocol/inspector",
  "mcp-server-fetch",
  "mcp-server-git",
  "mcp-server-time",
  "mcp-server-sqlite",
  "@playwright/mcp",
  "@upstash/context7-mcp",
  "@supabase/mcp-server-supabase",
  "@notionhq/notion-mcp-server",
  "@stripe/mcp",
  "@sentry/mcp-server",
  "@browserbasehq/mcp-server-browserbase",
  "@cloudflare/mcp-server-cloudflare",
  "@executeautomation/playwright-mcp-server",
  "@neondatabase/mcp-server-neon",
  "@heroku/mcp-server",
  "@azure/mcp",
  "@hubspot/mcp-server",
  "@shopify/dev-mcp",
  "@21st-dev/magic",
  "figma-developer-mcp",
  "firecrawl-mcp",
  "exa-mcp-server",
  "mongodb-mcp-server",
  "mcp-remote",
  "tavily-mcp",
  "chrome-devtools-mcp",
  "awslabs.aws-documentation-mcp-server",
  "mcpvetter",
];

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

function split(pkg: string): { scope?: string; base: string } {
  if (pkg.startsWith("@") && pkg.includes("/")) {
    const [scope, base] = pkg.split("/", 2);
    return { scope, base };
  }
  return { base: pkg };
}

/** Returns the known package this name imitates, or undefined. */
export function typosquatOf(pkg: string): string | undefined {
  const name = pkg.toLowerCase();
  if (KNOWN_PACKAGES.includes(name)) return undefined;
  const p = split(name);
  for (const known of KNOWN_PACKAGES) {
    const k = split(known);
    // Whole-name near miss: @modelcontextprotocol/server-filesytem
    if (name.length >= 6 && levenshtein(name, known) <= 2) return known;
    // Scope impersonation: same package, look-alike scope (@modelcontextprotocoI/server-github)
    if (p.scope && k.scope && p.base === k.base && p.scope !== k.scope && levenshtein(p.scope, k.scope) <= 3) return known;
  }
  return undefined;
}
