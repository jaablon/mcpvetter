import { existsSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";

export interface Candidate {
  path: string;
  client: string;
  scope: "user" | "project";
}

/** Standard MCP config locations for common clients, user-level then project-level. */
export function candidatePaths(cwd = process.cwd(), home = homedir(), os = platform()): Candidate[] {
  const appData =
    os === "darwin"
      ? join(home, "Library", "Application Support")
      : os === "win32"
        ? process.env.APPDATA ?? join(home, "AppData", "Roaming")
        : process.env.XDG_CONFIG_HOME ?? join(home, ".config");

  const user: Candidate[] = [
    { path: join(home, ".claude.json"), client: "Claude Code", scope: "user" },
    { path: join(home, ".claude", "settings.json"), client: "Claude Code", scope: "user" },
    { path: join(appData, "Claude", "claude_desktop_config.json"), client: "Claude Desktop", scope: "user" },
    { path: join(home, ".cursor", "mcp.json"), client: "Cursor", scope: "user" },
    { path: join(appData, "Code", "User", "mcp.json"), client: "VS Code", scope: "user" },
    { path: join(appData, "Code", "User", "settings.json"), client: "VS Code", scope: "user" },
    { path: join(appData, "Code - Insiders", "User", "mcp.json"), client: "VS Code Insiders", scope: "user" },
    { path: join(home, ".codeium", "windsurf", "mcp_config.json"), client: "Windsurf", scope: "user" },
    { path: join(home, ".gemini", "settings.json"), client: "Gemini CLI", scope: "user" },
  ];

  const project: Candidate[] = [
    { path: join(cwd, ".mcp.json"), client: "Claude Code", scope: "project" },
    { path: join(cwd, ".cursor", "mcp.json"), client: "Cursor", scope: "project" },
    { path: join(cwd, ".vscode", "mcp.json"), client: "VS Code", scope: "project" },
    { path: join(cwd, ".gemini", "settings.json"), client: "Gemini CLI", scope: "project" },
  ];

  const seen = new Set<string>();
  return [...user, ...project].filter((c) => {
    const key = resolve(c.path);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function discover(cwd?: string, home?: string): Candidate[] {
  return candidatePaths(cwd, home).filter((c) => existsSync(c.path));
}
