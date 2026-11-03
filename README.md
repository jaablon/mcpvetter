# mcpvetter

Audit the MCP servers your AI assistant uses: leaked secrets, unpinned or look-alike packages, risky launch commands, unencrypted remote servers, over-broad file access, poisoned tool descriptions, hidden Unicode, tool shadowing, and silent tool changes.

```bash
npx mcpvetter scan          # discover + static scan, offline
npx mcpvetter scan --live   # also read each server's tool descriptions (asks first)
```

Local, no account, no telemetry. A static scan reads your MCP config files and nothing else. It never changes a config file.

## What a finding looks like

```
■ github
[HIGH] Plain-text secret in MCP config  MCP-SECRET-001 · confidence high · static
    server: github  file: .mcp.json
    Evidence: env GITHUB_PERSONAL_ACCESS_TOKEN=ghp_…[redacted 40 chars] (GitHub token)
    Why it matters: Anything that can read this file, including other tools, backups, sync
    folders, and anyone the file is shared or committed with, gets a working credential.
    Fix: Rotate the credential first (removing it does not un-leak it), then reference it
    from the environment or a secret store instead of the literal value. Claude Code and
    Claude Desktop expand "${VAR}" in .mcp.json, Cursor expands "${env:VAR}", and VS Code
    supports "${input:...}" prompts or an "envFile".
```

Every finding has a stable ID, separate severity and confidence, redacted evidence, a plain-English reason, and a concrete fix. What each rule checks, and how, is published at [mcpvetter.com/rules](https://mcpvetter.com/rules) and in [src/scanner/rules](./src/scanner/rules).

## Clients discovered

Claude Code (`~/.claude.json`, `.mcp.json`), Claude Desktop, Cursor (`~/.cursor/mcp.json`, `.cursor/mcp.json`), VS Code (`mcp.json`, `settings.json`, `.vscode/mcp.json`), Windsurf, Gemini CLI. Or pass `--config <file>`.

## Commands

```
mcpvetter scan [--live] [--yes] [--config <file>]... [--json [file]] [--summary] [--fail-on <severity>]
mcpvetter list                               inventory only
mcpvetter explain MCP-POISON-001             explain a finding
mcpvetter rules                              every rule and what it checks
mcpvetter suppress <ID> --server <name> --reason "<why>"
mcpvetter accept <server> --reason "<why>"   accept a server's new tool fingerprint
mcpvetter serve                              run as a local MCP server (stdio)
```

Exit codes: `0` no findings at or above `--fail-on` (default `high`), `1` findings at or above it, `2` scan could not complete. Use it in CI as-is.

Suppressions are always listed in the report, so a shared report cannot hide them.

## About `--live`

To read tool descriptions, MCPVetter has to start each stdio server, exactly as your AI client does every time it launches. It asks before each one, runs it with a minimal environment plus the env your config declares, and only calls `initialize`, `tools/list`, `prompts/list`, and `resources/list`. It never calls a tool. The first approved probe records a fingerprint of each server's tools in `~/.mcpvetter/fingerprints.json`; later probes report any change (a "rug pull") with a before/after diff.

## Inside your AI assistant

Claude Code:

```bash
claude mcp add mcpvetter -- npx -y mcpvetter@0.1.3 serve
```

Cursor / VS Code / Claude Desktop (`mcpServers` or `servers`):

```json
{ "mcpServers": { "mcpvetter": { "command": "npx", "args": ["-y", "mcpvetter@0.1.3", "serve"] } } }
```

Then ask: "audit my MCP setup".

Free without an account: `check_mcp_setup`, `explain_finding`. With an API key (`MCPVETTER_API_KEY`, free tier available at [mcpvetter.com/account](https://mcpvetter.com/account)): `review_code`, `secure_pattern`, `start_lab`, `check_lab`, `team_posture`. Code review runs on your machine; only rule IDs and counts are sent for your history. Plans: [mcpvetter.com/pricing](https://mcpvetter.com/pricing).

## Privacy

- Static analysis runs on your machine. Without an API key, MCPVetter makes no network requests.
- With an API key, only rule IDs, severities, and counts are sent. Never code, evidence, file paths, or server names.
- Reports redact secret values by default.

## License

MIT
