import { evidence, findSecret, isPlaceholder, maskValue, SECRET_NAME_RE } from "../../engine/redact.js";
import type { Hit, Rule } from "../../engine/types.js";
import { typosquatOf } from "../known.js";
import { commandBase, effectiveCommand, isShell, launchInfo, serverIdentityText } from "../launch.js";
import type { ScanContext, ServerEntry } from "../types.js";

const loc = (s: ServerEntry) => ({ server: s.name, file: s.source });

const ENV_REF_FIX =
  'Claude Code and Claude Desktop expand "${VAR}" in .mcp.json, Cursor expands "${env:VAR}", and VS Code supports "${input:...}" prompts or an "envFile".';

export const parseRule: Rule<ScanContext> = {
  id: "MCP-PARSE-001",
  title: "MCP config could not be fully read",
  severity: "medium",
  confidence: "high",
  evidenceKind: "static",
  why: "A config file or server entry that cannot be parsed is not scanned, so anything risky inside it is invisible to this report. Clients may also load it differently than you expect.",
  fix: "Fix the JSON syntax or the server entry (each server needs a command or a url), then re-run the scan.",
  method: "Reports any discovered config file that cannot be read or parsed as JSON/JSONC, and any server entry that is not an object or has neither a command nor a url.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const f of ctx.files) if (f.error) hits.push({ evidence: evidence(f.error), location: { file: f.path } });
    for (const e of ctx.parseErrors) hits.push({ evidence: evidence(e.message), location: { file: e.source }, severity: "low" });
    return hits;
  },
};

export const dupRule: Rule<ScanContext> = {
  id: "MCP-DUP-001",
  title: "Same server name configured differently in more than one place",
  severity: "low",
  confidence: "high",
  evidenceKind: "static",
  why: "When two configs define the same server name with different launch details, which one runs depends on the client and its precedence rules. A project config can silently override the server you reviewed.",
  fix: "Keep one definition per server name, or rename one so you know which server the assistant is talking to.",
  method: "Groups servers by name across all discovered files and reports names whose command, arguments, or url differ between files.",
  check(ctx) {
    const byName = new Map<string, ServerEntry[]>();
    for (const s of ctx.servers) byName.set(s.name, [...(byName.get(s.name) ?? []), s]);
    const hits: Hit[] = [];
    for (const [name, list] of byName) {
      const shapes = new Set(list.map((s) => JSON.stringify([s.command, s.args, s.url])));
      if (list.length > 1 && shapes.size > 1) {
        hits.push({ evidence: `"${name}" defined in: ${list.map((s) => s.source).join(", ")}`, location: { server: name } });
      }
    }
    return hits;
  },
};

function secretHits(s: ServerEntry): Hit[] {
  const hits: Hit[] = [];
  const projectScoped = s.scope === "project";
  const sev = projectScoped ? "high" : "medium";
  const where = projectScoped ? " This file lives in a project and is often committed." : "";
  for (const [k, v] of Object.entries(s.env)) {
    const pat = findSecret(v);
    if (pat) {
      hits.push({ evidence: `env ${k}=${maskValue(v)} (${pat.name})`, location: loc(s), severity: sev, confidence: "high", fixDetail: where.trim() || undefined });
    } else if (SECRET_NAME_RE.test(k) && !isPlaceholder(v) && v.length >= 12 && /[A-Za-z]/.test(v) && /\d/.test(v)) {
      hits.push({ evidence: `env ${k}=${maskValue(v)}`, location: loc(s), severity: sev, confidence: "medium", fixDetail: where.trim() || undefined });
    }
  }
  s.args.forEach((a, i) => {
    const pat = findSecret(a);
    const flag = a.match(/^--?(?:api[-_]?key|token|secret|password|access[-_]?token)(?:=(.+))?$/i);
    if (pat) hits.push({ evidence: `args[${i}] ${evidence(a)} (${pat.name})`, location: loc(s), severity: "high", confidence: "high" });
    else if (flag) {
      const val = flag[1] ?? s.args[i + 1];
      if (val && !isPlaceholder(val) && !val.startsWith("-")) {
        hits.push({ evidence: `args[${i}] ${a.split("=")[0]} ${maskValue(val)}`, location: loc(s), severity: "high", confidence: "medium", fixDetail: "Secrets in arguments are also visible to every local user via the process list." });
      }
    }
  });
  for (const [k, v] of Object.entries(s.headers)) {
    const bearer = v.match(/^(?:Bearer|Basic|Token)\s+(.+)$/i);
    const value = bearer ? bearer[1] : v;
    if (findSecret(v) || ((/^authorization$|api[-_]?key|token/i.test(k)) && !isPlaceholder(value) && value.length >= 12)) {
      hits.push({ evidence: `header ${k}: ${maskValue(value)}`, location: loc(s), severity: sev, confidence: "high" });
    }
  }
  if (s.url) {
    try {
      const u = new URL(s.url);
      if (u.password) hits.push({ evidence: `url contains a password for user "${u.username}"`, location: loc(s), severity: "high", confidence: "high" });
      for (const [k, v] of u.searchParams) {
        if (/key|token|secret|auth|password/i.test(k) && !isPlaceholder(v)) {
          hits.push({ evidence: `url query ${k}=${maskValue(v)}`, location: loc(s), severity: sev, confidence: "high" });
        }
      }
    } catch {
      /* not a URL; transport rule handles it */
    }
  }
  return hits;
}

export const secretRule: Rule<ScanContext> = {
  id: "MCP-SECRET-001",
  title: "Plain-text secret in MCP config",
  severity: "high",
  confidence: "high",
  evidenceKind: "static",
  why: "Anything that can read this file, including other tools, backups, sync folders, and anyone the file is shared or committed with, gets a working credential. Assistants also read project files, so a key in a config can end up in a prompt or a log.",
  fix: `Rotate the credential first (removing it does not un-leak it), then reference it from the environment or a secret store instead of the literal value. ${ENV_REF_FIX}`,
  method: "Checks env values, arguments, headers, and URLs of every server against specific credential formats (Anthropic, OpenAI, AWS, GitHub, Slack, Stripe, Google, private keys, database URLs with passwords and more), and flags literal non-placeholder values under credential-like names (API_KEY, TOKEN, SECRET, PASSWORD). Placeholders like ${VAR}, <your-key>, and env:/op:// references are ignored. Severity is High for project-scoped files (likely committed) and Medium for files in your home directory.",
  lab: "lab-01-secrets",
  pattern: "secret-handling",
  check: (ctx) => ctx.servers.flatMap(secretHits),
};

const SHELL_META = /(\|\s*(?:sh|bash|zsh|python3?|node)\b|&&|\|\||;|\$\(|`|>\s*\S|<\s*\S|\|)/;

export const shellRule: Rule<ScanContext> = {
  id: "MCP-SHELL-001",
  title: "Shell command embedded in server launch",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  why: "A launch line that runs a shell script, pipes a download into a shell, or chains commands runs more than an MCP server. Every time the client starts, that script runs with your user's full permissions, and it is hard to review what it actually does.",
  fix: "Launch the server binary or package directly with a pinned version (for example npx -y package@1.2.3) and pass configuration through env, not a shell one-liner.",
  method: "Flags servers whose command is a shell (sh, bash, zsh, cmd, PowerShell) given an inline script containing pipes, command chaining, substitution, or redirection, and any argument that pipes a download into an interpreter (curl ... | sh). The plain Windows wrapper `cmd /c npx ...` is not flagged.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const s of ctx.servers) {
      const joined = s.args.join(" ");
      const downloadPipe = /\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^|]*\|\s*(?:sh|bash|zsh|python3?|iex|node)\b/i.test(joined);
      if (downloadPipe) {
        hits.push({ evidence: evidence(`${s.command} ${joined}`), location: loc(s), severity: "critical", confidence: "high" });
        continue;
      }
      const { command } = effectiveCommand(s);
      if (isShell(command) || isShell(s.command)) {
        const inline = s.args.find((a, i) => i > 0 && /^(?:-c|\/c|\/k|-Command|-EncodedCommand)$/i.test(s.args[i - 1] ?? ""));
        if (inline && SHELL_META.test(inline)) hits.push({ evidence: evidence(`${commandBase(s.command)} ${joined}`), location: loc(s) });
        if (s.args.some((a) => /^-EncodedCommand$/i.test(a))) hits.push({ evidence: evidence(`${commandBase(s.command)} ${joined}`), location: loc(s), confidence: "high" });
      }
    }
    return hits;
  },
};

export const unpinnedRule: Rule<ScanContext> = {
  id: "MCP-SUPPLY-001",
  title: "Server package version is not pinned",
  severity: "medium",
  confidence: "high",
  evidenceKind: "static",
  why: "Without a pinned version, every client start can download and run whatever the publisher (or anyone who takes over the package) released last. A server you reviewed last month is not the server you are running today.",
  fix: "Pin an exact version you have reviewed (npx -y package@1.2.3, uvx package==1.2.3, image:tag or image@sha256:...), and re-scan after each deliberate upgrade.",
  method: "Extracts the package from npx, bunx, pnpm/yarn dlx, uvx, uv tool run, pipx run, and docker/podman run launch lines. npm specs are pinned only with an exact semver (not ranges or @latest); Python specs need ==version; images need a non-latest tag or a digest.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const s of ctx.servers) {
      const li = launchInfo(s);
      if (li.runner !== "other" && li.spec && !li.pinned && !li.fromUrl) {
        hits.push({ evidence: `${li.runner} ${li.spec}${li.version ? ` (version "${li.version}" is not exact)` : ""}`, location: loc(s) });
      }
    }
    return hits;
  },
};

export const fromUrlRule: Rule<ScanContext> = {
  id: "MCP-SUPPLY-002",
  title: "Server installed straight from a URL or git repository",
  severity: "high",
  confidence: "high",
  evidenceKind: "static",
  why: "Installing from a URL or a git branch skips the registry's publisher identity and version history. Whoever controls that URL or branch can change the code you run at any time, with no version number to notice.",
  fix: "Install a published, pinned release from the package registry instead. If you must use git, pin a full commit SHA, not a branch or tag.",
  method: "Flags package specs that start with git+, git:, github:, gitlab:, bitbucket:, http(s)://, or file:, or that point at a .tgz/.tar.gz/.whl/.zip archive. A git spec pinned to a full 40-character commit SHA is reported at Low severity.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const s of ctx.servers) {
      const li = launchInfo(s);
      if (li.fromUrl && li.spec) {
        const sha = /#[0-9a-f]{40}\b|@[0-9a-f]{40}\b/.test(li.spec);
        hits.push({ evidence: evidence(`${li.runner} ${li.spec}`), location: loc(s), severity: sha ? "low" : "high" });
      }
    }
    return hits;
  },
};

export const typosquatRule: Rule<ScanContext> = {
  id: "MCP-SUPPLY-003",
  title: "Package name looks like a typo of a popular MCP server",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  why: "Attackers publish packages one or two characters away from popular ones and wait for a typo. A look-alike name is the single most common way malicious packages reach developer machines.",
  fix: "Compare the name character by character with the official package. If it is not the one you meant, remove it from the config and check what it may have accessed while it ran.",
  method: "Compares each launched package name with a published list of widely used MCP server packages. Flags names within an edit distance of 2 of a known package (but not identical), and known package names published under a look-alike scope.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const s of ctx.servers) {
      const li = launchInfo(s);
      if (!li.name || li.runner === "docker" || li.fromUrl) continue;
      const known = typosquatOf(li.name);
      if (known) hits.push({ evidence: `"${li.name}" is close to "${known}"`, location: loc(s) });
    }
    return hits;
  },
};

const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal|[^.]+\.localhost)$/i;

export const transportRule: Rule<ScanContext> = {
  id: "MCP-TRANSPORT-001",
  title: "Remote MCP server over unencrypted HTTP",
  severity: "high",
  confidence: "high",
  evidenceKind: "static",
  why: "Over plain HTTP, anyone on the network path (coffee-shop Wi-Fi, a proxy, a compromised router) can read every prompt, tool result, and token, and can inject their own tool descriptions into what the model sees.",
  fix: "Use the server's https:// endpoint. If it has none, do not send it anything sensitive, or run it locally over stdio instead.",
  method: "Flags remote servers whose url uses http:// with a host that is not loopback (localhost, 127.0.0.0/8, ::1, *.localhost). Malformed URLs are reported at Medium.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const s of ctx.servers) {
      if (!s.url) continue;
      let u: URL;
      try {
        u = new URL(s.url);
      } catch {
        hits.push({ evidence: evidence(`url "${s.url}" is not a valid URL`), location: loc(s), severity: "medium" });
        continue;
      }
      if (u.protocol === "http:" && !LOOPBACK.test(u.hostname)) hits.push({ evidence: evidence(`url ${u.protocol}//${u.host}${u.pathname}`), location: loc(s) });
    }
    return hits;
  },
};

export const fsRule: Rule<ScanContext> = {
  id: "MCP-FS-001",
  title: "File access granted to your whole disk or home directory",
  severity: "medium",
  confidence: "high",
  evidenceKind: "static",
  why: "A filesystem server rooted at / or your home directory lets the model read SSH keys, cloud credentials, browser data, and every other project. One prompt injection from a web page or issue is enough to ask for them.",
  fix: "Grant only the project directories the assistant needs (for example the current repo), never / or ~.",
  method: "For servers whose name or package mentions filesystem/fs/files, flags path arguments equal to /, ~, $HOME, %USERPROFILE%, the home directory itself, or a drive root (C:\\). Also flags docker volume mounts of / or the home directory.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    const home = (process.env.HOME ?? process.env.USERPROFILE ?? "").replace(/\/+$/, "");
    const broad = (p: string) => {
      const v = p.replace(/^["']|["']$/g, "").replace(/[\\/]+$/, "") || "/";
      return v === "/" || v === "~" || v === "$HOME" || v === "${HOME}" || /^%USERPROFILE%$/i.test(v) || /^[A-Za-z]:$/.test(v) || (home !== "" && v === home);
    };
    for (const s of ctx.servers) {
      const li = launchInfo(s);
      const isFs = /filesystem|(?:^|[-_/])fs(?:$|[-_])|files?-?server|server-files/.test(`${s.name} ${li.name ?? ""}`.toLowerCase());
      if (isFs) {
        const p = li.serverArgs.find((a) => !a.startsWith("-") && broad(a));
        if (p) hits.push({ evidence: `${s.name} allowed path: ${p}`, location: loc(s) });
      }
      if (li.runner === "docker") {
        s.args.forEach((a, i) => {
          if ((s.args[i - 1] === "-v" || s.args[i - 1] === "--volume") && broad(a.split(":")[0] ?? "")) {
            hits.push({ evidence: `docker volume ${a}`, location: loc(s) });
          }
        });
      }
    }
    return hits;
  },
};

export const dockerRule: Rule<ScanContext> = {
  id: "MCP-DOCKER-001",
  title: "Container launched with host-level privileges",
  severity: "high",
  confidence: "high",
  evidenceKind: "static",
  why: "Running a server in Docker only isolates it if the container is unprivileged. --privileged, host networking, host PID, or a mounted Docker socket give the server effective control of your machine.",
  fix: "Remove --privileged, --network host, --pid host, broad --cap-add, and Docker socket mounts. Pass only the env and the narrow volume the server needs.",
  method: "For docker/podman run launch lines, flags --privileged, --network/--net host, --pid host, --cap-add ALL or SYS_ADMIN, and volume mounts of /var/run/docker.sock.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const hits: Hit[] = [];
    for (const s of ctx.servers) {
      if (launchInfo(s).runner !== "docker") continue;
      const a = s.args;
      const bad: string[] = [];
      a.forEach((x, i) => {
        const next = a[i + 1] ?? "";
        if (x === "--privileged") bad.push(x);
        if ((x === "--network" || x === "--net") && next === "host") bad.push(`${x} host`);
        if (/^--(?:network|net)=host$/.test(x)) bad.push(x);
        if ((x === "--pid" && next === "host") || x === "--pid=host") bad.push("--pid host");
        if ((x === "--cap-add" && /^(?:ALL|SYS_ADMIN)$/i.test(next)) || /^--cap-add=(?:ALL|SYS_ADMIN)$/i.test(x)) bad.push(`--cap-add ${next || x.split("=")[1]}`);
        if (/docker\.sock/.test(x)) bad.push("docker.sock mounted");
      });
      if (bad.length) hits.push({ evidence: `docker run ${bad.join(", ")}`, location: loc(s) });
    }
    return hits;
  },
};

const READER = /filesystem|(?:^|[-_/ ])fs(?:$|[-_ ])|\bgit\b|github|gitlab|gdrive|google-drive|gmail|postgres|sqlite|mysql|mongodb|supabase|notion|obsidian|slack|jira|confluence|linear|database|\bdb\b|1password|keychain/;
const SENDER = /fetch|puppeteer|playwright|browser|chrome|firecrawl|http-client|webhook|curl|smtp|send-?mail|email|slack|discord|telegram|twilio/;

export const xserverRule: Rule<ScanContext> = {
  id: "MCP-XSERVER-001",
  title: "One server can read private data and another can send data out",
  severity: "medium",
  confidence: "low",
  evidenceKind: "static",
  why: "Each server may be fine alone. Together they form an exfiltration path: a prompt injection in a web page, issue, or document can ask the model to read a private file with one tool and send it out with another, all in one session.",
  fix: "Enable the sending server only in sessions that need it, scope the reading server to the minimum paths or repos, and require approval for tool calls on both.",
  method: "Classifies servers by name, package, and (when probed live) tool names into readers of private data (filesystem, git, databases, mail, notes, chat) and senders to the network (fetch, browsers, mail, chat, webhooks). Reports once when at least one of each is enabled. This is a combination warning, not proof of misuse, so confidence is Low.",
  lab: "lab-10-mcp-install",
  pattern: "mcp-config",
  check(ctx) {
    const enabled = ctx.servers.filter((s) => !s.disabled);
    const liveTools = (name: string) => ctx.live.find((l) => l.server === name)?.tools.map((t) => t.name).join(" ") ?? "";
    const text = (s: ServerEntry) => `${serverIdentityText(s)} ${liveTools(s.name)}`.toLowerCase();
    const readers = enabled.filter((s) => READER.test(text(s)) || /read_file|list_directory|query|search_files|get_file_contents/.test(liveTools(s.name)));
    const senders = enabled.filter((s) => SENDER.test(text(s)) || /fetch|navigate|send_|post_message|http_request/.test(liveTools(s.name)));
    const pairs = readers.flatMap((r) => senders.filter((x) => x.name !== r.name).map((x) => [r, x] as const));
    if (!pairs.length) return [];
    const r = [...new Set(pairs.map((p) => p[0].name))].slice(0, 4);
    const x = [...new Set(pairs.map((p) => p[1].name))].slice(0, 4);
    return [{ evidence: `reads: ${r.join(", ")}  |  sends: ${x.join(", ")}`, location: { server: `${r[0]} + ${x[0]}` } }];
  },
};

export const STATIC_RULES: Rule<ScanContext>[] = [
  parseRule,
  dupRule,
  secretRule,
  shellRule,
  unpinnedRule,
  fromUrlRule,
  typosquatRule,
  transportRule,
  fsRule,
  dockerRule,
  xserverRule,
];
