import { basename } from "node:path";
import type { ServerEntry } from "./types.js";

export type Runner = "npx" | "uvx" | "pipx" | "docker" | "other";

export interface LaunchInfo {
  runner: Runner;
  /** Package or image as written, including any version / tag. */
  spec?: string;
  /** Package name without version. */
  name?: string;
  version?: string;
  pinned: boolean;
  fromUrl: boolean;
  /** Arguments after the package spec (what the server itself receives). */
  serverArgs: string[];
}

const SHELLS = new Set(["sh", "bash", "zsh", "fish", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"]);

export function commandBase(cmd?: string): string {
  return cmd ? basename(cmd.replace(/\\/g, "/")).toLowerCase() : "";
}

export function isShell(cmd?: string): boolean {
  return SHELLS.has(commandBase(cmd));
}

/** Unwrap `cmd /c npx ...` (the standard Windows wrapper) so the real launcher is analysed. */
export function effectiveCommand(s: ServerEntry): { command: string; args: string[] } {
  const base = commandBase(s.command);
  if ((base === "cmd" || base === "cmd.exe") && s.args.length > 1 && /^\/[ck]$/i.test(s.args[0])) {
    return { command: s.args[1], args: s.args.slice(2) };
  }
  return { command: s.command ?? "", args: s.args };
}

const URL_SPEC = /^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/|file:)|\.(?:tgz|tar\.gz|whl|zip)$/i;

function splitNpm(spec: string): { name: string; version?: string } {
  const at = spec.lastIndexOf("@");
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec };
}

function npmPinned(version?: string): boolean {
  return !!version && /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version);
}

export function launchInfo(s: ServerEntry): LaunchInfo {
  const { command, args } = effectiveCommand(s);
  const base = commandBase(command);
  const none: LaunchInfo = { runner: "other", pinned: true, fromUrl: false, serverArgs: args };

  // npx / bunx / pnpm dlx / yarn dlx
  let rest: string[] | undefined;
  if (base === "npx" || base === "bunx" || base === "npx.cmd") rest = args;
  else if ((base === "pnpm" || base === "yarn" || base === "bun") && (args[0] === "dlx" || args[0] === "x")) rest = args.slice(1);
  if (rest) {
    let pkg: string | undefined;
    let idx = -1;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === "-p" || a === "--package") {
        pkg = rest[i + 1];
        idx = i + 1;
        break;
      }
      if (a.startsWith("--package=")) {
        pkg = a.slice("--package=".length);
        idx = i;
        break;
      }
      if (a.startsWith("-")) continue;
      pkg = a;
      idx = i;
      break;
    }
    if (!pkg) return { ...none, runner: "npx" };
    const fromUrl = URL_SPEC.test(pkg);
    const { name, version } = fromUrl ? { name: pkg, version: undefined } : splitNpm(pkg);
    return { runner: "npx", spec: pkg, name, version, pinned: fromUrl ? false : npmPinned(version), fromUrl, serverArgs: rest.slice(idx + 1) };
  }

  // uvx / uv tool run / pipx run
  if (base === "uvx" || (base === "uv" && args[0] === "tool" && args[1] === "run") || (base === "pipx" && args[0] === "run")) {
    const r = base === "uvx" ? args : base === "uv" ? args.slice(2) : args.slice(1);
    let from: string | undefined;
    let pkg: string | undefined;
    let idx = -1;
    for (let i = 0; i < r.length; i++) {
      const a = r[i];
      if (a === "--from" || a === "--spec") {
        from = r[i + 1];
        i++;
        continue;
      }
      if (a.startsWith("--from=")) {
        from = a.slice(7);
        continue;
      }
      if (a === "--python" || a === "--with" || a === "-p" || a === "--index-url") {
        i++;
        continue;
      }
      if (a.startsWith("-")) continue;
      pkg = a;
      idx = i;
      break;
    }
    const spec = from ?? pkg;
    if (!spec) return { ...none, runner: "uvx" };
    const fromUrl = URL_SPEC.test(spec) || /\s@\s|@\s*(?:git\+|https?:)/.test(spec);
    const m = spec.match(/^([A-Za-z0-9_.\-[\]]+)\s*(?:==\s*([0-9][^,;\s]*))?/);
    const name = m?.[1]?.replace(/\[.*\]$/, "");
    const version = m?.[2];
    const pinned = !fromUrl && !!version;
    return { runner: base === "pipx" ? "pipx" : "uvx", spec, name, version, pinned, fromUrl, serverArgs: r.slice(idx + 1) };
  }

  // docker / podman run
  if ((base === "docker" || base === "podman") && args[0] === "run") {
    const withValue = new Set(["-e", "--env", "-v", "--volume", "--network", "--net", "--name", "-p", "--publish", "--env-file", "-w", "--workdir", "--user", "-u", "--mount", "--entrypoint", "--pid", "--cap-add", "--platform"]);
    for (let i = 1; i < args.length; i++) {
      const a = args[i];
      if (withValue.has(a)) {
        i++;
        continue;
      }
      if (a.startsWith("-")) continue;
      const digest = a.includes("@sha256:");
      const lastSeg = a.split("/").pop() ?? a;
      const tag = lastSeg.includes(":") ? lastSeg.split(":").pop() : undefined;
      const pinned = digest || (!!tag && tag !== "latest");
      return { runner: "docker", spec: a, name: a.replace(/[:@].*$/, ""), version: digest ? "digest" : tag, pinned, fromUrl: false, serverArgs: args.slice(i + 1) };
    }
    return { ...none, runner: "docker" };
  }

  return none;
}

/** Text that identifies what a server is, for capability classification and typosquat checks. */
export function serverIdentityText(s: ServerEntry): string {
  const li = launchInfo(s);
  return [s.name, li.name ?? "", s.url ?? "", s.command ?? "", ...s.args].join(" ").toLowerCase();
}

export function serverIdentity(s: ServerEntry): string {
  if (s.url) return `url:${s.url}`;
  const li = launchInfo(s);
  return `cmd:${s.name}:${li.name ?? s.command ?? ""}`;
}
