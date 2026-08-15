import { execFile as execFileCallback } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

export type CodexSandboxProbeStatus = "usable" | "unusable" | "inconclusive";

export interface CodexSandboxProbeResult {
  status: CodexSandboxProbeStatus;
  /** "bundled-bwrap" | "system-bwrap" | null — which probe binary ran */
  probe: string | null;
  /** absolute path of the probe binary that ran (or was searched from) */
  probePath: string | null;
  /** stderr tail / error message when status is "unusable" (or the spawn error when "inconclusive") */
  reason: string | null;
}

export const DEFAULT_CODEX_SANDBOX_PROBE_TIMEOUT_MS = 5_000;
export const CODEX_SANDBOX_PROBE_REASON_TAIL_CHARS = 400;
export const CODEX_SANDBOX_PROBE_BWRAP_ARGS = [
  "--unshare-pid",
  "--ro-bind",
  "/",
  "/",
  "/bin/true",
] as const;

const CODEX_SANDBOX_PROBE_MAX_ANCESTOR_DEPTH = 8;
const CODEX_SANDBOX_PROBE_MAX_BUFFER_BYTES = 64 * 1024;

export interface CodexSandboxProbeExecOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeout: number;
  killSignal: NodeJS.Signals;
  maxBuffer: number;
}

export type ExecFileAsync = (
  file: string,
  args: readonly string[],
  options: CodexSandboxProbeExecOptions,
) => Promise<{ stdout: string; stderr: string }>;

export interface CodexSandboxProbeInput {
  resolvedCommand: string;
  cwd: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

export interface CodexSandboxProbeDeps {
  execFileAsync?: ExecFileAsync;
}

const execFilePromise = promisify(execFileCallback);

const defaultExecFileAsync: ExecFileAsync = (file, args, options) =>
  execFilePromise(file, args, options);

async function isExecutable(candidatePath: string): Promise<boolean> {
  try {
    await fs.access(candidatePath, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function firstExecutable(candidates: string[]): Promise<string | null> {
  for (const candidate of candidates) {
    if (await isExecutable(candidate)) return candidate;
  }
  return null;
}

async function listDirEntryNames(dir: string): Promise<string[]> {
  try {
    return await fs.readdir(dir);
  } catch {
    return [];
  }
}

/**
 * Check whether ancestor `dir` hosts a codex-bundled bwrap, trying the known
 * npm layouts in order:
 *   <dir>/codex-resources/bwrap
 *   <dir>/vendor/<triple>/codex-resources/bwrap
 *   <dir>/node_modules/@openai/codex-<platform-arch>/vendor/<triple>/codex-resources/bwrap
 */
async function findBundledBwrapUnderAncestor(dir: string): Promise<string | null> {
  const direct = await firstExecutable([path.join(dir, "codex-resources", "bwrap")]);
  if (direct) return direct;

  const vendorDir = path.join(dir, "vendor");
  const viaVendor = await firstExecutable(
    (await listDirEntryNames(vendorDir)).map((triple) =>
      path.join(vendorDir, triple, "codex-resources", "bwrap"),
    ),
  );
  if (viaVendor) return viaVendor;

  const openaiScopeDir = path.join(dir, "node_modules", "@openai");
  const scopedCandidates: string[] = [];
  for (const pkg of await listDirEntryNames(openaiScopeDir)) {
    if (!pkg.startsWith("codex-")) continue;
    const pkgVendorDir = path.join(openaiScopeDir, pkg, "vendor");
    for (const triple of await listDirEntryNames(pkgVendorDir)) {
      scopedCandidates.push(path.join(pkgVendorDir, triple, "codex-resources", "bwrap"));
    }
  }
  return firstExecutable(scopedCandidates);
}

/**
 * codex npm installs bury the bwrap binary it actually uses deep inside the
 * platform package (`@openai/codex-<platform>-<arch>/vendor/<triple>/codex-resources/`),
 * and the resolved launch command may be the JS shim symlink target rather
 * than the rust binary. Probing *that exact binary* is what predicts runtime
 * sandbox behaviour, so resolve the command's real path and walk its ancestor
 * directories (bounded, so a stray command location cannot scan the whole FS)
 * over the known codex install layouts until an executable bwrap shows up.
 */
export async function resolveBundledCodexSandboxProbePath(
  resolvedCodexCommand: string,
): Promise<string | null> {
  let realPath: string;
  try {
    realPath = await fs.realpath(resolvedCodexCommand);
  } catch {
    // Missing/dangling command path: fall back to the input so the walk still
    // gives callers a deterministic answer instead of throwing.
    realPath = resolvedCodexCommand;
  }

  let dir = path.dirname(realPath);
  for (let depth = 0; depth < CODEX_SANDBOX_PROBE_MAX_ANCESTOR_DEPTH; depth += 1) {
    const found = await findBundledBwrapUnderAncestor(dir);
    if (found) return found;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/**
 * When codex has no bundled bwrap (custom installs), a system bubblewrap on
 * the caller's PATH is the next best thing to probe. Resolve it the same way
 * the invoking shell would: split PATH on the platform delimiter and take the
 * first executable `<entry>/bwrap`.
 */
async function resolveSystemBwrapPath(pathEnv: string | undefined): Promise<string | null> {
  if (!pathEnv) return null;
  return firstExecutable(
    pathEnv
      .split(path.delimiter)
      .filter((entry) => entry.length > 0)
      .map((entry) => path.join(entry, "bwrap")),
  );
}

/**
 * A zero exit status is the only trustworthy "sandbox works" signal. A spawn
 * error (ENOENT/ENOEXEC — the binary vanished or was never executable) tells
 * us nothing about kernel namespace support, so that is "inconclusive" rather
 * than "unusable". Everything else — chiefly the bwrap user-namespace denial —
 * means the sandbox genuinely cannot run.
 */
export function classifyBwrapProbeExit(
  exitCode: number | null,
  stderr: string,
  spawnError?: Error | null,
): CodexSandboxProbeResult["status"] {
  void stderr;
  if (spawnError) return "inconclusive";
  if (exitCode === 0) return "usable";
  return "unusable";
}

/**
 * Compact bwrap stderr into a loggable reason: trimmed and capped at the last
 * ~400 chars, because kernels/bwrap can print multi-line diagnostics and this
 * string is surfaced verbatim in issue comments and logs.
 */
export function formatCodexSandboxProbeReason(stderr: string): string | null {
  const trimmed = stderr.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.length <= CODEX_SANDBOX_PROBE_REASON_TAIL_CHARS) return trimmed;
  return trimmed.slice(trimmed.length - CODEX_SANDBOX_PROBE_REASON_TAIL_CHARS);
}

/**
 * codex 0.147 routes agent writes (apply_patch) through its bundled
 * bubblewrap, which requires unprivileged user namespaces. On hosts that
 * block them every run fails at first write with the opaque
 * `bwrap: No permissions to create a new namespace...` error. Probing once at
 * startup with the smallest namespace-requiring command
 * (`bwrap --unshare-pid --ro-bind / / /bin/true`) turns that into a fast,
 * actionable preflight failure instead of a wasted agent run. Anything we
 * cannot positively judge (non-Linux host, missing binary, spawn race) is
 * reported "inconclusive" so callers never fail closed on a guess.
 */
export async function probeCodexLinuxSandboxCapability(
  input: CodexSandboxProbeInput,
  deps: CodexSandboxProbeDeps = {},
): Promise<CodexSandboxProbeResult> {
  if (process.platform !== "linux") {
    return {
      status: "inconclusive",
      probe: null,
      probePath: null,
      reason: "probe only supported on Linux",
    };
  }

  const execFileAsync = deps.execFileAsync ?? defaultExecFileAsync;

  let probe: "bundled-bwrap" | "system-bwrap";
  let probePath: string;
  const bundledPath = await resolveBundledCodexSandboxProbePath(input.resolvedCommand);
  if (bundledPath) {
    probe = "bundled-bwrap";
    probePath = bundledPath;
  } else {
    const systemPath = await resolveSystemBwrapPath(input.env?.PATH ?? process.env.PATH);
    if (!systemPath) {
      return {
        status: "inconclusive",
        probe: null,
        probePath: null,
        reason: "no bubblewrap binary found to probe",
      };
    }
    probe = "system-bwrap";
    probePath = systemPath;
  }

  try {
    const { stderr } = await execFileAsync(probePath, CODEX_SANDBOX_PROBE_BWRAP_ARGS, {
      cwd: input.cwd,
      env: input.env ?? process.env,
      timeout: input.timeoutMs ?? DEFAULT_CODEX_SANDBOX_PROBE_TIMEOUT_MS,
      killSignal: "SIGKILL",
      maxBuffer: CODEX_SANDBOX_PROBE_MAX_BUFFER_BYTES,
    });
    return { status: classifyBwrapProbeExit(0, stderr), probe, probePath, reason: null };
  } catch (rawError) {
    const error = rawError as Error & {
      code?: number | string;
      killed?: boolean;
      stderr?: unknown;
    };

    // execFile only sets `killed` when it terminated the child itself, and the
    // only termination trigger here is the timeout — treat it as unusable
    // because a hung namespace setup hangs the real run the same way.
    if (error.killed === true) {
      return { status: "unusable", probe, probePath, reason: "probe timed out" };
    }

    // A string errno (ENOENT/ENOEXEC/...) means bwrap never actually ran, so
    // we cannot judge sandbox capability — inconclusive, not unusable.
    const exitCode = typeof error.code === "number" ? error.code : null;
    const stderr = typeof error.stderr === "string" ? error.stderr : "";
    const spawnError = exitCode === null ? error : null;
    const status = classifyBwrapProbeExit(exitCode, stderr, spawnError);
    return {
      status,
      probe,
      probePath,
      reason:
        status === "unusable"
          ? (formatCodexSandboxProbeReason(stderr) ?? error.message)
          : status === "inconclusive"
            ? error.message
            : null,
    };
  }
}
