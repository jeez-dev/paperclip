// JEE-442: fail-fast write-path liveness probe for every codex ACP session.
// Failure class: JEE-413 — codex-acp sandboxed tool calls die mid-run with
// `bwrap: No permissions to create a new namespace` on hosts whose kernel
// blocks user namespaces, stranding delegated work. Prove the session write
// path once at session start (before any config/prompt/turn), fail fast with
// a CTO escalation, and leave zero workspace-visible state.

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { promisify } from "node:util";
import type { AcpxSessionWritePathProbeInput } from "@paperclipai/adapter-utils/acpx-engine/execute";
import {
  runAdapterExecutionTargetShellCommand,
  type AdapterExecutionTarget,
  type AdapterExecutionTargetShellOptions,
} from "@paperclipai/adapter-utils/execution-target";

interface ProbeShellResult {
  exitCode: number | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
}

/** Test seams only — never passed in prod. */
export interface CodexWritePathProbeDeps {
  execFileImpl?: (file: string, args: string[], options: { timeout: number }) => Promise<unknown>;
  runShellImpl?: (
    runId: string,
    target: AdapterExecutionTarget | null | undefined,
    command: string,
    options: AdapterExecutionTargetShellOptions,
  ) => Promise<ProbeShellResult>;
  /** Replaces the bundled-package + PATH bwrap resolution strategies. */
  resolveBwrapImpl?: () => string | null;
  now?: () => number;
}

type ProbeStep =
  | "sentinel write"
  | "sentinel update"
  | "sentinel verify"
  | "sentinel cleanup"
  | "bwrap namespace canary";

type CanaryDisposition =
  | "skipped-full-access"
  | "ok"
  | "skipped-no-bwrap"
  | "not-applicable";

const SENTINEL_PREFIX = ".paperclip-acp-write-probe-";
const PROBE_CONTENT_MARKER = "paperclip-acp-write-probe:v1";
const PROBE_UPDATE_LINE = "update-ok";
const REMOTE_PROBE_TIMEOUT_SEC = 8;
const CANARY_TIMEOUT_MS = 5000;
const NO_BWRAP_SKIP_NOTE =
  "[paperclip] Codex ACP write-path probe: sandboxed mode but no bwrap located for the namespace canary; skipping canary.\n";

// codex-acp resolves "agent-full-access" to dangerFullAccess (apply_patch out
// of bwrap); "danger-full-access" is the same escape hatch. Everything else —
// including unset, whose default "agent" mode is workspaceWrite — is sandboxed.
const UNSANDBOXED_AGENT_MODES = new Set(["agent-full-access", "danger-full-access"]);

const execFileAsync = promisify(execFile);

function detailOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function buildProbeFailure(input: AcpxSessionWritePathProbeInput, step: ProbeStep, detail: string): Error {
  const initialAgentMode = input.env.INITIAL_AGENT_MODE ?? "unset(default agent)";
  return new Error(
    `codex_local ACP session write-path probe failed during ${step}: ${detail} ` +
      `(cwd: ${input.cwd}; initialAgentMode: ${initialAgentMode}). ` +
      "Failing the run fast before implementation work; escalate to the CTO — codex ACP write path is broken.",
  );
}

async function runLocalSentinel(
  input: AcpxSessionWritePathProbeInput,
  sentinelName: string,
  line1: string,
): Promise<void> {
  const sentinelPath = path.join(input.cwd, sentinelName);
  try {
    try {
      await fs.writeFile(sentinelPath, `${line1}\n`, "utf8");
    } catch (err) {
      throw buildProbeFailure(input, "sentinel write", detailOf(err));
    }
    try {
      await fs.appendFile(sentinelPath, `${PROBE_UPDATE_LINE}\n`, "utf8");
    } catch (err) {
      throw buildProbeFailure(input, "sentinel update", detailOf(err));
    }
    try {
      const content = await fs.readFile(sentinelPath, "utf8");
      if (!content.includes(line1) || !content.includes(PROBE_UPDATE_LINE)) {
        throw new Error(`sentinel content mismatch after add+update (read: ${JSON.stringify(content)})`);
      }
    } catch (err) {
      throw buildProbeFailure(input, "sentinel verify", detailOf(err));
    }
    try {
      await fs.rm(sentinelPath, { force: true });
      if (fsSync.existsSync(sentinelPath)) {
        throw new Error("sentinel still present after rm");
      }
    } catch (err) {
      throw buildProbeFailure(input, "sentinel cleanup", detailOf(err));
    }
  } finally {
    // Best-effort: a mid-probe crash must never leave the sentinel behind.
    await fs.rm(sentinelPath, { force: true }).catch(() => {});
  }
}

function buildRemoteSentinelScript(sentinelName: string, line1: string): string {
  return [
    "set -eu",
    `f='${sentinelName}'`,
    `printf '%s\\n' '${line1}' > "$f"`,
    `printf '%s\\n' '${PROBE_UPDATE_LINE}' >> "$f"`,
    `grep -qF '${line1}' "$f"`,
    `grep -qF '${PROBE_UPDATE_LINE}' "$f"`,
    `rm -f "$f"`,
    `test ! -e "$f"`,
  ].join("; ");
}

async function runRemoteSentinel(
  input: AcpxSessionWritePathProbeInput,
  deps: CodexWritePathProbeDeps,
  sentinelName: string,
  line1: string,
): Promise<void> {
  const runShell = deps.runShellImpl ?? runAdapterExecutionTargetShellCommand;
  const result = await runShell(input.ctx.runId, input.executionTarget, buildRemoteSentinelScript(sentinelName, line1), {
    cwd: input.cwd,
    env: {},
    timeoutSec: REMOTE_PROBE_TIMEOUT_SEC,
  });
  if (result.timedOut || result.exitCode !== 0) {
    const output = `${result.stdout}${result.stderr}`.slice(0, 300);
    throw buildProbeFailure(
      input,
      "sentinel write",
      `remote sentinel script failed (exitCode: ${String(result.exitCode)}, timedOut: ${result.timedOut}); output: ${JSON.stringify(output)}`,
    );
  }
}

// Anchor resolution at codex-acp, a declared codex-local dependency: it is
// codex-acp that resolves and spawns the codex binary, so its dependency tree
// is the only one guaranteed to see @openai/codex under pnpm's strict layout.
// Anchoring at this module never resolves there (codex-local does not declare
// @openai/codex) — verified with plain-node createRequire on the prod tree.
function resolveBundledCodexJsPath(): string | null {
  try {
    const req = createRequire(import.meta.url);
    const codexAcpEntry = req.resolve("@agentclientprotocol/codex-acp");
    const acpRequire = createRequire(codexAcpEntry);
    return acpRequire.resolve("@openai/codex/bin/codex.js");
  } catch {
    return null;
  }
}

function resolveBwrapFromCodexBundle(): string | null {
  try {
    const codexJs = resolveBundledCodexJsPath();
    if (!codexJs) return null;
    const scopeDir = path.dirname(path.dirname(path.dirname(codexJs)));
    const platformDir = path.join(scopeDir, `codex-${process.platform}-${process.arch}`);
    const triple = fsSync.readdirSync(path.join(platformDir, "vendor"))[0];
    if (!triple) return null;
    const candidate = path.join(platformDir, "vendor", triple, "codex-resources", "bwrap");
    return fsSync.existsSync(candidate) ? candidate : null;
  } catch {
    return null;
  }
}

function resolveBwrapFromPath(): string | null {
  try {
    for (const segment of (process.env.PATH ?? "").split(path.delimiter)) {
      if (!segment) continue;
      const candidate = path.join(segment, "bwrap");
      if (fsSync.existsSync(candidate)) return candidate;
    }
  } catch {
    return null;
  }
  return null;
}

function defaultResolveBwrap(): string | null {
  return resolveBwrapFromCodexBundle() ?? resolveBwrapFromPath();
}

async function defaultExecFile(file: string, args: string[], options: { timeout: number }): Promise<void> {
  await execFileAsync(file, args, options);
}

const CANARY_KERNEL_NOTE =
  "the kernel denies user namespaces (the JEE-413 class) unless the bypass mode is active";

async function runLocalBwrapCanary(
  input: AcpxSessionWritePathProbeInput,
  deps: CodexWritePathProbeDeps,
): Promise<CanaryDisposition> {
  const resolveBwrap = deps.resolveBwrapImpl ?? defaultResolveBwrap;
  const bwrapPath = resolveBwrap();
  if (!bwrapPath) {
    await input.ctx.onLog("stderr", NO_BWRAP_SKIP_NOTE);
    return "skipped-no-bwrap";
  }
  const canaryExecFile = deps.execFileImpl ?? defaultExecFile;
  try {
    await canaryExecFile(
      bwrapPath,
      ["--unshare-user", "--ro-bind", "/", "/", "true"],
      { timeout: CANARY_TIMEOUT_MS },
    );
  } catch (err) {
    throw buildProbeFailure(
      input,
      "bwrap namespace canary",
      `bwrap canary at ${bwrapPath} failed: ${detailOf(err)} — ${CANARY_KERNEL_NOTE}`,
    );
  }
  return "ok";
}

async function runRemoteBwrapCanary(
  input: AcpxSessionWritePathProbeInput,
  deps: CodexWritePathProbeDeps,
): Promise<CanaryDisposition> {
  const runShell = deps.runShellImpl ?? runAdapterExecutionTargetShellCommand;
  const result = await runShell(
    input.ctx.runId,
    input.executionTarget,
    "if command -v bwrap >/dev/null 2>&1; then bwrap --unshare-user --ro-bind / / true; else echo PROBE_NO_BWRAP; fi",
    { cwd: input.cwd, env: {}, timeoutSec: REMOTE_PROBE_TIMEOUT_SEC },
  );
  if (result.timedOut) {
    throw buildProbeFailure(
      input,
      "bwrap namespace canary",
      `remote bwrap canary timed out after ${REMOTE_PROBE_TIMEOUT_SEC}s (stderr: ${JSON.stringify(result.stderr.slice(-300))}) — ${CANARY_KERNEL_NOTE}`,
    );
  }
  if (result.exitCode === 0 && result.stdout.includes("PROBE_NO_BWRAP")) {
    await input.ctx.onLog("stderr", NO_BWRAP_SKIP_NOTE);
    return "skipped-no-bwrap";
  }
  if (result.exitCode === 0) return "ok";
  throw buildProbeFailure(
    input,
    "bwrap namespace canary",
    `remote bwrap canary exited ${String(result.exitCode)} (stderr: ${JSON.stringify(result.stderr.slice(-300))}) — the sandbox kernel denies user namespaces (the JEE-413 class) unless the bypass mode is active`,
  );
}

export async function probeCodexAcpSessionWritePath(
  input: AcpxSessionWritePathProbeInput,
  deps: CodexWritePathProbeDeps = {},
): Promise<void> {
  const now = deps.now ?? (() => Date.now());
  const startedAt = now();
  const initialAgentMode = input.env.INITIAL_AGENT_MODE;
  const sandboxed = !UNSANDBOXED_AGENT_MODES.has(initialAgentMode ?? "");
  const isRemote = input.executionTarget?.kind === "remote";

  const rand8 = randomUUID().replace(/-/g, "").slice(0, 8);
  const sentinelName = `${SENTINEL_PREFIX}${rand8}`;
  const line1 = `${PROBE_CONTENT_MARKER} run=${input.ctx.runId}`;

  if (isRemote) {
    await runRemoteSentinel(input, deps, sentinelName, line1);
  } else {
    await runLocalSentinel(input, sentinelName, line1);
  }

  let canaryDisposition: CanaryDisposition;
  if (!sandboxed) {
    canaryDisposition = "skipped-full-access";
  } else if (process.platform !== "linux") {
    canaryDisposition = "not-applicable";
  } else if (isRemote) {
    canaryDisposition = await runRemoteBwrapCanary(input, deps);
  } else {
    canaryDisposition = await runLocalBwrapCanary(input, deps);
  }

  const elapsedMs = Math.max(0, Math.round(now() - startedAt));
  await input.ctx.onLog(
    "stdout",
    `[paperclip] Codex ACP write-path probe passed (sentinel add+update+cleanup in ${input.cwd}; canary=${canaryDisposition}; ${elapsedMs}ms).\n`,
  );
}
