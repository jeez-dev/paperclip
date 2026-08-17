// JEE-442: the probe must pass on hosts whose kernel BLOCKS user namespaces
// (this CI host does) and regardless of the test runner's uid, so every
// canary interaction is injected through the probe deps — never the real
// bundled bwrap.

import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AcpxSessionWritePathProbeInput } from "@paperclipai/adapter-utils/acpx-engine/execute";
import type { AdapterExecutionTargetShellOptions } from "@paperclipai/adapter-utils/execution-target";
import {
  probeCodexAcpSessionWritePath,
  type CodexWritePathProbeDeps,
} from "./session-write-path-probe.js";

const tempRoots: string[] = [];

async function makeTempRoot(prefix: string) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  tempRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});

type LogLine = [stream: string, chunk: string];

function buildInput(overrides: {
  cwd: string;
  env?: Record<string, string>;
  executionTarget?: AcpxSessionWritePathProbeInput["executionTarget"];
}): { input: AcpxSessionWritePathProbeInput; logs: LogLine[] } {
  const logs: LogLine[] = [];
  const ctx = {
    runId: "r1",
    onLog: async (stream: "stdout" | "stderr", chunk: string) => {
      logs.push([stream, chunk]);
    },
  } as unknown as AcpxSessionWritePathProbeInput["ctx"];
  return {
    input: {
      ctx,
      cwd: overrides.cwd,
      env: overrides.env ?? {},
      executionTarget: overrides.executionTarget ?? null,
    },
    logs,
  };
}

function fakeRemoteTarget() {
  return { kind: "remote", transport: "sandbox", remoteCwd: "/w", runner: {} } as never;
}

function okShellResult() {
  return { exitCode: 0, timedOut: false, stdout: "", stderr: "" };
}

function sentinelHappyDeps() {
  // Sentinel passes wherever it is pointed; full-access mode keeps the host
  // canary out of these tests entirely.
  return { env: { INITIAL_AGENT_MODE: "agent-full-access" } };
}

describe("probeCodexAcpSessionWritePath (JEE-442)", () => {
  it("proves the local write path and leaves no sentinel behind (happy path)", async () => {
    const root = await makeTempRoot("paperclip-probe-happy-");
    const { input, logs } = buildInput({ cwd: root, ...sentinelHappyDeps() });

    await probeCodexAcpSessionWritePath(input);

    const entries = await fs.readdir(root);
    expect(entries.filter((name) => name.startsWith(".paperclip-acp-write-probe-"))).toEqual([]);
    expect(logs).toContainEqual([
      "stdout",
      expect.stringContaining("Codex ACP write-path probe passed"),
    ]);
    expect(logs).toContainEqual([
      "stdout",
      expect.stringContaining("canary=skipped-full-access"),
    ]);
  });

  it("fails fast with CTO escalation when the sentinel write cannot land", async () => {
    const missing = path.join(os.tmpdir(), `paperclip-probe-missing-${randomUUID()}`);
    const { input } = buildInput({ cwd: missing, ...sentinelHappyDeps() });

    const failure = await probeCodexAcpSessionWritePath(input).catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toMatch(/write-path probe failed during sentinel write/);
    expect((failure as Error).message).toMatch(/escalate to the CTO/);
  });

  it("never runs the bwrap canary in agent-full-access mode", async () => {
    const root = await makeTempRoot("paperclip-probe-full-access-");
    const execFileImpl = vi.fn(async () => {
      throw new Error("execFileImpl must not be called in full-access mode");
    });
    const { input } = buildInput({ cwd: root, ...sentinelHappyDeps() });
    const deps: CodexWritePathProbeDeps = {
      execFileImpl,
      resolveBwrapImpl: () => "/fake/bwrap",
    };

    await probeCodexAcpSessionWritePath(input, deps);

    expect(execFileImpl).not.toHaveBeenCalled();
  });

  it("fails fast when the sandboxed bwrap canary hits the JEE-413 namespace wall", async () => {
    const root = await makeTempRoot("paperclip-probe-canary-fail-");
    const { input, logs } = buildInput({ cwd: root });
    const execFileImpl = vi.fn(async () => {
      throw new Error(
        "bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces",
      );
    });

    const failure = await probeCodexAcpSessionWritePath(input, {
      execFileImpl,
      resolveBwrapImpl: () => "/fake/bwrap",
    }).catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toMatch(/write-path probe failed during bwrap namespace canary/);
    expect((failure as Error).message).toMatch(/No permissions to create a new namespace/);
    expect((failure as Error).message).toMatch(/escalate to the CTO/);
    expect(logs.some(([stream, chunk]) => stream === "stdout" && chunk.includes("probe passed"))).toBe(false);
  });

  it("passes the sandboxed canary when the kernel allows the namespace", async () => {
    const root = await makeTempRoot("paperclip-probe-canary-pass-");
    const { input, logs } = buildInput({ cwd: root });
    const execFileImpl = vi.fn(async () => ({ stdout: "", stderr: "" }));

    await probeCodexAcpSessionWritePath(input, {
      execFileImpl,
      resolveBwrapImpl: () => "/fake/bwrap",
    });

    expect(execFileImpl).toHaveBeenCalledTimes(1);
    expect(execFileImpl).toHaveBeenCalledWith(
      "/fake/bwrap",
      ["--unshare-user", "--ro-bind", "/", "/", "true"],
      { timeout: 5000 },
    );
    expect(logs).toContainEqual([
      "stdout",
      expect.stringContaining("canary=ok"),
    ]);
  });

  it("drives the remote sentinel add/update/grep/rm through one shell call in the session cwd", async () => {
    const calls: Array<{ command: string; options: AdapterExecutionTargetShellOptions }> = [];
    const runShellImpl = vi.fn(async (
      _runId: string,
      _target: unknown,
      command: string,
      options: AdapterExecutionTargetShellOptions,
    ) => {
      calls.push({ command, options });
      return okShellResult();
    });
    const { input } = buildInput({
      cwd: "/repo/worktree",
      env: { INITIAL_AGENT_MODE: "agent-full-access" },
      executionTarget: fakeRemoteTarget(),
    });

    await probeCodexAcpSessionWritePath(input, { runShellImpl });

    // agent-full-access skips the canary, so the sentinel is the only call.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.options.cwd).toBe(input.cwd);
    expect(calls[0]?.options.timeoutSec).toBe(8);
    expect(calls[0]?.command).toMatch(/'\.paperclip-acp-write-probe-[0-9a-f]{8}'/);
    expect(calls[0]?.command).toContain("grep");
    expect(calls[0]?.command).toContain("rm -f");
    expect(calls[0]?.command).toContain("paperclip-acp-write-probe:v1 run=r1");
  });

  it("soft-passes the remote canary (with a logged note) when the sandbox has no bwrap", async () => {
    const results = [
      okShellResult(),
      { exitCode: 0, timedOut: false, stdout: "PROBE_NO_BWRAP\n", stderr: "" },
    ];
    const runShellImpl = vi.fn(async () => results.shift() ?? okShellResult());
    const { input, logs } = buildInput({
      cwd: "/repo/worktree",
      executionTarget: fakeRemoteTarget(),
    });

    await probeCodexAcpSessionWritePath(input, { runShellImpl });

    expect(runShellImpl).toHaveBeenCalledTimes(2);
    expect(logs).toContainEqual([
      "stderr",
      expect.stringContaining("no bwrap located"),
    ]);
    expect(logs).toContainEqual([
      "stdout",
      expect.stringContaining("canary=skipped-no-bwrap"),
    ]);
  });
});
