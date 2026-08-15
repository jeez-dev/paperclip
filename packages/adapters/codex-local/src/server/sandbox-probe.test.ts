import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  CODEX_SANDBOX_PROBE_REASON_TAIL_CHARS,
  DEFAULT_CODEX_SANDBOX_PROBE_TIMEOUT_MS,
  classifyBwrapProbeExit,
  formatCodexSandboxProbeReason,
  probeCodexLinuxSandboxCapability,
  resolveBundledCodexSandboxProbePath,
  type CodexSandboxProbeExecOptions,
  type ExecFileAsync,
} from "./sandbox-probe.js";

const BWRAP_NO_USERNS_STDERR =
  "bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces...";

describe("sandbox-probe", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  async function makeFixtureRoot(name: string): Promise<string> {
    const root = await mkdtemp(path.join(os.tmpdir(), `codex-sandbox-probe-${name}-`));
    cleanupDirs.push(root);
    return root;
  }

  /** <pkg>/node_modules/@openai/codex/bin/codex.js + platform-package bwrap (0755). */
  async function makeBundledCodexFixture(root: string): Promise<{
    commandPath: string;
    bwrapPath: string;
  }> {
    const bwrapPath = path.join(
      root,
      "node_modules",
      "@openai",
      "codex-linux-x64",
      "vendor",
      "test-triple",
      "codex-resources",
      "bwrap",
    );
    await mkdir(path.dirname(bwrapPath), { recursive: true });
    await writeFile(bwrapPath, "#!/bin/sh\n");
    await chmod(bwrapPath, 0o755);

    const commandPath = path.join(root, "node_modules", "@openai", "codex", "bin", "codex.js");
    await mkdir(path.dirname(commandPath), { recursive: true });
    await writeFile(commandPath, "// codex js shim\n");
    return { commandPath, bwrapPath };
  }

  interface ExecCall {
    file: string;
    args: readonly string[];
    options: CodexSandboxProbeExecOptions;
  }

  function stubExecFile(impl: (call: ExecCall) => Promise<{ stdout: string; stderr: string }>) {
    const calls: ExecCall[] = [];
    const execFileAsync: ExecFileAsync = async (file, args, options) => {
      const call: ExecCall = { file, args, options };
      calls.push(call);
      return impl(call);
    };
    return { calls, execFileAsync };
  }

  describe("resolveBundledCodexSandboxProbePath", () => {
    it("discovers the bundled bwrap from the @openai/codex js shim path", async () => {
      const root = await makeFixtureRoot("bundled");
      const { commandPath, bwrapPath } = await makeBundledCodexFixture(path.join(root, "pkg"));

      await expect(resolveBundledCodexSandboxProbePath(commandPath)).resolves.toBe(bwrapPath);
    });

    it("returns null when no codex-resources tree exists anywhere up the ancestors", async () => {
      const root = await makeFixtureRoot("empty");
      const commandPath = path.join(
        root,
        "pkg-none",
        "node_modules",
        "@openai",
        "codex",
        "bin",
        "codex.js",
      );
      await mkdir(path.dirname(commandPath), { recursive: true });
      await writeFile(commandPath, "// codex js shim without platform pkg\n");

      await expect(resolveBundledCodexSandboxProbePath(commandPath)).resolves.toBeNull();
    });

    it("finds bwrap via the <ancestor>/vendor/<triple>/codex-resources construction", async () => {
      const root = await makeFixtureRoot("vendor");
      const pkgDir = path.join(root, "pkg2");
      const bwrapPath = path.join(pkgDir, "vendor", "t2", "codex-resources", "bwrap");
      await mkdir(path.dirname(bwrapPath), { recursive: true });
      await writeFile(bwrapPath, "#!/bin/sh\n");
      await chmod(bwrapPath, 0o755);
      const commandPath = path.join(pkgDir, "bin", "codex");
      await mkdir(path.dirname(commandPath), { recursive: true });
      await writeFile(commandPath, "// codex rust binary placeholder\n");

      await expect(resolveBundledCodexSandboxProbePath(commandPath)).resolves.toBe(bwrapPath);
    });

    it("ignores a non-executable codex-resources/bwrap", async () => {
      const root = await makeFixtureRoot("not-executable");
      const pkgDir = path.join(root, "pkg");
      const bwrapPath = path.join(pkgDir, "codex-resources", "bwrap");
      await mkdir(path.dirname(bwrapPath), { recursive: true });
      await writeFile(bwrapPath, "#!/bin/sh\n");
      await chmod(bwrapPath, 0o644);
      const commandPath = path.join(pkgDir, "bin", "codex");
      await mkdir(path.dirname(commandPath), { recursive: true });
      await writeFile(commandPath, "// placeholder\n");

      await expect(resolveBundledCodexSandboxProbePath(commandPath)).resolves.toBeNull();
    });
  });

  describe("classifyBwrapProbeExit", () => {
    it("exit 0 is usable", () => {
      expect(classifyBwrapProbeExit(0, "")).toBe("usable");
    });

    it("user-namespace denial stderr is unusable", () => {
      expect(classifyBwrapProbeExit(1, BWRAP_NO_USERNS_STDERR)).toBe("unusable");
    });

    it("non-zero exit is unusable even with empty stderr", () => {
      expect(classifyBwrapProbeExit(42, "")).toBe("unusable");
    });

    it("spawn error is inconclusive (binary never ran, cannot judge)", () => {
      expect(classifyBwrapProbeExit(null, "", new Error("spawn bwrap ENOENT"))).toBe(
        "inconclusive",
      );
    });

    it("spawn error wins over a misleading exit code", () => {
      expect(classifyBwrapProbeExit(0, "", new Error("spawn bwrap ENOENT"))).toBe("inconclusive");
    });
  });

  describe("formatCodexSandboxProbeReason", () => {
    it("trims surrounding whitespace", () => {
      expect(formatCodexSandboxProbeReason(`\n  ${BWRAP_NO_USERNS_STDERR}\n\n`)).toBe(
        BWRAP_NO_USERNS_STDERR,
      );
    });

    it("returns null for empty stderr", () => {
      expect(formatCodexSandboxProbeReason("   \n ")).toBeNull();
    });

    it("keeps only the tail of very long stderr", () => {
      const tail = "x".repeat(100);
      const long = `${"y".repeat(800)}\n${tail}`;
      const reason = formatCodexSandboxProbeReason(long);
      expect(reason).toHaveLength(CODEX_SANDBOX_PROBE_REASON_TAIL_CHARS);
      expect(reason?.endsWith(tail)).toBe(true);
    });
  });

  describe("probeCodexLinuxSandboxCapability", () => {
    it("reports usable/bundled-bwrap when the bundled probe exits 0", async () => {
      const root = await makeFixtureRoot("probe-usable");
      const pkgDir = path.join(root, "pkg");
      const { commandPath, bwrapPath } = await makeBundledCodexFixture(pkgDir);
      const { calls, execFileAsync } = stubExecFile(async () => ({ stdout: "", stderr: "" }));

      const result = await probeCodexLinuxSandboxCapability(
        { resolvedCommand: commandPath, cwd: pkgDir },
        { execFileAsync },
      );

      expect(result).toEqual({
        status: "usable",
        probe: "bundled-bwrap",
        probePath: bwrapPath,
        reason: null,
      });
      expect(calls).toHaveLength(1);
      expect(calls[0].file).toBe(bwrapPath);
      expect(calls[0].args).toEqual(["--unshare-pid", "--ro-bind", "/", "/", "/bin/true"]);
      expect(calls[0].options.cwd).toBe(pkgDir);
      expect(calls[0].options.timeout).toBe(DEFAULT_CODEX_SANDBOX_PROBE_TIMEOUT_MS);
    });

    it("reports unusable with the stderr tail when bwrap denies user namespaces", async () => {
      const root = await makeFixtureRoot("probe-denied");
      const pkgDir = path.join(root, "pkg");
      const { commandPath, bwrapPath } = await makeBundledCodexFixture(pkgDir);
      const { execFileAsync } = stubExecFile(async () => {
        throw Object.assign(new Error(`Command failed: ${bwrapPath}`), {
          code: 1,
          stderr: `${BWRAP_NO_USERNS_STDERR}\n`,
        });
      });

      const result = await probeCodexLinuxSandboxCapability(
        { resolvedCommand: commandPath, cwd: pkgDir },
        { execFileAsync },
      );

      expect(result.status).toBe("unusable");
      expect(result.probe).toBe("bundled-bwrap");
      expect(result.probePath).toBe(bwrapPath);
      expect(result.reason).toBe(BWRAP_NO_USERNS_STDERR);
    });

    it("reports inconclusive when the probe binary fails to spawn (ENOENT)", async () => {
      const root = await makeFixtureRoot("probe-enoent");
      const pkgDir = path.join(root, "pkg");
      const { commandPath, bwrapPath } = await makeBundledCodexFixture(pkgDir);
      const { execFileAsync } = stubExecFile(async () => {
        throw Object.assign(new Error(`spawn ${bwrapPath} ENOENT`), { code: "ENOENT" });
      });

      const result = await probeCodexLinuxSandboxCapability(
        { resolvedCommand: commandPath, cwd: pkgDir },
        { execFileAsync },
      );

      expect(result.status).toBe("inconclusive");
      expect(result.probe).toBe("bundled-bwrap");
      expect(result.probePath).toBe(bwrapPath);
      expect(result.reason).toContain("ENOENT");
    });

    it("reports unusable with 'probe timed out' when the timeout kills the probe", async () => {
      const root = await makeFixtureRoot("probe-timeout");
      const pkgDir = path.join(root, "pkg");
      const { commandPath, bwrapPath } = await makeBundledCodexFixture(pkgDir);
      const { execFileAsync } = stubExecFile(async () => {
        throw Object.assign(new Error("Command failed: probe timed out"), {
          code: null,
          killed: true,
          signal: "SIGKILL",
        });
      });

      const result = await probeCodexLinuxSandboxCapability(
        { resolvedCommand: commandPath, cwd: pkgDir, timeoutMs: 1234 },
        { execFileAsync },
      );

      expect(result.status).toBe("unusable");
      expect(result.probePath).toBe(bwrapPath);
      expect(result.reason).toBe("probe timed out");
    });

    it("falls back to system-bwrap found on the caller env PATH", async () => {
      const root = await makeFixtureRoot("probe-system");
      const pkgDir = path.join(root, "pkg-nobundle");
      const commandPath = path.join(pkgDir, "bin", "codex");
      await mkdir(path.dirname(commandPath), { recursive: true });
      await writeFile(commandPath, "// codex without bundled bwrap\n");
      const systemBwrapPath = path.join(root, "syspath", "bwrap");
      await mkdir(path.dirname(systemBwrapPath), { recursive: true });
      await writeFile(systemBwrapPath, "#!/bin/sh\n");
      await chmod(systemBwrapPath, 0o755);
      const env = { PATH: path.dirname(systemBwrapPath) };
      const { calls, execFileAsync } = stubExecFile(async () => ({ stdout: "", stderr: "" }));

      const result = await probeCodexLinuxSandboxCapability(
        { resolvedCommand: commandPath, cwd: pkgDir, env },
        { execFileAsync },
      );

      expect(result).toEqual({
        status: "usable",
        probe: "system-bwrap",
        probePath: systemBwrapPath,
        reason: null,
      });
      expect(calls).toHaveLength(1);
      expect(calls[0].options.env).toBe(env);
    });

    it("reports inconclusive when no bubblewrap binary can be found at all", async () => {
      const root = await makeFixtureRoot("probe-nobinary");
      const pkgDir = path.join(root, "pkg-nobundle");
      const commandPath = path.join(pkgDir, "bin", "codex");
      await mkdir(path.dirname(commandPath), { recursive: true });
      await writeFile(commandPath, "// codex without bundled bwrap\n");
      const { calls, execFileAsync } = stubExecFile(async () => ({ stdout: "", stderr: "" }));

      const result = await probeCodexLinuxSandboxCapability(
        { resolvedCommand: commandPath, cwd: pkgDir, env: { PATH: "" } },
        { execFileAsync },
      );

      expect(result).toEqual({
        status: "inconclusive",
        probe: null,
        probePath: null,
        reason: "no bubblewrap binary found to probe",
      });
      expect(calls).toHaveLength(0);
    });

    it("reports inconclusive on non-Linux platforms without probing", async () => {
      const root = await makeFixtureRoot("probe-platform");
      const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
      Object.defineProperty(process, "platform", { ...descriptor, value: "darwin" });
      const { calls, execFileAsync } = stubExecFile(async () => ({ stdout: "", stderr: "" }));
      try {
        const result = await probeCodexLinuxSandboxCapability(
          { resolvedCommand: path.join(root, "codex"), cwd: root },
          { execFileAsync },
        );
        expect(result).toEqual({
          status: "inconclusive",
          probe: null,
          probePath: null,
          reason: "probe only supported on Linux",
        });
        expect(calls).toHaveLength(0);
      } finally {
        if (descriptor) Object.defineProperty(process, "platform", descriptor);
      }
    });
  });
});
