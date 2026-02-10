/**
 * Terminal interceptor — spawn processes with proxy env vars pre-configured.
 *
 * Sets HTTP_PROXY, HTTPS_PROXY, SSL_CERT_FILE, and many language/tool-specific
 * env vars so spawned processes automatically route through the MITM proxy.
 * Zero external dependencies — uses Node.js child_process.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { writeCertTempFile } from "./cert-utils.js";
import type { Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult, ActiveTarget } from "./types.js";

const MAX_OUTPUT_BUFFER = 8192;

interface SpawnedProcess {
  target: ActiveTarget;
  process: ChildProcess;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  exited: boolean;
}

export class TerminalInterceptor implements Interceptor {
  readonly id = "terminal";
  readonly name = "Terminal / Process Spawner";

  private spawned = new Map<string, SpawnedProcess>();

  async isActivable(): Promise<boolean> {
    return true; // Always available — pure Node.js
  }

  async activate(options: ActivateOptions): Promise<ActivateResult> {
    const { proxyPort, certPem, certFingerprint } = options;
    const command = options.command as string | undefined;
    const args = options.args as string[] | undefined;
    const cwd = options.cwd as string | undefined;
    const env = options.env as Record<string, string> | undefined;

    if (!command) {
      throw new Error("'command' option is required for terminal interceptor");
    }

    // Write cert to temp file for SSL_CERT_FILE and friends
    const certPath = await writeCertTempFile(certPem);

    const proxyUrl = `http://127.0.0.1:${proxyPort}`;

    // Build env with proxy vars
    const proxyEnv: Record<string, string> = {
      ...process.env as Record<string, string>,
      ...env,
      // Standard proxy vars (both cases for compatibility)
      HTTP_PROXY: proxyUrl,
      HTTPS_PROXY: proxyUrl,
      http_proxy: proxyUrl,
      https_proxy: proxyUrl,
      // SSL certificate file (many tools check this)
      SSL_CERT_FILE: certPath,
      // Node.js
      NODE_EXTRA_CA_CERTS: certPath,
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
      // Python requests
      REQUESTS_CA_BUNDLE: certPath,
      // curl
      CURL_CA_BUNDLE: certPath,
      // AWS SDK
      AWS_CA_BUNDLE: certPath,
      // Deno
      DENO_CERT: certPath,
      DENO_TLS_CA_STORE: "system",
      // Git
      GIT_SSL_CAINFO: certPath,
      GIT_SSL_NO_VERIFY: "true",
      // npm/yarn
      npm_config_proxy: proxyUrl,
      npm_config_https_proxy: proxyUrl,
      npm_config_cafile: certPath,
      npm_config_strict_ssl: "false",
      // Certificate fingerprint (for reference)
      PROXY_MCP_CERT_FINGERPRINT: certFingerprint,
    };

    const child = spawn(command, args ?? [], {
      cwd,
      env: proxyEnv,
      stdio: ["ignore", "pipe", "pipe"],
      detached: false,
    });

    const targetId = `proc_${child.pid ?? Date.now()}`;

    const entry: SpawnedProcess = {
      target: {
        id: targetId,
        description: `${command} ${(args ?? []).join(" ")}`.trim(),
        activatedAt: Date.now(),
        details: {
          pid: child.pid,
          command,
          args: args ?? [],
          cwd: cwd ?? process.cwd(),
          proxyUrl,
          certPath,
        },
      },
      process: child,
      stdout: "",
      stderr: "",
      exitCode: null,
      exited: false,
    };

    // Capture stdout/stderr in ring buffers
    child.stdout?.on("data", (chunk: Buffer) => {
      entry.stdout += chunk.toString("utf-8");
      if (entry.stdout.length > MAX_OUTPUT_BUFFER) {
        entry.stdout = entry.stdout.slice(-MAX_OUTPUT_BUFFER);
      }
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      entry.stderr += chunk.toString("utf-8");
      if (entry.stderr.length > MAX_OUTPUT_BUFFER) {
        entry.stderr = entry.stderr.slice(-MAX_OUTPUT_BUFFER);
      }
    });

    child.on("exit", (code) => {
      entry.exitCode = code;
      entry.exited = true;
    });

    child.on("error", (err) => {
      entry.stderr += `\n[spawn error] ${err.message}`;
      entry.exited = true;
    });

    this.spawned.set(targetId, entry);

    return {
      targetId,
      details: {
        pid: child.pid,
        command,
        args: args ?? [],
        proxyUrl,
        certPath,
      },
    };
  }

  async deactivate(targetId: string): Promise<void> {
    const entry = this.spawned.get(targetId);
    if (!entry) {
      throw new Error(`No spawned process with target ID '${targetId}'`);
    }

    if (!entry.exited) {
      entry.process.kill("SIGTERM");
      // Give it a moment, then force kill
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          if (!entry.exited) entry.process.kill("SIGKILL");
          resolve();
        }, 3000);
        entry.process.once("exit", () => {
          clearTimeout(timeout);
          resolve();
        });
      });
    }

    this.spawned.delete(targetId);
  }

  async deactivateAll(): Promise<void> {
    const ids = [...this.spawned.keys()];
    for (const id of ids) {
      try {
        await this.deactivate(id);
      } catch {
        // Best effort
      }
    }
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description: "Spawn processes with HTTP_PROXY, HTTPS_PROXY, SSL_CERT_FILE, and 15+ env vars pre-configured for automatic proxy routing.",
      isActivable: true,
      activeTargets: [...this.spawned.values()].map((s) => ({
        ...s.target,
        details: {
          ...s.target.details,
          exited: s.exited,
          exitCode: s.exitCode,
          stdoutTail: s.stdout.slice(-1024),
          stderrTail: s.stderr.slice(-1024),
        },
      })),
    };
  }

  /** Get output for a specific spawned process. */
  getProcessOutput(targetId: string): { stdout: string; stderr: string; exitCode: number | null; exited: boolean } | undefined {
    const entry = this.spawned.get(targetId);
    if (!entry) return undefined;
    return {
      stdout: entry.stdout,
      stderr: entry.stderr,
      exitCode: entry.exitCode,
      exited: entry.exited,
    };
  }
}
