/**
 * Android Frida interceptor — attach to apps with SSL unpinning scripts.
 *
 * Uses frida-js (pure JS DBus client, dynamic import) to connect to
 * frida-server on the device via ADB tunnel. Injects bundled SSL unpinning
 * and proxy redirect scripts from src/frida-scripts/vendor/.
 *
 * No native Frida binaries needed on the host machine.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { buildFridaBundle } from "../frida-scripts/bundle.js";
import type { Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult, ActiveTarget } from "./types.js";

const execFileAsync = promisify(execFile);

const FRIDA_PORT = 27042;

/** Convert unknown errors (including plain objects from DBus) to readable strings. */
function stringifyError(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const obj = e as Record<string, unknown>;
    if (obj.message) return String(obj.message);
    if (obj.description) return String(obj.description);
    if (obj.name) return String(obj.name);
    try { return JSON.stringify(e); } catch { /* circular */ }
  }
  return String(e);
}

interface FridaTarget {
  target: ActiveTarget;
  serial: string;
  appName: string;
  // frida-js FridaAgentSession
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  agentSession: any;
  // frida-js FridaScript
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  fridaScript: any;
  // frida-js FridaSession (connection)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  connection: any;
}

export class AndroidFridaInterceptor implements Interceptor {
  readonly id = "android-frida";
  readonly name = "Android (Frida SSL Unpinning)";

  private sessions = new Map<string, FridaTarget>();
  private _activable: boolean | null = null;

  async isActivable(): Promise<boolean> {
    if (this._activable !== null) return this._activable;
    try {
      await import("frida-js");
      // Also need adb for the tunnel
      await execFileAsync("adb", ["version"], { timeout: 5000 });
      this._activable = true;
    } catch {
      this._activable = false;
    }
    return this._activable;
  }

  /** List running apps on device. Exposed via tool, not part of Interceptor interface. */
  async listApps(serial: string): Promise<Array<{ pid: number; name: string }>> {
    await this.ensureFridaTunnel(serial);

    const fridaJs = await import("frida-js");

    let connection;
    try {
      connection = await fridaJs.connect({ host: `127.0.0.1:${FRIDA_PORT}` });
    } catch (e) {
      throw new Error(`Failed to connect to frida-server at 127.0.0.1:${FRIDA_PORT}: ${stringifyError(e)}. Is frida-server running on the device?`);
    }

    try {
      const processes = await connection.enumerateProcesses();
      return processes
        .filter((p) => p.pid > 0)
        .map((p) => ({ pid: p.pid, name: p.name }));
    } catch (e) {
      throw new Error(`Failed to enumerate processes: ${stringifyError(e)}`);
    } finally {
      await connection.disconnect().catch(() => {});
    }
  }

  async activate(options: ActivateOptions): Promise<ActivateResult> {
    const { proxyPort, certPem } = options;
    const serial = options.serial as string | undefined;
    const appName = options.appName as string | undefined;
    const pid = options.pid as number | undefined;

    if (!serial) {
      throw new Error("'serial' option required for Frida interceptor.");
    }
    if (!appName && pid === undefined) {
      throw new Error("Either 'appName' or 'pid' option required.");
    }

    await this.ensureFridaTunnel(serial);

    const fridaJs = await import("frida-js");

    let connection;
    try {
      connection = await fridaJs.connect({ host: `127.0.0.1:${FRIDA_PORT}` });
    } catch (e) {
      throw new Error(`Failed to connect to frida-server at 127.0.0.1:${FRIDA_PORT}: ${stringifyError(e)}. Is frida-server running on the device?`);
    }

    let resolvedPid = pid;
    let resolvedAppName = appName ?? `pid:${pid}`;

    if (pid === undefined) {
      // Find process by name
      let processes;
      try {
        processes = await connection.enumerateProcesses();
      } catch (e) {
        await connection.disconnect().catch(() => {});
        throw new Error(`Failed to enumerate processes: ${stringifyError(e)}`);
      }
      const proc = processes.find((p) => p.name === appName);
      if (!proc) {
        await connection.disconnect().catch(() => {});
        throw new Error(`App '${appName}' not found. Use interceptor_frida_apps to list running apps.`);
      }
      resolvedPid = proc.pid;
      resolvedAppName = proc.name;
    }

    // Build the unpinning script bundle
    const scriptSource = buildFridaBundle({
      proxyHost: "127.0.0.1",
      proxyPort,
      certPem,
    });

    // injectIntoProcess does attach + createScript + loadScript in one call
    let agentSession, fridaScript;
    try {
      const result = await connection.injectIntoProcess(resolvedPid!, scriptSource);
      agentSession = result.session;
      fridaScript = result.script;
    } catch (e) {
      await connection.disconnect().catch(() => {});
      throw new Error(`Failed to inject into PID ${resolvedPid}: ${stringifyError(e)}`);
    }

    const targetId = `frida_${serial}_${resolvedPid}`;

    const target: ActiveTarget = {
      id: targetId,
      description: `${resolvedAppName} (PID ${resolvedPid}) on ${serial}`,
      activatedAt: Date.now(),
      details: {
        serial,
        appName: resolvedAppName,
        pid: resolvedPid,
        proxyPort,
        scriptsInjected: true,
      },
    };

    this.sessions.set(targetId, {
      target,
      serial,
      appName: resolvedAppName,
      agentSession,
      fridaScript,
      connection,
    });

    return { targetId, details: target.details };
  }

  async deactivate(targetId: string): Promise<void> {
    const entry = this.sessions.get(targetId);
    if (!entry) {
      throw new Error(`No Frida session with target ID '${targetId}'`);
    }

    try {
      await entry.agentSession.kill();
    } catch { /* may already be detached */ }

    try {
      await entry.connection.disconnect();
    } catch { /* may already be disconnected */ }

    this.sessions.delete(targetId);
  }

  async deactivateAll(): Promise<void> {
    const ids = [...this.sessions.keys()];
    for (const id of ids) {
      try {
        await this.deactivate(id);
      } catch { /* best effort */ }
    }
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description: "Attach to Android apps via Frida, inject SSL unpinning + proxy redirect scripts. Requires frida-server on device.",
      isActivable: await this.isActivable(),
      activeTargets: [...this.sessions.values()].map((s) => s.target),
    };
  }

  /** Ensure ADB forward tunnel to frida-server on device. */
  private async ensureFridaTunnel(serial: string): Promise<void> {
    try {
      await execFileAsync("adb", ["-s", serial, "forward", `tcp:${FRIDA_PORT}`, `tcp:${FRIDA_PORT}`], { timeout: 10000 });
    } catch (e) {
      throw new Error(`Failed to set up ADB forward to frida-server: ${e}. Is frida-server running on the device?`);
    }
  }
}
