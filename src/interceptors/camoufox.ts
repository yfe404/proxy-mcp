/**
 * Camoufox interceptor — anti-detect Firefox via Playwright WS.
 *
 * Spawns a Python subprocess that wraps `camoufox.server.launch_server()`
 * with a WS-endpoint capture step. The wrapper reads the underlying
 * Playwright Node child's stdout, extracts the websocket URL, and writes
 * it atomically to `${launcherDir}/ws-endpoint.json`. Node side polls
 * that file — no regex on the hot path, immune to ANSI colour codes,
 * log-level prefixes, and any other future formatting tweaks.
 *
 * CA trust: NSS profile dir created with `certutil -N` and the proxy CA
 * imported as `proxy-mcp-ca`. Camoufox is launched with `user_data_dir`,
 * `persistent_context: true`, and `firefox_user_prefs.security.enterprise_roots.enabled`
 * = true so hardened-Firefox builds actually honour the imported CA. If
 * `certutil` is not on PATH the launch still succeeds — the user gets a
 * logged warning and HTTPS pages will show cert errors (proxy traffic
 * still flows).
 *
 * Spawn safety: the launcher's cwd is set to its own temp dir, AND a
 * `${launcherDir}/package.json` with `{"type":"commonjs"}` is written
 * before spawn. This isolates the wrapper from any stale `/tmp/package.json`
 * (e.g. left by other tools) that would otherwise poison Node's module
 * resolution and force `launchServer.js` to be loaded as ESM.
 */

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, writeFile, rm, access, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult, ActiveTarget,
} from "./types.js";

export interface CamoufoxTargetEntry {
  target: ActiveTarget;
  process: ChildProcess;
  wsUrl: string;
  profileDir: string | null;
  launcherDir: string;
}

const DEFAULT_LAUNCH_TIMEOUT_MS = 30_000;
const FORWARDED_PARAMS = [
  "os", "webgl_config", "fonts", "config", "humanize", "addons",
  "main_world_eval", "enable_cache", "disable_coop", "block_webgl",
  "block_images", "locale", "port", "ws_path", "firefox_user_prefs",
] as const;

type CamoufoxParam = (typeof FORWARDED_PARAMS)[number];

export class CamoufoxInterceptor implements Interceptor {
  readonly id = "camoufox";
  readonly name = "Camoufox (anti-detect Firefox via Playwright)";

  private launched = new Map<string, CamoufoxTargetEntry>();
  private _activable: boolean | null = null;
  private _pythonExe: string = "python3";

  async isActivable(): Promise<boolean> {
    if (this._activable !== null) return this._activable;
    try {
      const r = spawnSync(this._pythonExe, ["-c", "import camoufox"], { stdio: "ignore" });
      this._activable = r.status === 0;
    } catch {
      this._activable = false;
    }
    return this._activable;
  }

  getEntry(targetId: string): CamoufoxTargetEntry | undefined {
    return this.launched.get(targetId);
  }

  listEntries(): CamoufoxTargetEntry[] {
    return [...this.launched.values()];
  }

  async activate(options: ActivateOptions): Promise<ActivateResult> {
    const { proxyPort, certPem } = options;
    const headless = options.headless === undefined ? true : Boolean(options.headless);
    const blockWebrtc = options.block_webrtc === undefined ? true : Boolean(options.block_webrtc);
    const geoip = options.geoip === undefined ? true : options.geoip as boolean | string;
    const trustProxyCert = options.trust_proxy_cert === undefined ? true : Boolean(options.trust_proxy_cert);
    const pythonExe = typeof options.python_executable === "string" && options.python_executable
      ? options.python_executable
      : "python3";

    const params: Record<string, unknown> = {
      proxy: { server: `http://127.0.0.1:${proxyPort}` },
      headless,
      block_webrtc: blockWebrtc,
      geoip,
    };

    for (const key of FORWARDED_PARAMS as readonly CamoufoxParam[]) {
      const v = (options as Record<string, unknown>)[key];
      if (v !== undefined) params[key] = v;
    }

    let profileDir: string | null = null;
    if (trustProxyCert) {
      profileDir = await this.injectCaIntoNssProfile(certPem);
      if (profileDir) {
        params.user_data_dir = profileDir;
        params.persistent_context = true;
        // Hardened-Firefox builds (camoufox) ignore user-imported NSS
        // CAs unless this pref is set. Without it MITM-decrypted HTTPS
        // pages return SEC_ERROR_UNKNOWN_ISSUER even though the proxy CA
        // is in cert9.db. Caller-supplied prefs take precedence on key
        // collision; we only fill in the default.
        const callerPrefs = (params.firefox_user_prefs as Record<string, unknown> | undefined) ?? {};
        params.firefox_user_prefs = {
          "security.enterprise_roots.enabled": true,
          ...callerPrefs,
        };
      }
    }

    const launcherDir = await mkdtemp(join(tmpdir(), "proxy-mcp-camoufox-"));

    // Defensive isolation against poisoned ancestor package.json files: the
    // python wrapper invokes `node launchServer.js` (CommonJS) under
    // `playwright/driver/package`, but Node walks UP the cwd if no closer
    // package.json overrides. A stray `/tmp/package.json` with
    // `"type":"module"` would force ESM loading and break `require(...)`.
    // Two belts: (1) we set spawn cwd to `launcherDir`, (2) we drop a
    // commonjs marker package.json in `launcherDir` itself so the closest
    // ancestor pin is always one we control.
    const cjsMarker = join(launcherDir, "package.json");
    await writeFile(cjsMarker, JSON.stringify({ type: "commonjs" }), "utf-8");

    const wsEndpointFile = join(launcherDir, "ws-endpoint.json");
    const scriptPath = join(launcherDir, "launch.py");
    await writeFile(scriptPath, buildLauncherScript(params, wsEndpointFile), "utf-8");

    const proc = spawn(pythonExe, [scriptPath], {
      stdio: ["ignore", "pipe", "pipe"],
      cwd: launcherDir,
      env: {
        ...process.env,
        NO_COLOR: "1",
        PYTHONIOENCODING: "utf-8",
      },
    });

    let wsUrl: string;
    try {
      wsUrl = await awaitWsEndpoint(proc, wsEndpointFile, DEFAULT_LAUNCH_TIMEOUT_MS);
    } catch (e) {
      try { proc.kill("SIGKILL"); } catch { /* already gone */ }
      await rm(launcherDir, { recursive: true, force: true }).catch(() => {});
      if (profileDir) await rm(profileDir, { recursive: true, force: true }).catch(() => {});
      throw e;
    }

    const pid = typeof proc.pid === "number" ? proc.pid : 0;
    const targetId = `camoufox_${pid}_${Date.now()}`;

    const details: Record<string, unknown> = {
      wsUrl,
      proxyPort,
      headless,
      humanize: options.humanize ?? null,
      geoip,
      block_webrtc: blockWebrtc,
      main_world_eval: Boolean(params.main_world_eval),
      ...(options.os !== undefined ? { os: options.os } : {}),
      ...(options.locale !== undefined ? { locale: options.locale } : {}),
      profileDir,
      certutil: profileDir !== null,
      playwright_connect: `await firefox.connect('${wsUrl}')`,
    };

    const target: ActiveTarget = {
      id: targetId,
      description: `camoufox (headless=${headless})`,
      activatedAt: Date.now(),
      details,
    };

    const entry: CamoufoxTargetEntry = { target, process: proc, wsUrl, profileDir, launcherDir };
    this.launched.set(targetId, entry);

    proc.once("exit", () => {
      this.launched.delete(targetId);
      rm(launcherDir, { recursive: true, force: true }).catch(() => {});
      if (profileDir) rm(profileDir, { recursive: true, force: true }).catch(() => {});
    });

    return { targetId, details };
  }

  async deactivate(targetId: string): Promise<void> {
    const entry = this.launched.get(targetId);
    if (!entry) {
      throw new Error(`No camoufox instance with target ID '${targetId}'`);
    }

    // If a caller previously took over the camoufox target via the
    // session.ts driver path (`firefox.connect(wsUrl)`), the cached
    // Playwright Browser handle is stored back on the entry. Close it
    // before SIGTERM-ing the python launcher so Playwright shuts down
    // its WS client cleanly.
    const browseable = entry as CamoufoxTargetEntry & { browser?: { close: () => Promise<void> } };
    if (browseable.browser) {
      try { await browseable.browser.close(); } catch { /* best effort */ }
    }

    const proc = entry.process;
    if (proc.exitCode === null) {
      try { proc.kill("SIGTERM"); } catch { /* ignore */ }
      const killed = await waitForExit(proc, 3_000);
      if (!killed) {
        try { proc.kill("SIGKILL"); } catch { /* ignore */ }
        await waitForExit(proc, 1_000);
      }
    }

    await rm(entry.launcherDir, { recursive: true, force: true }).catch(() => {});
    if (entry.profileDir) {
      await rm(entry.profileDir, { recursive: true, force: true }).catch(() => {});
    }
    this.launched.delete(targetId);
  }

  async deactivateAll(): Promise<void> {
    const ids = [...this.launched.keys()];
    for (const id of ids) {
      try { await this.deactivate(id); } catch { /* best effort */ }
    }
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description:
        "Launch camoufox (anti-detect Firefox) as a Playwright WS server with proxy + NSS CA trust. " +
        "Drive the returned target_id through the same `interceptor_browser_*` and `humanizer_*` " +
        "tools as cloakbrowser. Requires Python + `pip install camoufox[geoip]`.",
      isActivable: await this.isActivable(),
      activeTargets: [...this.launched.values()].map((e) => e.target),
    };
  }

  /**
   * Create an NSS profile dir, run `certutil -N` (empty password) then
   * `certutil -A` to import the proxy CA. Returns the profile dir on
   * success, or null if certutil is missing / fails (degraded mode).
   */
  private async injectCaIntoNssProfile(certPem: string): Promise<string | null> {
    const probe = spawnSync("certutil", ["--help"], { stdio: "ignore" });
    if (probe.error || probe.status === undefined || probe.status === null) {
      console.error("[camoufox] certutil not found — launching without CA trust. HTTPS pages will show cert errors.");
      return null;
    }

    const profileDir = await mkdtemp(join(tmpdir(), "proxy-mcp-camoufox-nss-"));
    const initRes = spawnSync(
      "certutil",
      ["-N", "--empty-password", "-d", `sql:${profileDir}`],
      { stdio: "ignore" },
    );
    if (initRes.status !== 0) {
      console.error("[camoufox] certutil -N failed — launching without CA trust.");
      await rm(profileDir, { recursive: true, force: true }).catch(() => {});
      return null;
    }

    const certPath = join(profileDir, "proxy-mcp-ca.pem");
    await writeFile(certPath, certPem, "utf-8");
    const addRes = spawnSync(
      "certutil",
      ["-A", "-n", "proxy-mcp-ca", "-t", "CT,,", "-d", `sql:${profileDir}`, "-i", certPath],
      { stdio: "ignore" },
    );
    if (addRes.status !== 0) {
      console.error("[camoufox] certutil -A failed — launching without CA trust.");
      await rm(profileDir, { recursive: true, force: true }).catch(() => {});
      return null;
    }

    return profileDir;
  }
}

/* ----------------------------------------------------------------------- */
/*  Helpers (also exported for unit tests)                                  */
/* ----------------------------------------------------------------------- */

/**
 * Generate the Python launcher.
 *
 * Reimplements `camoufox.server.launch_server` so we can pipe the
 * underlying Playwright Node child's stdout instead of inheriting it.
 * The wrapper extracts the websocket URL from the first matching line
 * (after stripping ANSI escapes) and atomically writes a JSON handshake
 * file at `wsEndpointFile`. The original line is forwarded to stdout for
 * log visibility; subsequent lines pass through unchanged.
 *
 * If camoufox upstream changes its emission format the wrapper's regex
 * is the only thing to update — Node side polls a file with a fixed
 * schema and never sees the print formatting.
 */
export function buildLauncherScript(
  params: Record<string, unknown>,
  wsEndpointFile: string,
): string {
  const json = JSON.stringify(params);
  // Embed as a Python-safe string literal: backslash-escape backslashes and
  // single quotes, then drop the result inside single quotes. Newlines and
  // double quotes are already escaped by JSON.stringify.
  const escapedParams = json.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const escapedWsFile = wsEndpointFile.replace(/\\/g, "\\\\").replace(/'/g, "\\'");

  return [
    "import sys, json, base64, signal, subprocess, re, os, tempfile, time",
    "from pathlib import Path",
    "import orjson",
    "from camoufox.server import LAUNCH_SCRIPT, get_nodejs, to_camel_case_dict",
    "from camoufox.utils import launch_options",
    "",
    `_WS_FILE = '${escapedWsFile}'`,
    "_ANSI = re.compile(r'\\x1b\\[[0-9;]*m')",
    "_WS_RE = re.compile(r'Websocket endpoint:\\s*(ws://\\S+)')",
    "",
    `params = json.loads('${escapedParams}')`,
    "config = launch_options(**params)",
    "nodejs = get_nodejs()",
    "data = orjson.dumps(to_camel_case_dict(config))",
    "",
    "proc = subprocess.Popen(",
    "    [nodejs, str(LAUNCH_SCRIPT)],",
    "    cwd=str(Path(nodejs).parent / 'package'),",
    "    stdin=subprocess.PIPE,",
    "    stdout=subprocess.PIPE,",
    "    stderr=subprocess.STDOUT,",
    "    text=True, bufsize=1,",
    ")",
    "if proc.stdin:",
    "    proc.stdin.write(base64.b64encode(data).decode())",
    "    proc.stdin.close()",
    "",
    "def _term(*_):",
    "    try: proc.terminate()",
    "    except Exception: pass",
    "    sys.exit(0)",
    "signal.signal(signal.SIGTERM, _term)",
    "",
    "_ws_done = False",
    "for line in proc.stdout:",
    "    sys.stdout.write(line)",
    "    sys.stdout.flush()",
    "    if not _ws_done:",
    "        m = _WS_RE.search(_ANSI.sub('', line))",
    "        if m:",
    "            _ws_done = True",
    "            payload = json.dumps({'wsUrl': m.group(1), 'ts': int(time.time())})",
    "            d = os.path.dirname(_WS_FILE) or '.'",
    "            fd, tmp = tempfile.mkstemp(prefix='.ws-', dir=d)",
    "            with os.fdopen(fd, 'w') as f:",
    "                f.write(payload)",
    "            os.replace(tmp, _WS_FILE)",
    "",
    "proc.wait()",
    "sys.exit(proc.returncode or 0)",
    "",
  ].join("\n");
}

interface WsHandshake {
  wsUrl: string;
  ts: number;
}

/**
 * Poll `wsEndpointFile` until the python wrapper writes the handshake
 * JSON, or `proc` exits, or the timeout fires — whichever happens first.
 *
 * Replaces the previous stdout-regex parser. The contract is now
 * insensitive to upstream camoufox / Playwright print formatting:
 * any change in what they print to stdout / stderr is the python
 * wrapper's problem (it can update its own regex), and Node only
 * reads a structured file.
 */
export function awaitWsEndpoint(
  proc: ChildProcess,
  wsEndpointFile: string,
  timeoutMs: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let stderrTail = "";

    const onStderr = (chunk: Buffer | string) => {
      // Capture for diagnostic purposes only — failure path slices the
      // last 500 bytes into the rejection message exactly like before.
      stderrTail = (stderrTail + chunk.toString("utf-8")).slice(-2000);
    };

    const onStdout = onStderr; // mirrored — stderr is piped to stdout in our launcher

    const onExit = (code: number | null) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error(
        `camoufox launcher exited (code=${code}) before emitting Websocket endpoint. ` +
        `stderr: ${stderrTail.slice(-500)}`,
      ));
    };

    const onTimeout = () => {
      if (settled) return;
      settled = true;
      cleanup();
      try { proc.kill("SIGKILL"); } catch { /* ignore */ }
      reject(new Error(
        `Timed out after ${timeoutMs}ms waiting for camoufox Websocket endpoint. ` +
        `last output: ${stderrTail.slice(-500)}`,
      ));
    };

    const timer = setTimeout(onTimeout, timeoutMs);

    let pollHandle: NodeJS.Timeout | null = null;
    const poll = async () => {
      if (settled) return;
      try {
        await access(wsEndpointFile);
      } catch {
        pollHandle = setTimeout(poll, 75);
        return;
      }
      try {
        const raw = await readFile(wsEndpointFile, "utf-8");
        const handshake = JSON.parse(raw) as WsHandshake;
        if (typeof handshake.wsUrl === "string" && handshake.wsUrl.startsWith("ws://")) {
          settled = true;
          cleanup();
          resolve(handshake.wsUrl);
          return;
        }
        // File present but malformed — keep polling; the python wrapper
        // writes atomically via rename, so a partial read shouldn't
        // happen, but tolerate it rather than fail the launch.
        pollHandle = setTimeout(poll, 75);
      } catch {
        pollHandle = setTimeout(poll, 75);
      }
    };

    function cleanup() {
      clearTimeout(timer);
      if (pollHandle) clearTimeout(pollHandle);
      proc.stdout?.off("data", onStdout);
      proc.stderr?.off("data", onStderr);
      proc.off("exit", onExit);
    }

    proc.stdout?.on("data", onStdout);
    proc.stderr?.on("data", onStderr);
    proc.once("exit", onExit);
    poll();
  });
}

function waitForExit(proc: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (proc.exitCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    proc.once("exit", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}
