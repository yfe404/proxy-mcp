/**
 * DevTools bridge tools — proxy-safe wrappers around chrome-devtools-mcp sidecar.
 *
 * These tools enforce binding to a specific Chrome interceptor target_id so
 * CDP actions and proxy capture always refer to the same browser instance.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { interceptorManager } from "../interceptors/manager.js";
import { getCdpBaseUrl, getCdpTargets } from "../cdp-utils.js";
import { proxyManager } from "../state.js";
import { truncateResult } from "../utils.js";
import { devToolsBridge, getLocalSidecarStatus, resetSidecarResolutionCache } from "../devtools/bridge.js";

function errorToString(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeHostname(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function estimateBase64Bytes(data: string): number {
  const len = data.length;
  const padding = data.endsWith("==") ? 2 : data.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((len * 3) / 4) - padding);
}

function sanitizeDevToolsPayload(payload: unknown): unknown {
  if (Array.isArray(payload)) {
    return payload.map((item) => sanitizeDevToolsPayload(item));
  }
  if (!payload || typeof payload !== "object") {
    return payload;
  }

  const obj = payload as Record<string, unknown>;
  if (obj.type === "image" && typeof obj.data === "string") {
    const bytes = estimateBase64Bytes(obj.data);
    const { data, ...rest } = obj;
    return {
      ...rest,
      dataRedacted: true,
      redactionReason: "Omitted base64 image payload to keep MCP context small.",
      approximateImageBytes: bytes,
    };
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = sanitizeDevToolsPayload(v);
  }
  return out;
}

function findProjectRoot(): string {
  const start = dirname(fileURLToPath(import.meta.url));
  let dir = start;
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, "package.json"))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}

async function runInstallCommand(
  command: string,
  args: string[],
  cwd: string,
  timeoutMs: number,
): Promise<{ exitCode: number | null; stdout: string; stderr: string; timedOut: boolean }> {
  return await new Promise((resolve) => {
    const child = spawn(command, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });

    let stdout = "";
    let stderr = "";
    let resolved = false;
    let timedOut = false;

    const done = (exitCode: number | null): void => {
      if (resolved) return;
      resolved = true;
      resolve({ exitCode, stdout: stdout.trim(), stderr: stderr.trim(), timedOut });
    };

    child.stdout?.on("data", (d: unknown) => {
      stdout += String(d);
    });
    child.stderr?.on("data", (d: unknown) => {
      stderr += String(d);
    });

    child.on("error", (e) => {
      stderr += `\n${String(e)}`;
      done(-1);
    });
    child.on("close", (code) => done(code));

    setTimeout(() => {
      if (!resolved) {
        timedOut = true;
        child.kill("SIGTERM");
      }
    }, timeoutMs);
  });
}

async function getChromeTargetPort(targetId: string): Promise<number> {
  const chrome = interceptorManager.get("chrome");
  if (!chrome) {
    throw new Error("Chrome interceptor not registered.");
  }

  const meta = await chrome.getMetadata();
  const target = meta.activeTargets.find((t) => t.id === targetId);
  if (!target) {
    throw new Error(`Chrome target '${targetId}' not found. Is it still running?`);
  }

  // Chrome interceptor stores CDP port in details.port
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const details: any = target.details ?? {};
  const port = details.port;
  if (typeof port !== "number" || !Number.isFinite(port) || port <= 0) {
    throw new Error(`Chrome target '${targetId}' has no valid CDP port.`);
  }

  return port;
}

async function ensureSessionTargetIsAlive(sessionId: string): Promise<{ targetId: string }> {
  const session = devToolsBridge.getSession(sessionId);
  if (!session) {
    throw new Error(`DevTools session '${sessionId}' not found.`);
  }

  try {
    await getChromeTargetPort(session.targetId);
  } catch (e) {
    await devToolsBridge.closeSession(sessionId).catch(() => {});
    throw new Error(`Bound Chrome target is no longer available: ${errorToString(e)}`);
  }

  return { targetId: session.targetId };
}

export function registerDevToolsTools(server: McpServer): void {
  server.tool(
    "interceptor_chrome_devtools_pull_sidecar",
    "Install/pull chrome-devtools-mcp sidecar locally so full DevTools bridge actions are available.",
    {
      version: z.string().optional().default("0.2.2").describe("Sidecar version to install"),
      timeout_ms: z.number().optional().default(180000).describe("Install timeout in milliseconds"),
      save_exact: z.boolean().optional().default(false)
        .describe("When true, persist to package.json with --save-exact (default false uses --no-save)"),
    },
    async ({ version, timeout_ms, save_exact }) => {
      try {
        const cwd = findProjectRoot();
        const spec = `chrome-devtools-mcp@${version}`;
        const args = save_exact
          ? ["install", "--save-exact", spec]
          : ["install", "--no-save", spec];

        const before = getLocalSidecarStatus();
        const result = await runInstallCommand("npm", args, cwd, timeout_ms);
        resetSidecarResolutionCache();
        const after = getLocalSidecarStatus();

        const ok = result.exitCode === 0 && !result.timedOut && after.available;
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: ok ? "success" : "error",
              installed: ok,
              version,
              mode: save_exact ? "save-exact" : "no-save",
              cwd,
              before,
              after,
              command: `npm ${args.join(" ")}`,
              exitCode: result.exitCode,
              timedOut: result.timedOut,
              stdoutTail: result.stdout.slice(-1500),
              stderrTail: result.stderr.slice(-1500),
              ...(ok
                ? {}
                : {
                    hint:
                      "Install failed or sidecar not resolvable. Check network/npm registry access and rerun this tool.",
                  }),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_attach",
    "Start a chrome-devtools-mcp sidecar session bound to a specific interceptor_chrome_launch target_id.",
    {
      target_id: z.string().describe("Target ID from interceptor_chrome_launch"),
      include_targets: z.boolean().optional().default(false).describe("Include current CDP tab targets in output (default: false)"),
      timeout_ms: z.number().optional().default(1500).describe("Timeout when fetching optional CDP target list"),
    },
    async ({ target_id, include_targets, timeout_ms }) => {
      try {
        const port = await getChromeTargetPort(target_id);
        const browserUrl = getCdpBaseUrl(port);
        const session = await devToolsBridge.createSession(target_id, browserUrl);

        let cdpTargets: Array<Record<string, unknown>> | null = null;
        let targetsError: string | null = null;

        if (include_targets) {
          try {
            cdpTargets = await getCdpTargets(port, { timeoutMs: timeout_ms });
          } catch (e) {
            targetsError = errorToString(e);
          }
        }

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              session,
              ...(session.mode === "native-fallback"
                ? {
                    warning:
                      "chrome-devtools-mcp binary was not found. Session is running in native-fallback mode: " +
                      "navigation works, but snapshot/network/console/screenshot require installing chrome-devtools-mcp.",
                  }
                : {}),
              cdp: {
                httpUrl: browserUrl,
              },
              cdpTargets,
              ...(targetsError ? { targetsError } : {}),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_detach",
    "Close a chrome-devtools-mcp sidecar session by session ID.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
    },
    async ({ devtools_session_id }) => {
      try {
        const closed = await devToolsBridge.closeSession(devtools_session_id);
        if (!closed) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({ status: "error", error: `DevTools session '${devtools_session_id}' not found.` }),
            }],
          };
        }
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: `DevTools session ${devtools_session_id} closed.` }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_navigate",
    "Navigate the bound Chrome session via chrome-devtools-mcp and verify matching host traffic was captured by proxy-mcp.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      url: z.string().describe("Destination URL"),
      wait_for_proxy_capture: z.boolean().optional().default(true)
        .describe("Wait for matching proxy traffic after navigate (default: true)"),
      timeout_ms: z.number().optional().default(5000).describe("Max wait for navigate response and optional proxy verification"),
      poll_interval_ms: z.number().optional().default(200).describe("Polling interval while waiting for proxy capture"),
    },
    async ({ devtools_session_id, url, wait_for_proxy_capture, timeout_ms, poll_interval_ms }) => {
      try {
        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const beforeCount = proxyManager.getTraffic().length;
        const devtoolsResult = await devToolsBridge.callAction(
          devtools_session_id,
          "navigate",
          { type: "url", url },
        );

        const destinationHost = normalizeHostname(url);
        let matchedExchangeIds: string[] = [];
        let sawAnyNewTraffic = false;
        let waitedMs = 0;

        if (wait_for_proxy_capture) {
          const startedAt = Date.now();
          while (Date.now() - startedAt <= timeout_ms) {
            const delta = proxyManager.getTraffic().slice(beforeCount);
            if (delta.length > 0) sawAnyNewTraffic = true;

            if (destinationHost) {
              const matches = delta
                .filter((x) => {
                  const host = x.request.hostname.toLowerCase();
                  return host === destinationHost || host.endsWith(`.${destinationHost}`);
                })
                .map((x) => x.id);
              if (matches.length > 0) {
                matchedExchangeIds = matches;
                break;
              }
            } else if (delta.length > 0) {
              matchedExchangeIds = delta.map((x) => x.id);
              break;
            }

            await sleep(Math.max(50, poll_interval_ms));
            waitedMs = Date.now() - startedAt;
          }
        }

        const delta = proxyManager.getTraffic().slice(beforeCount);
        const response: Record<string, unknown> = {
          status: "success",
          devtools_session_id,
          target_id: targetId,
          url,
          devtoolsResult: sanitizeDevToolsPayload(devtoolsResult),
          traffic: {
            beforeCount,
            afterCount: beforeCount + delta.length,
            deltaCount: delta.length,
            destinationHost,
            matchedHostExchangeCount: matchedExchangeIds.length,
            matchedHostExchangeIds: matchedExchangeIds,
            waitedMs,
          },
        };

        if (wait_for_proxy_capture && destinationHost && matchedExchangeIds.length === 0) {
          response.warning = sawAnyNewTraffic
            ? `Navigation succeeded but no '${destinationHost}' traffic was captured within ${timeout_ms}ms.`
            : `No new proxy traffic observed within ${timeout_ms}ms after navigation.`;
        }

        return {
          content: [{
            type: "text",
            text: truncateResult(response),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_snapshot",
    "Take an accessibility snapshot from the bound Chrome DevTools session.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      verbose: z.boolean().optional().default(false).describe("Include full a11y tree details"),
    },
    async ({ devtools_session_id, verbose }) => {
      try {
        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const devtoolsResult = await devToolsBridge.callAction(
          devtools_session_id,
          "snapshot",
          { verbose },
        );
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              devtoolsResult: sanitizeDevToolsPayload(devtoolsResult),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_list_network",
    "List network requests from the bound Chrome DevTools session.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      include_preserved_requests: z.boolean().optional().default(false)
        .describe("Include requests preserved over the last navigations"),
      resource_types: z.array(z.string()).optional().describe("Filter by resource types"),
      page_idx: z.number().optional().describe("Page number (0-based)"),
      page_size: z.number().optional().describe("Page size"),
    },
    async ({ devtools_session_id, include_preserved_requests, resource_types, page_idx, page_size }) => {
      try {
        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const args: Record<string, unknown> = {
          includePreservedRequests: include_preserved_requests,
        };
        if (resource_types && resource_types.length > 0) args.resourceTypes = resource_types;
        if (page_idx !== undefined) args.pageIdx = page_idx;
        if (page_size !== undefined) args.pageSize = page_size;

        const devtoolsResult = await devToolsBridge.callAction(devtools_session_id, "listNetwork", args);
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              devtoolsResult: sanitizeDevToolsPayload(devtoolsResult),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_list_console",
    "List console messages from the bound Chrome DevTools session.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      include_preserved_messages: z.boolean().optional().default(false)
        .describe("Include messages preserved over the last navigations"),
      types: z.array(z.string()).optional().describe("Filter by console message types"),
      page_idx: z.number().optional().describe("Page number (0-based)"),
      page_size: z.number().optional().describe("Page size"),
    },
    async ({ devtools_session_id, include_preserved_messages, types, page_idx, page_size }) => {
      try {
        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const args: Record<string, unknown> = {
          includePreservedMessages: include_preserved_messages,
        };
        if (types && types.length > 0) args.types = types;
        if (page_idx !== undefined) args.pageIdx = page_idx;
        if (page_size !== undefined) args.pageSize = page_size;

        const devtoolsResult = await devToolsBridge.callAction(devtools_session_id, "listConsole", args);
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              devtoolsResult: sanitizeDevToolsPayload(devtoolsResult),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_screenshot",
    "Take a screenshot using the bound Chrome DevTools session.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      file_path: z.string().optional().describe("Optional path to save screenshot"),
      format: z.enum(["png", "jpeg", "webp"]).optional().describe("Image format"),
      full_page: z.boolean().optional().default(false).describe("Capture the full page"),
      quality: z.number().optional().describe("Compression quality for jpeg/webp"),
    },
    async ({ devtools_session_id, file_path, format, full_page, quality }) => {
      try {
        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const args: Record<string, unknown> = {};
        if (file_path) args.filePath = file_path;
        if (format) args.format = format;
        if (full_page) args.fullPage = true;
        if (quality !== undefined) args.quality = quality;

        const devtoolsResult = await devToolsBridge.callAction(devtools_session_id, "screenshot", args);
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              devtoolsResult: sanitizeDevToolsPayload(devtoolsResult),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );
}
