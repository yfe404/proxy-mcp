/**
 * DevTools bridge tools — proxy-safe wrappers around chrome-devtools-mcp sidecar.
 *
 * These tools enforce binding to a specific Chrome interceptor target_id so
 * CDP actions and proxy capture always refer to the same browser instance.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { interceptorManager } from "../interceptors/manager.js";
import { getCdpBaseUrl, getCdpTargets, sendCdpCommand } from "../cdp-utils.js";
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

const DEFAULT_VALUE_MAX_CHARS = 256;
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const HARD_VALUE_CAP_CHARS = 20000;

function normalizeLimit(limit: number | undefined): number {
  const n = limit ?? DEFAULT_LIST_LIMIT;
  if (!Number.isFinite(n)) return DEFAULT_LIST_LIMIT;
  return Math.max(1, Math.min(MAX_LIST_LIMIT, Math.trunc(n)));
}

function normalizeOffset(offset: number | undefined): number {
  const n = offset ?? 0;
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.trunc(n));
}

function toBase64UrlUtf8(s: string): string {
  return Buffer.from(s, "utf8")
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function fromBase64UrlUtf8(s: string): string {
  let b64 = s.replaceAll("-", "+").replaceAll("_", "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return Buffer.from(b64, "base64").toString("utf8");
}

function capValue(value: string, maxChars: number): { value: string; valueLength: number; truncated: boolean; maxChars: number } {
  const valueLength = value.length;
  const effectiveMax = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(maxChars)));
  if (effectiveMax === 0) {
    return { value, valueLength, truncated: false, maxChars: 0 };
  }
  if (valueLength <= effectiveMax) {
    return { value, valueLength, truncated: false, maxChars: effectiveMax };
  }
  return { value: value.slice(0, effectiveMax) + "...", valueLength, truncated: true, maxChars: effectiveMax };
}

function cookieStableId(cookie: Record<string, unknown>): string {
  const parts = [
    typeof cookie.name === "string" ? cookie.name : "",
    typeof cookie.domain === "string" ? cookie.domain : "",
    typeof cookie.path === "string" ? cookie.path : "",
    String(!!cookie.secure),
    String(!!cookie.httpOnly),
    typeof cookie.sameSite === "string" ? cookie.sameSite : "",
    typeof cookie.partitionKey === "string" ? cookie.partitionKey : "",
  ];
  const hash = createHash("sha1").update(parts.join("|"), "utf8").digest("hex");
  return `ck_${hash}`;
}

function targetUrlIsUserPage(url: unknown): boolean {
  if (typeof url !== "string") return false;
  const tUrl = url.toLowerCase();
  return tUrl.length > 0 && !tUrl.startsWith("devtools://") && !tUrl.startsWith("chrome://");
}

function pickCdpPageTarget(targets: Array<Record<string, unknown>>): { url: string; wsUrl: string } {
  const pages = targets.filter((t) => t.type === "page");
  if (pages.length === 0) {
    throw new Error("No page targets available for this Chrome instance.");
  }
  const selected = pages.find((t) => targetUrlIsUserPage(t.url)) ?? pages[0];
  const url = typeof selected.url === "string" ? selected.url : "";
  const wsUrl = typeof selected.webSocketDebuggerUrl === "string" ? selected.webSocketDebuggerUrl : "";
  if (!wsUrl) {
    throw new Error("Selected page target has no webSocketDebuggerUrl.");
  }
  return { url, wsUrl };
}

function getOriginFromUrl(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin;
  } catch {
    return null;
  }
}

async function getCdpPageEndpoint(targetId: string): Promise<{ pageUrl: string; wsUrl: string; port: number }> {
  const port = await getChromeTargetPort(targetId);
  const targets = await getCdpTargets(port, { timeoutMs: 2000 });
  const { url: pageUrl, wsUrl } = pickCdpPageTarget(targets);
  return { pageUrl, wsUrl, port };
}

async function cdpGetCookies(wsUrl: string, pageUrl?: string): Promise<Array<Record<string, unknown>>> {
  const attempts: Array<{ method: string; params?: Record<string, unknown> }> = [
    { method: "Storage.getCookies" },
    { method: "Network.getAllCookies" },
  ];
  if (pageUrl) {
    attempts.push({ method: "Network.getCookies", params: { urls: [pageUrl] } });
  }

  let lastErr: unknown = null;
  for (const attempt of attempts) {
    try {
      const result = await sendCdpCommand(wsUrl, attempt.method, attempt.params);
      const cookies = (result as Record<string, unknown>).cookies;
      if (Array.isArray(cookies)) {
        return cookies.filter((c): c is Record<string, unknown> => !!c && typeof c === "object");
      }
      lastErr = new Error(`CDP ${attempt.method} returned no cookies array.`);
    } catch (e) {
      lastErr = e;
    }
  }

  throw new Error(`Unable to fetch cookies via CDP.${lastErr ? ` Last error: ${errorToString(lastErr)}` : ""}`);
}

async function cdpEvaluateValue<T = unknown>(
  wsUrl: string,
  expression: string,
): Promise<T> {
  const result = await sendCdpCommand(wsUrl, "Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });

  const err = (result as Record<string, unknown>).exceptionDetails;
  if (err) {
    throw new Error(`Runtime.evaluate failed: ${JSON.stringify(err)}`);
  }

  const remote = (result as Record<string, unknown>).result as Record<string, unknown> | undefined;
  return (remote?.value as T);
}

interface InlineImagePayload {
  data: string;
  mimeType?: string;
}

function findInlineImagePayload(payload: unknown): InlineImagePayload | null {
  const stack: unknown[] = [payload];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || current === undefined) continue;

    if (Array.isArray(current)) {
      for (const item of current) stack.push(item);
      continue;
    }
    if (typeof current !== "object") continue;

    const obj = current as Record<string, unknown>;
    if (obj.type === "image" && typeof obj.data === "string" && obj.data.length > 0) {
      return {
        data: obj.data,
        ...(typeof obj.mimeType === "string" ? { mimeType: obj.mimeType } : {}),
      };
    }
    for (const value of Object.values(obj)) {
      stack.push(value);
    }
  }
  return null;
}

async function persistScreenshotIfRequested(
  devtoolsResult: unknown,
  filePath?: string,
): Promise<Record<string, unknown>> {
  if (!filePath) return {};

  try {
    if (existsSync(filePath)) {
      return {
        screenshot: {
          requestedFilePath: filePath,
          saved: true,
          savedBy: "sidecar",
        },
      };
    }

    const inline = findInlineImagePayload(devtoolsResult);
    if (!inline) {
      return {
        screenshot: {
          requestedFilePath: filePath,
          saved: false,
          warning: "No inline image payload was returned by DevTools sidecar.",
        },
      };
    }

    const bytes = Buffer.from(inline.data, "base64");
    if (bytes.length === 0 && inline.data.length > 0) {
      return {
        screenshot: {
          requestedFilePath: filePath,
          saved: false,
          error: "Inline image payload could not be decoded from base64.",
        },
      };
    }

    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, bytes);

    return {
      screenshot: {
        requestedFilePath: filePath,
        saved: true,
        savedBy: "proxy-wrapper",
        bytesWritten: bytes.length,
        ...(inline.mimeType ? { mimeType: inline.mimeType } : {}),
      },
    };
  } catch (e) {
    return {
      screenshot: {
        requestedFilePath: filePath,
        saved: false,
        error: errorToString(e),
      },
    };
  }
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
                      "navigation works; cookie/storage list/get tools still work via direct CDP; " +
                      "snapshot/network/console/screenshot require installing chrome-devtools-mcp.",
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
        const screenshot = await persistScreenshotIfRequested(devtoolsResult, file_path);
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              devtoolsResult: sanitizeDevToolsPayload(devtoolsResult),
              ...screenshot,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_list_cookies",
    "List browser cookies for the bound Chrome session with pagination and truncated values by default.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      url_filter: z.string().optional().describe("Filter cookies by domain/path substring"),
      domain_filter: z.string().optional().describe("Filter cookies by domain substring"),
      name_filter: z.string().optional().describe("Filter cookies by name substring"),
      offset: z.number().optional().default(0).describe("Offset into results (default: 0)"),
      limit: z.number().optional().default(DEFAULT_LIST_LIMIT).describe("Max cookies to return (default: 50, max: 500)"),
      value_max_chars: z.number().optional().default(DEFAULT_VALUE_MAX_CHARS)
        .describe("Max characters for cookie value previews (default: 256)"),
      sort: z.enum(["name", "domain", "expires"]).optional().default("name").describe("Sort order (default: name)"),
    },
    async ({ devtools_session_id, url_filter, domain_filter, name_filter, offset, limit, value_max_chars, sort }) => {
      try {
        const session = devToolsBridge.getSession(devtools_session_id);
        if (!session) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `DevTools session '${devtools_session_id}' not found.` }) }] };
        }

        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const { pageUrl, wsUrl } = await getCdpPageEndpoint(targetId);
        const cookies = await cdpGetCookies(wsUrl, pageUrl);

        const urlNeedle = url_filter?.toLowerCase();
        const domainNeedle = domain_filter?.toLowerCase();
        const nameNeedle = name_filter?.toLowerCase();

        const filtered = cookies.filter((c) => {
          const name = typeof c.name === "string" ? c.name : "";
          const domain = typeof c.domain === "string" ? c.domain : "";
          const path = typeof c.path === "string" ? c.path : "";
          if (urlNeedle && !`${domain}${path}`.toLowerCase().includes(urlNeedle)) return false;
          if (domainNeedle && !domain.toLowerCase().includes(domainNeedle)) return false;
          if (nameNeedle && !name.toLowerCase().includes(nameNeedle)) return false;
          return true;
        });

        const sorted = filtered.sort((a, b) => {
          const aName = typeof a.name === "string" ? a.name : "";
          const bName = typeof b.name === "string" ? b.name : "";
          const aDomain = typeof a.domain === "string" ? a.domain : "";
          const bDomain = typeof b.domain === "string" ? b.domain : "";
          const aExpires = typeof a.expires === "number" ? a.expires : 0;
          const bExpires = typeof b.expires === "number" ? b.expires : 0;

          switch (sort) {
            case "domain": return aDomain.localeCompare(bDomain) || aName.localeCompare(bName);
            case "expires": return aExpires - bExpires || aDomain.localeCompare(bDomain) || aName.localeCompare(bName);
            case "name":
            default: return aName.localeCompare(bName) || aDomain.localeCompare(bDomain);
          }
        });

        const total = sorted.length;
        const o = normalizeOffset(offset);
        const l = normalizeLimit(limit);
        const page = sorted.slice(o, o + l);

        const valueCap = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? DEFAULT_VALUE_MAX_CHARS)));

        const summaries = page.map((c) => {
          const name = typeof c.name === "string" ? c.name : "";
          const domain = typeof c.domain === "string" ? c.domain : "";
          const path = typeof c.path === "string" ? c.path : "";
          const value = typeof c.value === "string" ? c.value : "";
          const capped = capValue(value, valueCap);
          return {
            cookie_id: cookieStableId(c),
            name,
            domain,
            path,
            expires: typeof c.expires === "number" ? c.expires : null,
            httpOnly: typeof c.httpOnly === "boolean" ? c.httpOnly : null,
            secure: typeof c.secure === "boolean" ? c.secure : null,
            sameSite: typeof c.sameSite === "string" ? c.sameSite : null,
            value_preview: capped.value,
            value_length: capped.valueLength,
            value_truncated: capped.truncated,
          };
        });

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              total,
              offset: o,
              limit: l,
              showing: summaries.length,
              cookies: summaries,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_get_cookie",
    "Get one cookie by cookie_id with full value (subject to a hard cap to keep output bounded).",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      cookie_id: z.string().describe("cookie_id from interceptor_chrome_devtools_list_cookies"),
      value_max_chars: z.number().optional().default(HARD_VALUE_CAP_CHARS)
        .describe(`Max characters for cookie value (default: ${HARD_VALUE_CAP_CHARS})`),
    },
    async ({ devtools_session_id, cookie_id, value_max_chars }) => {
      try {
        const session = devToolsBridge.getSession(devtools_session_id);
        if (!session) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `DevTools session '${devtools_session_id}' not found.` }) }] };
        }

        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const { pageUrl, wsUrl } = await getCdpPageEndpoint(targetId);
        const cookies = await cdpGetCookies(wsUrl, pageUrl);

        const found = cookies.find((c) => cookieStableId(c) === cookie_id) ?? null;
        if (!found) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({ status: "error", error: `Cookie '${cookie_id}' not found. Re-run list tool.` }),
            }],
          };
        }

        const value = typeof found.value === "string" ? found.value : "";
        const capped = capValue(value, Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? HARD_VALUE_CAP_CHARS))));

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              cookie_id,
              cookie: {
                ...found,
                value: capped.value,
              },
              value_length: capped.valueLength,
              value_truncated: capped.truncated,
              value_max_chars: capped.maxChars,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_list_storage_keys",
    "List localStorage/sessionStorage keys for the current origin with pagination and truncated value previews.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      storage_type: z.enum(["local", "session"]).describe("Storage type"),
      origin: z.string().optional().describe("Optional origin override (must match current page origin)"),
      key_filter: z.string().optional().describe("Filter by key substring"),
      offset: z.number().optional().default(0).describe("Offset into results (default: 0)"),
      limit: z.number().optional().default(DEFAULT_LIST_LIMIT).describe("Max items to return (default: 50, max: 500)"),
      value_max_chars: z.number().optional().default(DEFAULT_VALUE_MAX_CHARS)
        .describe("Max characters for storage value previews (default: 256)"),
    },
    async ({ devtools_session_id, storage_type, origin, key_filter, offset, limit, value_max_chars }) => {
      try {
        const session = devToolsBridge.getSession(devtools_session_id);
        if (!session) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `DevTools session '${devtools_session_id}' not found.` }) }] };
        }

        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const { pageUrl, wsUrl } = await getCdpPageEndpoint(targetId);

        const currentOrigin = getOriginFromUrl(pageUrl);
        if (!currentOrigin) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `No http(s) origin available for current page URL: '${pageUrl}'` }) }] };
        }
        if (origin && origin !== currentOrigin) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({ status: "error", error: `origin '${origin}' does not match current origin '${currentOrigin}'. Navigate first.` }),
            }],
          };
        }

        const previewLen = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? DEFAULT_VALUE_MAX_CHARS)));
        const keyNeedle = (key_filter ?? "").toLowerCase();
        const stType = storage_type;

        const expr = `(() => {
  try {
    const storageType = ${JSON.stringify(stType)};
    const keyFilter = ${JSON.stringify(keyNeedle)};
    const maxChars = ${previewLen};
    const storage = storageType === "local" ? localStorage : sessionStorage;
    const out = [];
    for (let i = 0; i < storage.length; i++) {
      const k = storage.key(i);
      if (typeof k !== "string") continue;
      if (keyFilter && !k.toLowerCase().includes(keyFilter)) continue;
      const raw = storage.getItem(k);
      const v = typeof raw === "string" ? raw : "";
      out.push({ key: k, valuePreview: maxChars > 0 ? v.slice(0, maxChars) : "", valueLength: v.length });
    }
    out.sort((a, b) => a.key.localeCompare(b.key));
    return out;
  } catch (e) {
    return { error: String(e && e.message ? e.message : e) };
  }
})()`;

        const result = await cdpEvaluateValue(wsUrl, expr) as unknown;
        if (result && typeof result === "object" && !Array.isArray(result) && "error" in (result as Record<string, unknown>)) {
          const err = (result as Record<string, unknown>).error;
          throw new Error(`Storage evaluation error: ${typeof err === "string" ? err : JSON.stringify(err)}`);
        }
        if (!Array.isArray(result)) {
          throw new Error("Unexpected storage evaluation result.");
        }

        const items = result
          .filter((x): x is Record<string, unknown> => !!x && typeof x === "object")
          .map((x) => ({
            key: typeof x.key === "string" ? x.key : "",
            valuePreview: typeof x.valuePreview === "string" ? x.valuePreview : "",
            valueLength: typeof x.valueLength === "number" ? x.valueLength : 0,
          }))
          .filter((x) => x.key.length > 0);

        const total = items.length;
        const o = normalizeOffset(offset);
        const l = normalizeLimit(limit);
        const page = items.slice(o, o + l);

        const summaries = page.map((x) => ({
          item_id: `st.${stType}.${toBase64UrlUtf8(currentOrigin)}.${toBase64UrlUtf8(x.key)}`,
          key: x.key,
          value_preview: x.valuePreview,
          value_length: x.valueLength,
          value_truncated: previewLen > 0 ? x.valueLength > previewLen : (x.valueLength > 0),
        }));

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              origin: currentOrigin,
              storage_type: stType,
              total,
              offset: o,
              limit: l,
              showing: summaries.length,
              items: summaries,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_get_storage_value",
    "Get one localStorage/sessionStorage value by item_id.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      storage_type: z.enum(["local", "session"]).describe("Storage type"),
      item_id: z.string().describe("item_id from interceptor_chrome_devtools_list_storage_keys"),
      origin: z.string().optional().describe("Optional origin override (must match current page origin)"),
      value_max_chars: z.number().optional().default(HARD_VALUE_CAP_CHARS)
        .describe(`Max characters for returned value (default: ${HARD_VALUE_CAP_CHARS})`),
    },
    async ({ devtools_session_id, storage_type, item_id, origin, value_max_chars }) => {
      try {
        const session = devToolsBridge.getSession(devtools_session_id);
        if (!session) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `DevTools session '${devtools_session_id}' not found.` }) }] };
        }

        const parts = item_id.split(".");
        if (parts.length !== 4 || parts[0] !== "st") {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Invalid item_id '${item_id}'` }) }] };
        }
        const itemType = parts[1];
        const itemOrigin = fromBase64UrlUtf8(parts[2]);
        const itemKey = fromBase64UrlUtf8(parts[3]);
        if (itemType !== storage_type) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `item_id storage_type '${itemType}' does not match requested '${storage_type}'` }) }] };
        }

        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);
        const { pageUrl, wsUrl } = await getCdpPageEndpoint(targetId);

        const currentOrigin = getOriginFromUrl(pageUrl);
        if (!currentOrigin) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `No http(s) origin available for current page URL: '${pageUrl}'` }) }] };
        }
        if (origin && origin !== currentOrigin) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({ status: "error", error: `origin '${origin}' does not match current origin '${currentOrigin}'. Navigate first.` }),
            }],
          };
        }
        if (itemOrigin !== currentOrigin) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({ status: "error", error: `item_id origin '${itemOrigin}' does not match current origin '${currentOrigin}'. Navigate first.` }),
            }],
          };
        }

        const maxChars = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? HARD_VALUE_CAP_CHARS)));
        const stType = storage_type;

        const expr = `(() => {
  try {
    const storageType = ${JSON.stringify(stType)};
    const key = ${JSON.stringify(itemKey)};
    const maxChars = ${maxChars};
    const storage = storageType === "local" ? localStorage : sessionStorage;
    const raw = storage.getItem(key);
    const v = typeof raw === "string" ? raw : "";
    const valueLength = v.length;
    const truncated = maxChars > 0 && valueLength > maxChars;
    const value = maxChars > 0 ? (truncated ? v.slice(0, maxChars) : v) : v;
    return { key, value, valueLength, truncated };
  } catch (e) {
    return { error: String(e && e.message ? e.message : e) };
  }
})()`;

        const result = await cdpEvaluateValue(wsUrl, expr) as unknown;
        if (!result || typeof result !== "object") {
          throw new Error("Unexpected storage evaluation result.");
        }
        const obj = result as Record<string, unknown>;
        if (obj.error) {
          throw new Error(`Storage evaluation error: ${typeof obj.error === "string" ? obj.error : JSON.stringify(obj.error)}`);
        }

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              origin: currentOrigin,
              storage_type: stType,
              item_id,
              key: obj.key ?? itemKey,
              value: typeof obj.value === "string" ? obj.value : "",
              value_length: typeof obj.valueLength === "number" ? obj.valueLength : null,
              value_truncated: typeof obj.truncated === "boolean" ? obj.truncated : null,
              value_max_chars: maxChars,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_list_network_fields",
    "List request/response header fields from proxy-captured traffic since the DevTools session was created, with pagination and truncation.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      direction: z.enum(["request", "response", "both"]).optional().default("both").describe("Header direction (default: both)"),
      header_name_filter: z.string().optional().describe("Filter by header name substring"),
      method_filter: z.string().optional().describe("Filter by HTTP method"),
      url_filter: z.string().optional().describe("Filter by URL substring"),
      status_filter: z.number().optional().describe("Filter by response status code"),
      hostname_filter: z.string().optional().describe("Filter by hostname substring"),
      offset: z.number().optional().default(0).describe("Offset into results (default: 0)"),
      limit: z.number().optional().default(DEFAULT_LIST_LIMIT).describe("Max fields to return (default: 50, max: 500)"),
      value_max_chars: z.number().optional().default(DEFAULT_VALUE_MAX_CHARS)
        .describe("Max characters for header value previews (default: 256)"),
    },
    async ({ devtools_session_id, direction, header_name_filter, method_filter, url_filter, status_filter, hostname_filter, offset, limit, value_max_chars }) => {
      try {
        const session = devToolsBridge.getSession(devtools_session_id);
        if (!session) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `DevTools session '${devtools_session_id}' not found.` }) }] };
        }
        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);

        const since = session.createdAt;
        let traffic = proxyManager.getTraffic().filter((t) => t.timestamp >= since);

        if (method_filter) {
          const m = method_filter.toUpperCase();
          traffic = traffic.filter((t) => t.request.method === m);
        }
        if (url_filter) {
          const u = url_filter.toLowerCase();
          traffic = traffic.filter((t) => t.request.url.toLowerCase().includes(u));
        }
        if (status_filter !== undefined) {
          traffic = traffic.filter((t) => t.response?.statusCode === status_filter);
        }
        if (hostname_filter) {
          const h = hostname_filter.toLowerCase();
          traffic = traffic.filter((t) => t.request.hostname.toLowerCase().includes(h));
        }

        const nameNeedle = header_name_filter?.toLowerCase();
        const valueCap = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? DEFAULT_VALUE_MAX_CHARS)));

        const rows: Array<Record<string, unknown>> = [];
        const wantReq = direction === "request" || direction === "both";
        const wantRes = direction === "response" || direction === "both";

        for (const ex of traffic) {
          if (wantReq) {
            for (const [k, v] of Object.entries(ex.request.headers)) {
              if (nameNeedle && !k.toLowerCase().includes(nameNeedle)) continue;
              const capped = capValue(v, valueCap);
              rows.push({
                field_id: `nf.${ex.id}.request.${toBase64UrlUtf8(k.toLowerCase())}`,
                exchange_id: ex.id,
                direction: "request",
                header_name: k,
                value_preview: capped.value,
                value_length: capped.valueLength,
                value_truncated: capped.truncated,
                method: ex.request.method,
                url: ex.request.url,
                hostname: ex.request.hostname,
                status: ex.response?.statusCode ?? null,
                timestamp: ex.timestamp,
              });
            }
          }
          if (wantRes && ex.response) {
            for (const [k, v] of Object.entries(ex.response.headers)) {
              if (nameNeedle && !k.toLowerCase().includes(nameNeedle)) continue;
              const capped = capValue(v, valueCap);
              rows.push({
                field_id: `nf.${ex.id}.response.${toBase64UrlUtf8(k.toLowerCase())}`,
                exchange_id: ex.id,
                direction: "response",
                header_name: k,
                value_preview: capped.value,
                value_length: capped.valueLength,
                value_truncated: capped.truncated,
                method: ex.request.method,
                url: ex.request.url,
                hostname: ex.request.hostname,
                status: ex.response.statusCode,
                timestamp: ex.timestamp,
              });
            }
          }
        }

        const total = rows.length;
        const o = normalizeOffset(offset);
        const l = normalizeLimit(limit);
        const page = rows.slice(o, o + l);

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              since_ts: since,
              total,
              offset: o,
              limit: l,
              showing: page.length,
              fields: page,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_chrome_devtools_get_network_field",
    "Get one full header field value from proxy-captured traffic by field_id.",
    {
      devtools_session_id: z.string().describe("Session ID from interceptor_chrome_devtools_attach"),
      field_id: z.string().describe("field_id from interceptor_chrome_devtools_list_network_fields"),
      value_max_chars: z.number().optional().default(HARD_VALUE_CAP_CHARS)
        .describe(`Max characters for returned value (default: ${HARD_VALUE_CAP_CHARS})`),
    },
    async ({ devtools_session_id, field_id, value_max_chars }) => {
      try {
        const session = devToolsBridge.getSession(devtools_session_id);
        if (!session) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `DevTools session '${devtools_session_id}' not found.` }) }] };
        }
        const { targetId } = await ensureSessionTargetIsAlive(devtools_session_id);

        const parts = field_id.split(".");
        if (parts.length !== 4 || parts[0] !== "nf") {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Invalid field_id '${field_id}'` }) }] };
        }
        const exchangeId = parts[1];
        const dir = parts[2];
        const headerName = fromBase64UrlUtf8(parts[3]);

        const exchange = proxyManager.getExchange(exchangeId);
        if (!exchange) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Exchange '${exchangeId}' not found in capture buffer.` }) }] };
        }
        if (exchange.timestamp < session.createdAt) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "field_id refers to an exchange older than this DevTools session." }) }] };
        }

        let value: string | null = null;
        if (dir === "request") {
          value = exchange.request.headers[headerName.toLowerCase()] ?? null;
        } else if (dir === "response") {
          value = exchange.response?.headers?.[headerName.toLowerCase()] ?? null;
        } else {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Invalid field direction '${dir}'` }) }] };
        }

        if (value === null) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Header '${headerName}' not found on ${dir}.` }) }] };
        }

        const capped = capValue(value, Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? HARD_VALUE_CAP_CHARS))));

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              devtools_session_id,
              target_id: targetId,
              field_id,
              exchange_id: exchangeId,
              direction: dir,
              header_name: headerName,
              value: capped.value,
              value_length: capped.valueLength,
              value_truncated: capped.truncated,
              value_max_chars: capped.maxChars,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );
}
