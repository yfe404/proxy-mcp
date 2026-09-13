/**
 * Interceptor tools — MCP tools for auto-attaching to Browser, Docker, and processes.
 *
 * Organized into 4 groups:
 *   Discovery (3): list, status, deactivate_all
 *   Browser (3): launch, navigate, close
 *   Terminal (2): spawn, kill
 *   Docker (2): attach, detach
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import { interceptorManager } from "../interceptors/manager.js";
import type { TerminalInterceptor } from "../interceptors/terminal.js";
import { getPageForTarget } from "../browser/session.js";
import { truncateResult } from "../utils.js";

/** Robust error-to-string — handles Error, plain objects (e.g. DBus errors), and primitives. */
function errorToString(e: unknown): string {
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

function requireProxy(): { proxyPort: number; certPem: string; certFingerprint: string } {
  if (!proxyManager.isRunning()) {
    throw new Error("Proxy is not running. Start it first with proxy_start.");
  }
  const cert = proxyManager.getCert();
  if (!cert) {
    throw new Error("No certificate available. Start the proxy first.");
  }
  return {
    proxyPort: proxyManager.getPort()!,
    certPem: cert.cert,
    certFingerprint: cert.fingerprint,
  };
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

export function registerInterceptorTools(server: McpServer): void {
  // ──────────────────────────────────────────
  // Discovery (3 tools)
  // ──────────────────────────────────────────

  server.tool(
    "interceptor_list",
    "List all interceptors with their availability and active targets. Shows the Browser, Terminal and Docker interceptors.",
    {},
    async () => {
      try {
        const list = await interceptorManager.list();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              interceptors: list,
              totalActive: list.reduce((sum, i) => sum + i.activeTargets.length, 0),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_status",
    "Get detailed status of a specific interceptor, including all active targets and their details.",
    {
      interceptor_id: z.string().describe("Interceptor ID (e.g., 'browser', 'terminal', 'docker')"),
    },
    async ({ interceptor_id }) => {
      try {
        const interceptor = interceptorManager.get(interceptor_id);
        if (!interceptor) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Interceptor '${interceptor_id}' not found` }) }] };
        }
        const meta = await interceptor.getMetadata();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", ...meta }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_deactivate_all",
    "Kill ALL active interceptors across all types. Emergency cleanup — stops all browser instances, kills spawned processes, cleans Docker.",
    {},
    async () => {
      try {
        await interceptorManager.deactivateAll();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: "All interceptors deactivated." }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ──────────────────────────────────────────
  // Browser (3 tools)
  // ──────────────────────────────────────────

  server.tool(
    "interceptor_browser_launch",
    "Launch cloakbrowser (stealth Chromium) with proxy flags and SPKI certificate trust. Built-in source-level fingerprint patches + humanize mode. Driven via Playwright — locator-based tools replace CDP.",
    {
      url: z.string().optional().describe("URL to open (default: about:blank)"),
      headless: z.boolean().optional().default(false).describe("Run headless (default: false)"),
      humanize: z.boolean().optional().default(true).describe("Enable cloakbrowser's humanize mode (default: true)"),
      human_preset: z.enum(["default", "careful"]).optional().default("default")
        .describe("Human behavior preset"),
      timezone: z.string().optional().describe("IANA timezone, e.g. 'America/New_York'"),
      locale: z.string().optional().describe("BCP 47 locale, e.g. 'en-US'"),
      viewport_width: z.number().optional().describe("Viewport width in px"),
      viewport_height: z.number().optional().describe("Viewport height in px"),
    },
    async ({ url, headless, humanize, human_preset, timezone, locale, viewport_width, viewport_height }) => {
      try {
        const proxyInfo = requireProxy();
        const viewport = (viewport_width && viewport_height)
          ? { width: viewport_width, height: viewport_height }
          : undefined;

        const result = await interceptorManager.activate("browser", {
          ...proxyInfo,
          url,
          headless,
          humanize,
          humanPreset: human_preset,
          timezone,
          locale,
          viewport,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", ...result }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_browser_navigate",
    "Navigate the browser target's page via Playwright and optionally wait for matching host traffic to be captured by the proxy.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      url: z.string().describe("Destination URL"),
      wait_until: z.enum(["load", "domcontentloaded", "networkidle", "commit"]).optional().default("domcontentloaded")
        .describe("Playwright wait condition (default: domcontentloaded)"),
      wait_for_proxy_capture: z.boolean().optional().default(true)
        .describe("Wait for matching proxy traffic after navigate (default: true)"),
      timeout_ms: z.number().optional().default(5000).describe("Max wait for navigation and proxy capture (default: 5000ms)"),
      poll_interval_ms: z.number().optional().default(200).describe("Polling interval while waiting for proxy capture (default: 200ms)"),
    },
    async ({ target_id, url, wait_until, wait_for_proxy_capture, timeout_ms, poll_interval_ms }) => {
      try {
        const page = await getPageForTarget(target_id);
        const beforeCount = proxyManager.getTraffic().length;

        const response = await page.goto(url, {
          waitUntil: wait_until,
          timeout: timeout_ms,
        });

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
        const payload: Record<string, unknown> = {
          status: "success",
          target_id,
          url,
          http_status: response?.status() ?? null,
          final_url: page.url(),
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
          payload.warning = sawAnyNewTraffic
            ? `Navigation succeeded but no '${destinationHost}' traffic was captured within ${timeout_ms}ms.`
            : `No new proxy traffic observed within ${timeout_ms}ms after navigation.`;
        }

        return { content: [{ type: "text", text: truncateResult(payload) }] };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_browser_close",
    "Close a browser instance launched by interceptor_browser_launch.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
    },
    async ({ target_id }) => {
      try {
        await interceptorManager.deactivate("browser", target_id);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: `Browser instance ${target_id} closed.` }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ──────────────────────────────────────────
  // Terminal / Process (2 tools)
  // ──────────────────────────────────────────

  server.tool(
    "interceptor_spawn",
    "Spawn a command with proxy env vars pre-configured (HTTP_PROXY, HTTPS_PROXY, SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE, and 15+ more). Traffic automatically routes through the MITM proxy.",
    {
      command: z.string().describe("Command to run (e.g., 'curl', 'node', 'python')"),
      args: z.array(z.string()).optional().default([]).describe("Command arguments"),
      cwd: z.string().optional().describe("Working directory (default: current)"),
      env: z.record(z.string()).optional().describe("Additional env vars to set"),
    },
    async ({ command, args, cwd, env }) => {
      try {
        const proxyInfo = requireProxy();
        const result = await interceptorManager.activate("terminal", {
          ...proxyInfo,
          command,
          args,
          cwd,
          env,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", ...result }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_kill",
    "Kill a spawned process by target ID. Also retrieves final stdout/stderr output.",
    {
      target_id: z.string().describe("Target ID from interceptor_spawn"),
    },
    async ({ target_id }) => {
      try {
        const terminal = interceptorManager.get("terminal") as TerminalInterceptor | undefined;
        const output = terminal?.getProcessOutput(target_id);

        await interceptorManager.deactivate("terminal", target_id);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              message: `Process ${target_id} killed.`,
              output: output ? {
                stdout: output.stdout.slice(-2048),
                stderr: output.stderr.slice(-2048),
                exitCode: output.exitCode,
              } : null,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ──────────────────────────────────────────
  // Docker (2 tools)
  // ──────────────────────────────────────────

  server.tool(
    "interceptor_docker_attach",
    "Inject proxy env vars and CA certificate into a Docker container. Two modes: 'exec' (inject into running container) or 'restart' (stop + restart with proxy config).",
    {
      container_id: z.string().describe("Docker container ID or name"),
      mode: z.enum(["exec", "restart"]).optional().default("exec")
        .describe("Injection mode: 'exec' (live injection) or 'restart' (stop + restart)"),
    },
    async ({ container_id, mode }) => {
      try {
        const proxyInfo = requireProxy();
        const result = await interceptorManager.activate("docker", {
          ...proxyInfo,
          containerId: container_id,
          mode,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", ...result }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_docker_detach",
    "Remove proxy configuration from a Docker container and clean up injected files.",
    {
      target_id: z.string().describe("Target ID from interceptor_docker_attach"),
    },
    async ({ target_id }) => {
      try {
        await interceptorManager.deactivate("docker", target_id);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: `Docker container ${target_id} detached.` }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );
}
