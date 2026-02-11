import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createRequire } from "node:module";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { getCdpTargets, sendCdpCommand } from "../cdp-utils.js";
import { resolveToolMap } from "./tool-map.js";
import type { DevToolsAction, DevToolsResolvedToolMap, DevToolsSessionSnapshot } from "./types.js";

interface DevToolsSessionInternal extends DevToolsSessionSnapshot {
  transport: StdioClientTransport | null;
  client: Client | null;
  stderrTail: string[];
}

const SESSION_ID_PREFIX = "devtools";
const STDERR_TAIL_LINES = 30;

let resolvedSidecarBinPath: string | null = null;

function errorToString(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

function pushStderrTail(lines: string[], chunk: unknown): void {
  const text = typeof chunk === "string" ? chunk : String(chunk);
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    lines.push(line);
  }
  if (lines.length > STDERR_TAIL_LINES) {
    lines.splice(0, lines.length - STDERR_TAIL_LINES);
  }
}

function resolveChromeDevtoolsMcpBin(): string {
  if (resolvedSidecarBinPath) return resolvedSidecarBinPath;

  const require = createRequire(import.meta.url);
  const pkgPath = require.resolve("chrome-devtools-mcp/package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
    bin?: string | Record<string, unknown>;
  };

  let relBinPath: string | null = null;
  if (typeof pkg.bin === "string") {
    relBinPath = pkg.bin;
  } else if (pkg.bin && typeof pkg.bin === "object") {
    const direct = pkg.bin["chrome-devtools-mcp"];
    if (typeof direct === "string") {
      relBinPath = direct;
    } else {
      const firstString = Object.values(pkg.bin).find((v): v is string => typeof v === "string");
      relBinPath = firstString ?? null;
    }
  }

  if (!relBinPath) {
    throw new Error("Unable to resolve chrome-devtools-mcp binary from package metadata.");
  }

  resolvedSidecarBinPath = resolve(dirname(pkgPath), relBinPath);
  return resolvedSidecarBinPath;
}

export function resetSidecarResolutionCache(): void {
  resolvedSidecarBinPath = null;
}

export function getLocalSidecarStatus(): { available: boolean; binPath: string | null; error: string | null } {
  try {
    const binPath = resolveChromeDevtoolsMcpBin();
    return { available: true, binPath, error: null };
  } catch (e) {
    return { available: false, binPath: null, error: errorToString(e) };
  }
}

function resolveSidecarLaunch(browserUrl: string): {
  command: string;
  args: string[];
  mode: "local-package" | "path-command";
} {
  try {
    const binPath = resolveChromeDevtoolsMcpBin();
    return {
      command: process.execPath,
      args: [binPath, "--browserUrl", browserUrl],
      mode: "local-package",
    };
  } catch {
    // Fallback for environments where dependency install is not available yet.
    return {
      command: "chrome-devtools-mcp",
      args: ["--browserUrl", browserUrl],
      mode: "path-command",
    };
  }
}

function toPublicSession(session: DevToolsSessionInternal): DevToolsSessionSnapshot {
  return {
    id: session.id,
    targetId: session.targetId,
    browserUrl: session.browserUrl,
    mode: session.mode,
    createdAt: session.createdAt,
    lastUsedAt: session.lastUsedAt,
    sidecarPid: session.sidecarPid,
    tools: session.tools,
  };
}

function getPortFromBrowserUrl(browserUrl: string): number {
  let u: URL;
  try {
    u = new URL(browserUrl);
  } catch {
    throw new Error(`Invalid browser URL '${browserUrl}'`);
  }
  const port = Number(u.port);
  if (!Number.isFinite(port) || port <= 0) {
    throw new Error(`Browser URL '${browserUrl}' does not contain a valid port`);
  }
  return port;
}

async function navigateWithNativeFallback(browserUrl: string, args: Record<string, unknown>): Promise<unknown> {
  const url = typeof args.url === "string" ? args.url : null;
  if (!url) {
    throw new Error("Missing 'url' for native-fallback navigate action.");
  }

  const port = getPortFromBrowserUrl(browserUrl);
  const targets = await getCdpTargets(port, { timeoutMs: 2000 });
  const pageTargets = targets.filter((t) => t.type === "page");
  if (pageTargets.length === 0) {
    throw new Error("No page targets available for native-fallback navigation.");
  }

  const selected = pageTargets.find((t) => {
    const tUrl = typeof t.url === "string" ? t.url.toLowerCase() : "";
    return tUrl.length > 0 && !tUrl.startsWith("devtools://") && !tUrl.startsWith("chrome://");
  }) ?? pageTargets[0];

  const ws = selected.webSocketDebuggerUrl;
  if (typeof ws !== "string" || ws.length === 0) {
    throw new Error("Selected page target has no webSocketDebuggerUrl for native-fallback navigation.");
  }

  const cdpResult = await sendCdpCommand(
    ws,
    "Page.navigate",
    { url },
    { timeoutMs: 5000 },
  );

  return {
    mode: "native-fallback",
    selected_page_target_id: selected.id ?? null,
    selected_page_url: selected.url ?? null,
    cdpResult,
  };
}

export class DevToolsBridge {
  private sessions = new Map<string, DevToolsSessionInternal>();

  async createSession(targetId: string, browserUrl: string): Promise<DevToolsSessionSnapshot> {
    const sessionId = `${SESSION_ID_PREFIX}_${randomUUID()}`;
    const stderrTail: string[] = [];
    const launch = resolveSidecarLaunch(browserUrl);

    const transport = new StdioClientTransport({
      command: launch.command,
      args: launch.args,
      stderr: "pipe",
      cwd: process.cwd(),
    });

    const stderr = transport.stderr as NodeJS.ReadableStream | null;
    if (stderr && typeof stderr.on === "function") {
      stderr.on("data", (chunk: unknown) => pushStderrTail(stderrTail, chunk));
    }

    const client = new Client({
      name: "proxy-devtools-bridge-client",
      version: "1.0.0",
    });

    try {
      await client.connect(transport);
      const listed = await client.listTools();
      const availableNames = listed.tools.map((t) => t.name);
      const tools: DevToolsResolvedToolMap = resolveToolMap(availableNames);

      const session: DevToolsSessionInternal = {
        id: sessionId,
        targetId,
        browserUrl,
        mode: "sidecar",
        createdAt: Date.now(),
        lastUsedAt: Date.now(),
        sidecarPid: transport.pid,
        tools,
        client,
        transport,
        stderrTail,
      };

      this.sessions.set(sessionId, session);
      transport.onclose = () => {
        this.sessions.delete(sessionId);
      };

      return toPublicSession(session);
    } catch (e) {
      await client.close().catch(() => {});
      await transport.close().catch(() => {});

      const errText = errorToString(e);
      if (/ENOENT/.test(errText)) {
        const fallbackSession: DevToolsSessionInternal = {
          id: sessionId,
          targetId,
          browserUrl,
          mode: "native-fallback",
          createdAt: Date.now(),
          lastUsedAt: Date.now(),
          sidecarPid: null,
          tools: null,
          client: null,
          transport: null,
          stderrTail,
        };
        this.sessions.set(sessionId, fallbackSession);
        return toPublicSession(fallbackSession);
      }

      const tail = stderrTail.length > 0 ? ` stderr: ${stderrTail.join(" | ")}` : "";
      throw new Error(`Failed to start chrome-devtools-mcp sidecar (${launch.mode}): ${errText}.${tail}`);
    }
  }

  getSession(sessionId: string): DevToolsSessionSnapshot | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    return toPublicSession(session);
  }

  listSessions(): DevToolsSessionSnapshot[] {
    return [...this.sessions.values()]
      .map(toPublicSession)
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  async callAction(
    sessionId: string,
    action: DevToolsAction,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`DevTools session '${sessionId}' not found.`);
    }

    session.lastUsedAt = Date.now();

    if (session.mode === "native-fallback") {
      if (action !== "navigate") {
        throw new Error(
          "This DevTools session is in native-fallback mode (chrome-devtools-mcp binary not found). " +
          "Only navigation is available. Install chrome-devtools-mcp and re-attach for full DevTools actions.",
        );
      }
      return await navigateWithNativeFallback(session.browserUrl, args);
    }

    if (!session.client || !session.tools) {
      throw new Error("DevTools sidecar session is not available.");
    }

    const toolName = session.tools[action];
    return await session.client.callTool({
      name: toolName,
      arguments: args,
    });
  }

  async closeSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    this.sessions.delete(sessionId);
    if (session.client) {
      await session.client.close().catch(() => {});
    }
    if (session.transport) {
      await session.transport.close().catch(() => {});
    }
    return true;
  }

  async closeSessionsByTarget(targetId: string): Promise<number> {
    const ids = [...this.sessions.values()]
      .filter((s) => s.targetId === targetId)
      .map((s) => s.id);
    for (const id of ids) {
      await this.closeSession(id);
    }
    return ids.length;
  }

  async closeAllSessions(): Promise<number> {
    const ids = [...this.sessions.keys()];
    for (const id of ids) {
      await this.closeSession(id);
    }
    return ids.length;
  }
}

export const devToolsBridge = new DevToolsBridge();
