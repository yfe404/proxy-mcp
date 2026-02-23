/**
 * Proxy MCP Server — entry point.
 *
 * HTTPS MITM proxy via mockttp with lifecycle/rules/traffic/TLS/interceptors/session tools and resources.
 * Tools organized into 8 modules:
 *   lifecycle, upstream, rules, traffic, modification, tls, interceptors, devtools
 *
 * Transports:
 *   --transport stdio   (default) communicate over stdin/stdout
 *   --transport http    Streamable HTTP on --port (default 3001)
 */

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

import { registerLifecycleTools } from "./tools/lifecycle.js";
import { registerUpstreamTools } from "./tools/upstream.js";
import { registerRuleTools } from "./tools/rules.js";
import { registerTrafficTools } from "./tools/traffic.js";
import { registerModificationTools } from "./tools/modification.js";
import { registerTlsTools } from "./tools/tls.js";
import { registerInterceptorTools } from "./tools/interceptors.js";
import { registerDevToolsTools } from "./tools/devtools.js";
import { registerSessionTools } from "./tools/sessions.js";
import { registerResources } from "./resources.js";
import { initInterceptors } from "./interceptors/init.js";

/* ------------------------------------------------------------------ */
/*  CLI helpers                                                        */
/* ------------------------------------------------------------------ */

function arg(name: string, fallback: string): string {
  const prefix = `--${name}=`;
  const found = process.argv.find((a) => a.startsWith(prefix));
  if (found) return found.slice(prefix.length);

  const idx = process.argv.indexOf(`--${name}`);
  if (idx !== -1 && idx + 1 < process.argv.length) return process.argv[idx + 1];

  return process.env[name.toUpperCase().replace(/-/g, "_")] ?? fallback;
}

/* ------------------------------------------------------------------ */
/*  Server factory                                                     */
/* ------------------------------------------------------------------ */

function createMcpServer(): McpServer {
  const server = new McpServer({ name: "proxy", version: "1.0.0" });

  initInterceptors();

  registerLifecycleTools(server);
  registerUpstreamTools(server);
  registerRuleTools(server);
  registerTrafficTools(server);
  registerModificationTools(server);
  registerTlsTools(server);
  registerInterceptorTools(server);
  registerDevToolsTools(server);
  registerSessionTools(server);
  registerResources(server);

  return server;
}

/* ------------------------------------------------------------------ */
/*  Stdio transport                                                    */
/* ------------------------------------------------------------------ */

async function startStdio() {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

/* ------------------------------------------------------------------ */
/*  Streamable HTTP transport                                          */
/* ------------------------------------------------------------------ */

async function startHttp(port: number) {
  // One MCP server instance shared across all sessions
  const server = createMcpServer();

  // Session map: sessionId → transport
  const sessions = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // Only serve the /mcp endpoint
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (url.pathname !== "/mcp") {
      res.writeHead(404).end("Not found");
      return;
    }

    try {
      if (req.method === "POST") {
        await handlePost(req, res);
      } else if (req.method === "GET") {
        await handleGet(req, res);
      } else if (req.method === "DELETE") {
        await handleDelete(req, res);
      } else {
        res.writeHead(405).end("Method not allowed");
      }
    } catch (err) {
      console.error("HTTP handler error:", err);
      if (!res.headersSent) {
        res.writeHead(500).end(JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        }));
      }
    }
  });

  /* --- POST: initialize or send JSON-RPC messages --- */
  async function handlePost(req: IncomingMessage, res: ServerResponse) {
    const body = await readJson(req);
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    // Existing session
    if (sessionId && sessions.has(sessionId)) {
      const transport = sessions.get(sessionId)!;
      await transport.handleRequest(req, res, body);
      return;
    }

    // New initialization
    if (!sessionId && isInitializeRequest(body)) {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid) => {
          sessions.set(sid, transport);
        },
      });

      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) sessions.delete(sid);
      };

      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      return;
    }

    // Invalid
    res.writeHead(400).end(JSON.stringify({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Bad request: missing or invalid session" },
      id: null,
    }));
  }

  /* --- GET: open SSE stream for server-initiated messages --- */
  async function handleGet(req: IncomingMessage, res: ServerResponse) {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !sessions.has(sessionId)) {
      res.writeHead(400).end("Invalid or missing session ID");
      return;
    }
    await sessions.get(sessionId)!.handleRequest(req, res);
  }

  /* --- DELETE: terminate a session --- */
  async function handleDelete(req: IncomingMessage, res: ServerResponse) {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !sessions.has(sessionId)) {
      res.writeHead(400).end("Invalid or missing session ID");
      return;
    }
    await sessions.get(sessionId)!.handleRequest(req, res);
  }

  // Graceful shutdown
  process.on("SIGINT", async () => {
    console.error("Shutting down…");
    for (const [sid, transport] of sessions) {
      try { await transport.close(); } catch { /* ignore */ }
      sessions.delete(sid);
    }
    httpServer.close();
    process.exit(0);
  });

  httpServer.listen(port, () => {
    console.error(`Proxy MCP server (Streamable HTTP) listening on http://127.0.0.1:${port}/mcp`);
  });
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString()));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

async function main() {
  const transport = arg("transport", "stdio");

  if (transport === "stdio") {
    await startStdio();
  } else if (transport === "http") {
    const port = parseInt(arg("port", "3001"), 10);
    await startHttp(port);
  } else {
    console.error(`Unknown transport: ${transport}. Use "stdio" or "http".`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
