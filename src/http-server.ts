/**
 * Streamable HTTP transport — one MCP session per connected client.
 *
 * Each session gets its own McpServer and its own transport. Both are closed
 * when the session ends: closing only the transport left one McpServer per
 * past session alive for the lifetime of the process (#26).
 */

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

/** The part of a transport the registry needs. */
export interface ClosableTransport {
  readonly sessionId?: string;
  close(): Promise<void>;
}

/** The part of an McpServer the registry needs. */
export interface ClosableServer {
  close(): Promise<void>;
}

/** One MCP session: the transport carrying it and the server answering on it. */
export interface McpHttpSession<
  T extends ClosableTransport = ClosableTransport,
  S extends ClosableServer = ClosableServer,
> {
  transport: T;
  server: S;
}

/**
 * The live MCP sessions of an HTTP transport.
 *
 * Holds both halves of a session so neither outlives the other.
 */
export class HttpSessionRegistry<
  T extends ClosableTransport = ClosableTransport,
  S extends ClosableServer = ClosableServer,
> {
  private sessions = new Map<string, McpHttpSession<T, S>>();

  add(sessionId: string, session: McpHttpSession<T, S>): void {
    this.sessions.set(sessionId, session);
  }

  get(sessionId: string): McpHttpSession<T, S> | undefined {
    return this.sessions.get(sessionId);
  }

  has(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  get size(): number {
    return this.sessions.size;
  }

  /**
   * Drop a session and close its McpServer.
   *
   * Called from `transport.onclose`, so the transport is already closing and
   * is not closed again here. Returns false when the session was already gone,
   * which keeps a close during closeAll() from closing the server twice.
   */
  async close(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    this.sessions.delete(sessionId);
    await session.server.close();
    return true;
  }

  /** Drop every session, closing transport then server. Errors are ignored. */
  async closeAll(): Promise<void> {
    for (const [sessionId, session] of [...this.sessions]) {
      this.sessions.delete(sessionId);
      try { await session.transport.close(); } catch { /* ignore */ }
      try { await session.server.close(); } catch { /* ignore */ }
    }
  }
}

/** A running HTTP transport. */
export interface HttpTransportHandle {
  /** The port actually bound (useful when 0 was requested). */
  port: number;
  httpServer: Server;
  sessions: HttpSessionRegistry<StreamableHTTPServerTransport, McpServer>;
  /** Close every session and stop listening. */
  close(): Promise<void>;
}

/**
 * Start the Streamable HTTP transport on `port`.
 *
 * `createMcpServer` is called once per new MCP session.
 */
export async function startHttp(
  port: number,
  createMcpServer: () => McpServer,
): Promise<HttpTransportHandle> {
  const sessions = new HttpSessionRegistry<StreamableHTTPServerTransport, McpServer>();

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
      await sessions.get(sessionId)!.transport.handleRequest(req, res, body);
      return;
    }

    // New initialization — create a fresh McpServer per session so
    // multiple clients (Claude Code + scripts) can connect simultaneously.
    if (!sessionId && isInitializeRequest(body)) {
      const sessionServer = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid) => {
          sessions.add(sid, { transport, server: sessionServer });
        },
      });

      // The session's McpServer dies with its transport: closing only the
      // transport leaked one server per past session (#26).
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) void sessions.close(sid);
      };

      await sessionServer.connect(transport);
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
    await sessions.get(sessionId)!.transport.handleRequest(req, res);
  }

  /* --- DELETE: terminate a session --- */
  async function handleDelete(req: IncomingMessage, res: ServerResponse) {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !sessions.has(sessionId)) {
      res.writeHead(400).end("Invalid or missing session ID");
      return;
    }
    await sessions.get(sessionId)!.transport.handleRequest(req, res);
  }

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });

  const address = httpServer.address();
  const boundPort = typeof address === "object" && address !== null ? address.port : port;

  return {
    port: boundPort,
    httpServer,
    sessions,
    close: async () => {
      await sessions.closeAll();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
}

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
