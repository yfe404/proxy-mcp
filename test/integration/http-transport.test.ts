import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { startHttp, type HttpTransportHandle } from "../../src/http-server.js";

/**
 * Regression for #26.2, over the real Streamable HTTP transport.
 *
 * Each MCP session gets its own McpServer. Ending one session must close that
 * server and drop it from the session map, while every other session keeps
 * answering.
 */

/** Records which per-session McpServers were closed. */
function serverFactory(closed: string[]): () => McpServer {
  let n = 0;
  return () => {
    const name = `session-${n++}`;
    const server = new McpServer({ name, version: "test" });
    server.tool("whoami", "Return the name of the server answering.", {}, async () => ({
      content: [{ type: "text" as const, text: name }],
    }));
    server.tool("echo", "Echo a value.", { value: z.string() }, async ({ value }) => ({
      content: [{ type: "text" as const, text: value }],
    }));
    const close = server.close.bind(server);
    server.close = async () => {
      closed.push(name);
      await close();
    };
    return server;
  };
}

async function connectClient(url: string) {
  const transport = new StreamableHTTPClientTransport(new URL(url));
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(transport);
  return { client, transport };
}

function textOf(result: unknown): string {
  const content = (result as { content: Array<{ type: string; text?: string }> }).content;
  return content.map((c) => c.text ?? "").join("");
}

describe("Streamable HTTP transport sessions", () => {
  let handle: HttpTransportHandle | undefined;

  afterEach(async () => {
    if (handle) await handle.close();
    handle = undefined;
  });

  it("closes only the ended session's McpServer and keeps the other answering", async (t) => {
    const closed: string[] = [];
    const released: string[] = [];
    try {
      handle = await startHttp(0, serverFactory(closed), (sid) => { released.push(sid); });
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }
    const url = `http://127.0.0.1:${handle.port}/mcp`;

    const a = await connectClient(url);
    const b = await connectClient(url);

    // Two distinct sessions, each answered by its own McpServer.
    // terminateSession() clears the client's copy, so keep A's id now.
    const aSessionId = a.transport.sessionId!;
    assert.notEqual(aSessionId, b.transport.sessionId);
    assert.equal(handle.sessions.size, 2);
    assert.equal(textOf(await a.client.callTool({ name: "whoami", arguments: {} })), "session-0");
    assert.equal(textOf(await b.client.callTool({ name: "whoami", arguments: {} })), "session-1");

    // Session A terminates (HTTP DELETE), which closes its transport.
    await a.transport.terminateSession();
    await a.client.close();

    // Its McpServer was closed and both halves left the map.
    await waitFor(() => closed.includes("session-0"), "session-0's McpServer was not closed");
    assert.deepEqual(closed, ["session-0"], "no other session's server may be closed");
    assert.equal(handle.sessions.size, 1);
    assert.equal(handle.sessions.has(aSessionId), false);

    // What that session activated is released, so its browsers cannot outlive
    // it owned by a session id no client can name again (#26).
    assert.deepEqual(released, [aSessionId]);

    // Session B still answers on its own server.
    assert.equal(textOf(await b.client.callTool({ name: "whoami", arguments: {} })), "session-1");
    assert.equal(
      textOf(await b.client.callTool({ name: "echo", arguments: { value: "still here" } })),
      "still here",
    );

    await b.client.close();
  });

  it("closes every session's McpServer on shutdown", async (t) => {
    const closed: string[] = [];
    try {
      handle = await startHttp(0, serverFactory(closed));
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }
    const url = `http://127.0.0.1:${handle.port}/mcp`;

    const a = await connectClient(url);
    const b = await connectClient(url);
    assert.equal(handle.sessions.size, 2);

    await handle.close();
    handle = undefined;

    assert.deepEqual(closed.sort(), ["session-0", "session-1"]);
    await a.client.close().catch(() => {});
    await b.client.close().catch(() => {});
  });
});

async function waitFor(predicate: () => boolean, message: string, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.fail(message);
}
