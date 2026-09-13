import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { HttpSessionRegistry } from "../../src/http-server.js";

/**
 * Regression for #26.2.
 *
 * The HTTP transport created one McpServer per MCP session but removed only
 * the transport from the session map when the session closed. A long-running
 * server accumulated one McpServer per past session.
 */

class FakeTransport {
  closed = 0;
  constructor(readonly sessionId: string) {}
  async close(): Promise<void> {
    this.closed++;
  }
}

class FakeServer {
  closed = 0;
  async close(): Promise<void> {
    this.closed++;
  }
}

function twoSessions() {
  const registry = new HttpSessionRegistry<FakeTransport, FakeServer>();
  const a = { transport: new FakeTransport("a"), server: new FakeServer() };
  const b = { transport: new FakeTransport("b"), server: new FakeServer() };
  registry.add("a", a);
  registry.add("b", b);
  return { registry, a, b };
}

describe("HTTP session registry", () => {
  it("closes the McpServer of the session that ended and drops it from the map", async () => {
    const { registry, a, b } = twoSessions();

    const closed = await registry.close("a");

    assert.equal(closed, true);
    assert.equal(a.server.closed, 1, "the ended session's McpServer must be closed");
    assert.equal(registry.has("a"), false, "both halves must leave the map");

    // The other session is untouched and still reachable.
    assert.equal(b.server.closed, 0);
    assert.equal(registry.has("b"), true);
    assert.equal(registry.get("b")?.server, b.server);
    assert.equal(registry.size, 1);
  });

  it("does not close the transport again — it is already closing", async () => {
    const { registry, a } = twoSessions();
    await registry.close("a");
    assert.equal(a.transport.closed, 0);
  });

  it("closes a session's McpServer exactly once", async () => {
    const { registry, a } = twoSessions();

    assert.equal(await registry.close("a"), true);
    assert.equal(await registry.close("a"), false, "a second close is a no-op");

    assert.equal(a.server.closed, 1);
  });

  it("closes transport and server for every session on shutdown", async () => {
    const { registry, a, b } = twoSessions();

    await registry.closeAll();

    assert.equal(registry.size, 0);
    for (const session of [a, b]) {
      assert.equal(session.transport.closed, 1);
      assert.equal(session.server.closed, 1);
    }
  });

  it("survives a server that throws on close during shutdown", async () => {
    const registry = new HttpSessionRegistry<FakeTransport, FakeServer>();
    const bad = new FakeServer();
    bad.close = async () => { throw new Error("already closed"); };
    const good = { transport: new FakeTransport("b"), server: new FakeServer() };
    registry.add("a", { transport: new FakeTransport("a"), server: bad });
    registry.add("b", good);

    await registry.closeAll();

    assert.equal(registry.size, 0);
    assert.equal(good.server.closed, 1);
  });
});
