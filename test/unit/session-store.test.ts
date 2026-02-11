import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { SessionStore } from "../../src/session-store.js";
import type { CapturedExchange } from "../../src/state.js";

function sampleExchange(id: string): CapturedExchange {
  return {
    id,
    timestamp: Date.now(),
    request: {
      method: "GET",
      url: "https://example.com/api/test?x=1",
      hostname: "example.com",
      path: "/api/test?x=1",
      headers: { "user-agent": "unit-test", accept: "application/json" },
      bodyPreview: "",
      bodySize: 0,
    },
    response: {
      statusCode: 200,
      statusMessage: "OK",
      headers: { "content-type": "application/json" },
      bodyPreview: "{\"ok\":true}",
      bodySize: 11,
    },
    duration: 42,
  };
}

async function makeTempDir(): Promise<string> {
  return await fs.mkdtemp(path.join(tmpdir(), "proxy-mcp-session-"));
}

describe("SessionStore", () => {
  it("records, queries, and retrieves exchanges", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);

    const session = await store.startSession({ captureProfile: "full" });
    store.recordExchange(sampleExchange("e1"), {
      requestBody: Buffer.from("hello"),
      responseBody: Buffer.from("{\"ok\":true}"),
    });
    await store.stopSession();

    const query = await store.querySession(session.id, { limit: 10, offset: 0 });
    assert.equal(query.total, 1);
    assert.equal(query.items[0].exchangeId, "e1");
    assert.equal(query.items[0].hasFullResponseBody, true);

    const exchange = await store.getSessionExchange(session.id, { exchangeId: "e1", includeBody: true });
    assert.equal(exchange.index.exchangeId, "e1");
    assert.equal(exchange.record?.requestBodyText, "hello");
    assert.equal(exchange.record?.responseBodyText, "{\"ok\":true}");
  });

  it("exports HAR and lists sessions", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);

    const session = await store.startSession({ captureProfile: "full", sessionName: "har-test" });
    store.recordExchange(sampleExchange("e2"), {
      responseBody: Buffer.from("{\"ok\":true}"),
    });
    await store.stopSession();

    const sessions = await store.listSessions();
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].id, session.id);

    const out = await store.exportHar(session.id, {});
    const harRaw = await fs.readFile(out.outputFile, "utf8");
    const har = JSON.parse(harRaw) as { log: { entries: unknown[] } };
    assert.equal(out.entries, 1);
    assert.equal(har.log.entries.length, 1);
  });

  it("recovers sessions with truncated tail", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);

    const session = await store.startSession({ captureProfile: "preview" });
    store.recordExchange(sampleExchange("e3"));
    await store.stopSession();

    const recordsPath = path.join(dir, session.id, "records.ndjson");
    await fs.appendFile(recordsPath, "{\"bad\": ");

    const recovered = await store.recoverSession(session.id);
    assert.equal(recovered.recovered.length, 1);
    assert.equal(recovered.recovered[0].sessionId, session.id);
    assert.ok(recovered.recovered[0].droppedTailBytes > 0);
  });
});

