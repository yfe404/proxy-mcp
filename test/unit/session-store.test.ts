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

  it("imports HAR into a persisted session", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);

    const harPath = path.join(dir, "sample.har");
    const har = {
      log: {
        version: "1.2",
        creator: { name: "test", version: "1.0.0" },
        entries: [
          {
            startedDateTime: "2026-01-01T10:00:00.000Z",
            time: 25,
            request: {
              method: "GET",
              url: "https://example.com/api/v1/items?x=1",
              headers: [{ name: "accept", value: "application/json" }],
              bodySize: 0,
            },
            response: {
              status: 200,
              statusText: "OK",
              headers: [{ name: "content-type", value: "application/json" }],
              bodySize: 13,
              content: { text: "{\"ok\":true}" },
            },
          },
          {
            startedDateTime: "2026-01-01T10:00:01.000Z",
            time: 10,
            request: {
              method: "GET",
              url: "",
              headers: [],
            },
            response: {
              status: 500,
              statusText: "Error",
              headers: [],
              bodySize: 0,
              content: { text: "" },
            },
          },
        ],
      },
    };
    await fs.writeFile(harPath, JSON.stringify(har), "utf8");

    const imported = await store.importHar({
      harFile: harPath,
      sessionName: "import-test",
      strict: false,
    });
    assert.equal(imported.importSummary.totalEntries, 2);
    assert.equal(imported.importSummary.importedEntries, 1);
    assert.equal(imported.importSummary.skippedEntries, 1);
    assert.equal(imported.session.status, "stopped");

    const query = await store.querySession(imported.session.id, { limit: 10, offset: 0 });
    assert.equal(query.total, 1);
    assert.equal(query.items[0].hostname, "example.com");

    const exchange = await store.getSessionExchange(imported.session.id, {
      exchangeId: query.items[0].exchangeId,
      includeBody: true,
    });
    assert.equal(exchange.record?.exchange.response?.statusCode, 200);
    assert.equal(exchange.record?.responseBodyText, "{\"ok\":true}");
  });
});

// ── searchSessionBodies tests ──────────────────────────────────────────────

function sampleExchangeWithBody(
  id: string,
  opts: {
    requestBody?: string;
    responseBody?: string;
    responseContentType?: string;
    requestContentType?: string;
    statusCode?: number;
    method?: string;
    hostname?: string;
    url?: string;
  } = {},
): { exchange: CapturedExchange; requestBody?: Buffer; responseBody?: Buffer } {
  const responseBody = opts.responseBody ? Buffer.from(opts.responseBody) : undefined;
  const requestBody = opts.requestBody ? Buffer.from(opts.requestBody) : undefined;
  const hostname = opts.hostname ?? "example.com";
  const urlPath = opts.url ?? "/page";
  const exchange: CapturedExchange = {
    id,
    timestamp: Date.now(),
    request: {
      method: opts.method ?? "GET",
      url: `https://${hostname}${urlPath}`,
      hostname,
      path: urlPath,
      headers: {
        "user-agent": "unit-test",
        ...(opts.requestContentType ? { "content-type": opts.requestContentType } : {}),
      },
      bodyPreview: opts.requestBody?.slice(0, 4096) ?? "",
      bodySize: requestBody?.length ?? 0,
    },
    response: {
      statusCode: opts.statusCode ?? 200,
      statusMessage: "OK",
      headers: {
        "content-type": opts.responseContentType ?? "text/html; charset=utf-8",
      },
      bodyPreview: opts.responseBody?.slice(0, 4096) ?? "",
      bodySize: responseBody?.length ?? 0,
    },
    duration: 50,
  };
  return { exchange, requestBody, responseBody };
}

describe("searchSessionBodies", () => {
  // Core functionality

  it("finds text in response body", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, requestBody, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: '<div><span class="price">299,-</span></div>',
    });
    store.recordExchange(exchange, { requestBody, responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "299,-" });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].matchedIn, "response");
    assert.equal(result.matches[0].source, "full");
    assert.ok(result.matches[0].snippets[0].context.includes("[299,-]"));
    assert.ok(result.matches[0].snippets[0].context.includes("price"));
  });

  it("finds text in request body", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, requestBody, responseBody } = sampleExchangeWithBody("e1", {
      method: "POST",
      requestBody: '{"username":"admin","password":"secret"}',
      requestContentType: "application/json",
      responseBody: '{"ok":true}',
    });
    store.recordExchange(exchange, { requestBody, responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "admin",
      searchIn: "request",
    });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].matchedIn, "request");
  });

  it("searches both sides with response priority", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, requestBody, responseBody } = sampleExchangeWithBody("e1", {
      method: "POST",
      requestBody: "token123-in-request",
      responseBody: "token123-in-response",
    });
    store.recordExchange(exchange, { requestBody, responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "token123",
      searchIn: "both",
    });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].matchedIn, "response");
  });

  it("caps snippets at 3 per exchange", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const body = "error occurred. error again. error three. error four. error five.";
    const { exchange, requestBody, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: body,
    });
    store.recordExchange(exchange, { requestBody, responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "error" });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].snippets.length, 3);
  });

  it("returns multiple matching exchanges", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    for (let i = 1; i <= 3; i++) {
      const { exchange, requestBody, responseBody } = sampleExchangeWithBody(`e${i}`, {
        responseBody: `Page ${i} contains the keyword findme here`,
        url: `/page${i}`,
      });
      store.recordExchange(exchange, { requestBody, responseBody });
    }
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "findme", limit: 10 });
    assert.equal(result.totalMatches, 3);
    assert.equal(result.matches.length, 3);
  });

  // Case sensitivity

  it("searches case-insensitively by default", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, requestBody, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "The ProductName is great",
    });
    store.recordExchange(exchange, { requestBody, responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "productname" });
    assert.equal(result.totalMatches, 1);
    assert.ok(result.matches[0].snippets[0].context.includes("ProductName"));
  });

  it("respects case_sensitive flag", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, requestBody, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "The ProductName is great",
    });
    store.recordExchange(exchange, { requestBody, responseBody });
    await store.stopSession();

    const noMatch = await store.searchSessionBodies(session.id, {
      text: "productname",
      caseSensitive: true,
    });
    assert.equal(noMatch.totalMatches, 0);

    const match = await store.searchSessionBodies(session.id, {
      text: "ProductName",
      caseSensitive: true,
    });
    assert.equal(match.totalMatches, 1);
  });

  // Preview fallback

  it("falls back to bodyPreview in preview-profile sessions", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "preview" });

    const { exchange } = sampleExchangeWithBody("e1", {
      responseBody: "This preview has a secret-token inside",
    });
    // No full bodies passed — preview profile
    store.recordExchange(exchange);
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "secret-token" });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].source, "preview");
  });

  it("prefers full body over preview when available", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, requestBody, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "Full body content with unique-marker-xyz",
    });
    store.recordExchange(exchange, { requestBody, responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "unique-marker-xyz" });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].source, "full");
  });

  // Filtering and skipping

  it("skips binary bodies", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    // PNG-like binary body with null bytes
    const binaryBody = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x00, 0x0d]);
    const exchange: CapturedExchange = {
      id: "e1",
      timestamp: Date.now(),
      request: {
        method: "GET", url: "https://example.com/data", hostname: "example.com",
        path: "/data", headers: {}, bodyPreview: "", bodySize: 0,
      },
      response: {
        statusCode: 200, statusMessage: "OK",
        headers: { "content-type": "application/octet-stream" },
        bodyPreview: "", bodySize: binaryBody.length,
      },
      duration: 10,
    };
    // Force content-type to something non-binary for index so it's not pre-filtered,
    // but the actual body is binary
    exchange.response!.headers["content-type"] = "text/plain";
    store.recordExchange(exchange, { responseBody: binaryBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "anything" });
    assert.equal(result.skippedBinary, 1);
    assert.equal(result.totalMatches, 0);
  });

  it("pre-filters by content_type_contains", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const html = sampleExchangeWithBody("e1", {
      responseBody: "findme in html", responseContentType: "text/html",
    });
    const json = sampleExchangeWithBody("e2", {
      responseBody: "findme in json", responseContentType: "application/json",
    });
    store.recordExchange(html.exchange, { responseBody: html.responseBody });
    store.recordExchange(json.exchange, { responseBody: json.responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "findme",
      contentTypeContains: "json",
    });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].exchangeId, "e2");
  });

  it("skips known binary MIME types without reading records", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const img = sampleExchangeWithBody("e1", {
      responseBody: "not really an image findme",
      responseContentType: "image/jpeg",
    });
    const html = sampleExchangeWithBody("e2", {
      responseBody: "findme in html",
      responseContentType: "text/html",
    });
    store.recordExchange(img.exchange, { responseBody: img.responseBody });
    store.recordExchange(html.exchange, { responseBody: html.responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "findme" });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].exchangeId, "e2");
    // image/jpeg was filtered at index level, so scanned should be 1
    assert.equal(result.scanned, 1);
  });

  it("pre-filters by hostname", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const a = sampleExchangeWithBody("e1", {
      responseBody: "findme here", hostname: "api.example.com",
    });
    const b = sampleExchangeWithBody("e2", {
      responseBody: "findme too", hostname: "cdn.other.com",
    });
    store.recordExchange(a.exchange, { responseBody: a.responseBody });
    store.recordExchange(b.exchange, { responseBody: b.responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "findme",
      hostnameContains: "api.example",
    });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].exchangeId, "e1");
  });

  it("pre-filters by URL", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const a = sampleExchangeWithBody("e1", {
      responseBody: "findme", url: "/api/v2/data",
    });
    const b = sampleExchangeWithBody("e2", {
      responseBody: "findme", url: "/static/style.css",
    });
    store.recordExchange(a.exchange, { responseBody: a.responseBody });
    store.recordExchange(b.exchange, { responseBody: b.responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "findme",
      urlContains: "/api/v2",
    });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].exchangeId, "e1");
  });

  it("pre-filters by method", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const get = sampleExchangeWithBody("e1", {
      responseBody: "findme", method: "GET",
    });
    const post = sampleExchangeWithBody("e2", {
      responseBody: "findme", method: "POST",
    });
    store.recordExchange(get.exchange, { responseBody: get.responseBody });
    store.recordExchange(post.exchange, { responseBody: post.responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "findme",
      method: "POST",
    });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].exchangeId, "e2");
  });

  it("pre-filters by status code", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const ok = sampleExchangeWithBody("e1", {
      responseBody: "findme", statusCode: 200,
    });
    const err = sampleExchangeWithBody("e2", {
      responseBody: "findme", statusCode: 500,
    });
    store.recordExchange(ok.exchange, { responseBody: ok.responseBody });
    store.recordExchange(err.exchange, { responseBody: err.responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "findme",
      statusCode: 200,
    });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].exchangeId, "e1");
  });

  // Limits

  it("respects max_scan limit", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    for (let i = 1; i <= 10; i++) {
      const { exchange, responseBody } = sampleExchangeWithBody(`e${i}`, {
        responseBody: `Body ${i} with data`,
        url: `/p${i}`,
      });
      store.recordExchange(exchange, { responseBody });
    }
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "data",
      maxScan: 3,
    });
    assert.equal(result.scanned, 3);
  });

  it("respects limit on matching results", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    for (let i = 1; i <= 10; i++) {
      const { exchange, responseBody } = sampleExchangeWithBody(`e${i}`, {
        responseBody: `Body ${i} with data`,
        url: `/p${i}`,
      });
      store.recordExchange(exchange, { responseBody });
    }
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "data",
      limit: 2,
    });
    assert.equal(result.matches.length, 2);
    assert.equal(result.totalMatches, 2);
  });

  it("both limits interact correctly", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    for (let i = 1; i <= 10; i++) {
      const { exchange, responseBody } = sampleExchangeWithBody(`e${i}`, {
        responseBody: i <= 5 ? `match data here` : `no keyword`,
        url: `/p${i}`,
      });
      store.recordExchange(exchange, { responseBody });
    }
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "match data",
      maxScan: 4,
      limit: 2,
    });
    assert.ok(result.scanned <= 4);
    assert.ok(result.matches.length <= 2);
  });

  // Edge cases

  it("handles empty session gracefully", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "anything" });
    assert.equal(result.totalMatches, 0);
    assert.equal(result.scanned, 0);
    assert.equal(result.skippedBinary, 0);
    assert.equal(result.skippedNoBody, 0);
  });

  it("counts skippedNoBody for exchanges without body", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    // Exchange with empty bodies
    const exchange: CapturedExchange = {
      id: "e1",
      timestamp: Date.now(),
      request: {
        method: "GET", url: "https://example.com/empty", hostname: "example.com",
        path: "/empty", headers: {}, bodyPreview: "", bodySize: 0,
      },
      response: {
        statusCode: 204, statusMessage: "No Content",
        headers: { "content-type": "text/plain" },
        bodyPreview: "", bodySize: 0,
      },
      duration: 5,
    };
    store.recordExchange(exchange);
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "anything",
      searchIn: "response",
    });
    assert.equal(result.skippedNoBody, 1);
  });

  it("handles multi-line content", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "line1\nline2\nline3\nline4",
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "line2" });
    assert.equal(result.totalMatches, 1);
    assert.ok(result.matches[0].snippets[0].context.includes("line1"));
    assert.ok(result.matches[0].snippets[0].context.includes("line3"));
  });

  it("handles very long bodies", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const padding = "x".repeat(500_000);
    const body = `${padding}NEEDLE${padding}`;
    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: body,
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "NEEDLE" });
    assert.equal(result.totalMatches, 1);
    assert.equal(result.matches[0].snippets[0].position, 500_000);
  });

  it("returns no matches when text is absent", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "This body has no relevant content",
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "xyz-not-here" });
    assert.equal(result.totalMatches, 0);
    assert.equal(result.scanned, 1);
  });

  // responseContentType in index

  it("populates responseContentType in index entries", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "test",
      responseContentType: "text/html; charset=utf-8",
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    const query = await store.querySession(session.id, { limit: 10, offset: 0 });
    assert.equal(query.items[0].responseContentType, "text/html");
  });

  it("sets null responseContentType for exchange without response", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    // Aborted request — no response
    const exchange: CapturedExchange = {
      id: "e1",
      timestamp: Date.now(),
      request: {
        method: "GET", url: "https://example.com/abort", hostname: "example.com",
        path: "/abort", headers: {}, bodyPreview: "", bodySize: 0,
      },
      duration: undefined,
    };
    store.recordExchange(exchange);
    await store.stopSession();

    const query = await store.querySession(session.id, { limit: 10, offset: 0 });
    assert.equal(query.items[0].responseContentType, null);
  });

  // Snippet details

  it("respects contextChars parameter", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const before = "A".repeat(200);
    const after = "B".repeat(200);
    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: `${before}NEEDLE${after}`,
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, {
      text: "NEEDLE",
      contextChars: 20,
    });
    const snippet = result.matches[0].snippets[0].context;
    // Before [MATCH]: "..." prefix + ~20 A's
    // After [MATCH]: ~20 B's + "..." suffix
    assert.ok(snippet.startsWith("..."));
    assert.ok(snippet.endsWith("..."));
    // Total should be manageable, not 200 chars of context
    assert.ok(snippet.length < 80);
  });

  it("no ellipsis prefix when match is at start of body", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "NEEDLE followed by some text here",
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "NEEDLE" });
    const snippet = result.matches[0].snippets[0].context;
    assert.ok(!snippet.startsWith("..."));
    assert.equal(result.matches[0].snippets[0].position, 0);
  });

  it("no ellipsis suffix when match is at end of body", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "Some text before NEEDLE",
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    const result = await store.searchSessionBodies(session.id, { text: "NEEDLE" });
    const snippet = result.matches[0].snippets[0].context;
    assert.ok(!snippet.endsWith("..."));
  });

  // Backward compatibility

  it("old index entries without responseContentType pass content_type_contains filter", async () => {
    const dir = await makeTempDir();
    const store = new SessionStore(dir);
    const session = await store.startSession({ captureProfile: "full" });

    const { exchange, responseBody } = sampleExchangeWithBody("e1", {
      responseBody: "findme here",
    });
    store.recordExchange(exchange, { responseBody });
    await store.stopSession();

    // Manually rewrite the index to strip responseContentType (simulate old format)
    const indexPath = path.join(dir, session.id, "index.ndjson");
    const indexRaw = await fs.readFile(indexPath, "utf8");
    const lines = indexRaw.trim().split("\n").map(line => {
      const entry = JSON.parse(line);
      delete entry.responseContentType;
      return JSON.stringify(entry);
    });
    await fs.writeFile(indexPath, lines.join("\n") + "\n");

    // With contentTypeContains filter, old entries (undefined) should pass through
    const result = await store.searchSessionBodies(session.id, {
      text: "findme",
      contentTypeContains: "html",
    });
    assert.equal(result.totalMatches, 1);
  });
});
