import { describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { fetchJson, getCdpTargets, getCdpVersion, waitForCdpVersion } from "../../src/cdp-utils.js";

async function withServer(
  t: { skip: (reason?: string) => void },
  handler: http.RequestListener,
  fn: (port: number) => Promise<void>,
): Promise<void> {
  const server = http.createServer(handler);

  let port: number | null = null;
  try {
    port = await new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (!addr || typeof addr === "string") {
          reject(new Error("Unexpected server address"));
          return;
        }
        resolve(addr.port);
      });
    });
  } catch (e: any) {
    // In restricted sandboxes, listening sockets may be forbidden.
    if (e && (e.code === "EPERM" || e.code === "EACCES")) {
      t.skip("listen() not permitted in this environment");
      return;
    }
    throw e;
  }

  try {
    await fn(port);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

describe("cdp-utils", () => {
  it("fetches CDP version and targets JSON", async (t) => {
    await withServer(t, (req, res) => {
      if (!req.url) return void res.writeHead(400).end();

      if (req.url === "/json/version") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ Browser: "TestChrome/1.0", webSocketDebuggerUrl: "ws://127.0.0.1/devtools/browser/abc" }));
        return;
      }

      if (req.url === "/json/list") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify([{ id: "page_1", type: "page", url: "https://example.com", webSocketDebuggerUrl: "ws://127.0.0.1/devtools/page/1" }]));
        return;
      }

      res.writeHead(404).end();
    }, async (port) => {
      const version = await getCdpVersion(port, { timeoutMs: 500 });
      assert.equal(version.Browser, "TestChrome/1.0");

      const targets = await getCdpTargets(port, { timeoutMs: 500 });
      assert.equal(targets.length, 1);
      assert.equal(targets[0].id, "page_1");
    });
  });

  it("waitForCdpVersion retries until /json/version returns 200", async (t) => {
    let calls = 0;
    await withServer(t, (req, res) => {
      if (req.url !== "/json/version") return void res.writeHead(404).end();
      calls++;
      if (calls < 3) {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("not ready");
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ Browser: "ReadyChrome/1.0" }));
    }, async (port) => {
      const version = await waitForCdpVersion(port, { timeoutMs: 2000, intervalMs: 50, requestTimeoutMs: 200 });
      assert.equal(version.Browser, "ReadyChrome/1.0");
      assert.ok(calls >= 3);
    });
  });

  it("fetchJson enforces timeouts", async (t) => {
    await withServer(t, (req, res) => {
      if (req.url !== "/slow") return void res.writeHead(404).end();
      setTimeout(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      }, 200);
    }, async (port) => {
      await assert.rejects(
        () => fetchJson(`http://127.0.0.1:${port}/slow`, { timeoutMs: 20 }),
        /aborted|Abort|timeout|fetch failed/i,
      );
    });
  });
});

