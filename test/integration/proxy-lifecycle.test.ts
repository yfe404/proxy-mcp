import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { ProxyManager } from "../../src/state.js";

describe("Proxy Lifecycle Integration", () => {
  let pm: ProxyManager;

  afterEach(async () => {
    if (pm?.isRunning()) {
      await pm.stop();
    }
  });

  it("proxies HTTP request and captures traffic", async (t) => {
    // Create a simple target HTTP server
    const targetServer = http.createServer((req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("Hello from target");
    });

    try {
      await new Promise<void>((resolve, reject) => {
        targetServer.once("error", reject);
        targetServer.listen(0, resolve);
      });
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }
    const targetPort = (targetServer.address() as { port: number }).port;

    try {
      pm = new ProxyManager();
      let proxyPort: number;
      try {
        ({ port: proxyPort } = await pm.start(0));
      } catch (e: any) {
        if (e && (e.code === "EPERM" || e.code === "EACCES")) {
          t.skip("listen() not permitted in this environment");
          return;
        }
        throw e;
      }

      // Make HTTP request through the proxy
      const response = await new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
        const req = http.request({
          host: "127.0.0.1",
          port: proxyPort,
          path: `http://127.0.0.1:${targetPort}/test`,
          method: "GET",
          headers: { host: `127.0.0.1:${targetPort}` },
        }, (res) => {
          let body = "";
          res.on("data", (chunk: Buffer) => { body += chunk.toString(); });
          res.on("end", () => resolve({ statusCode: res.statusCode!, body }));
        });
        req.on("error", reject);
        req.end();
      });

      assert.equal(response.statusCode, 200);
      assert.equal(response.body, "Hello from target");

      // Wait briefly for traffic capture events to fire
      await new Promise((r) => setTimeout(r, 100));

      // Check traffic was captured
      const traffic = pm.getTraffic();
      assert.ok(traffic.length > 0, "Should have captured traffic");
      assert.equal(traffic[0].request.method, "GET");
      assert.ok(traffic[0].request.url.includes("/test"));
      assert.equal(traffic[0].response?.statusCode, 200);
    } finally {
      targetServer.close();
    }
  });

  it("applies mock rule to return fake response", async (t) => {
    pm = new ProxyManager();
    let proxyPort: number;
    try {
      ({ port: proxyPort } = await pm.start(0));
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }

    // Add a mock rule
    await pm.addRule({
      priority: 1,
      enabled: true,
      description: "Mock test",
      matcher: { urlPattern: "/mocked" },
      handler: { type: "mock", status: 418, body: "I'm a teapot", headers: { "x-mock": "true" } },
    });

    // Make HTTP request through the proxy
    const response = await new Promise<{ statusCode: number; body: string; headers: http.IncomingHttpHeaders }>((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1",
        port: proxyPort,
        path: "http://example.com/mocked",
        method: "GET",
      }, (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => { body += chunk.toString(); });
        res.on("end", () => resolve({ statusCode: res.statusCode!, body, headers: res.headers }));
      });
      req.on("error", reject);
      req.end();
    });

    assert.equal(response.statusCode, 418);
    assert.equal(response.body, "I'm a teapot");
  });
});
