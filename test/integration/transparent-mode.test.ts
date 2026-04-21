/**
 * Transparent proxy mode integration tests.
 *
 * Tests the transparent listener lifecycle, traffic capture with source tagging,
 * shared ring buffer, and rule sync between explicit and transparent servers.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { ProxyManager } from "../../src/state.js";

describe("Transparent Proxy Mode", () => {
  let pm: ProxyManager;

  afterEach(async () => {
    if (pm) {
      if (pm.isTransparentRunning()) {
        await pm.stopTransparent();
      }
      if (pm.isRunning()) {
        await pm.stop();
      }
    }
  });

  it("requires explicit proxy to be started first", async (t) => {
    pm = new ProxyManager();

    // Should fail because explicit proxy (and its CA cert) hasn't been started
    await assert.rejects(
      () => pm.startTransparent(0),
      /No certificate/,
    );
  });

  it("starts and stops transparent listener", async (t) => {
    pm = new ProxyManager();
    try {
      await pm.start(0);
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }

    // Start transparent
    const { port } = await pm.startTransparent(0);
    assert.ok(port > 0, "Should get a valid port");
    assert.ok(pm.isTransparentRunning(), "Should be running");

    // Check status
    const status = pm.getTransparentStatus() as any;
    assert.equal(status.running, true);
    assert.equal(status.port, port);
    assert.equal(status.trafficCount, 0);

    // Stop transparent
    await pm.stopTransparent();
    assert.ok(!pm.isTransparentRunning(), "Should be stopped");
  });

  it("rejects double start of transparent listener", async (t) => {
    pm = new ProxyManager();
    try {
      await pm.start(0);
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }

    await pm.startTransparent(0);
    await assert.rejects(
      () => pm.startTransparent(0),
      /already running/,
    );
  });

  it("captures HTTP traffic with source tagging on explicit proxy", async (t) => {
    // Create a simple target server
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

      // Make request through the explicit proxy
      await new Promise<void>((resolve, reject) => {
        const req = http.request({
          host: "127.0.0.1",
          port: proxyPort,
          path: `http://127.0.0.1:${targetPort}/test-explicit`,
          method: "GET",
          headers: { host: `127.0.0.1:${targetPort}` },
        }, (res) => {
          res.on("data", () => {});
          res.on("end", () => resolve());
        });
        req.on("error", reject);
        req.end();
      });

      // Wait for traffic capture events
      await new Promise((r) => setTimeout(r, 100));

      const traffic = pm.getTraffic();
      assert.ok(traffic.length > 0, "Should have captured traffic");
      assert.equal(traffic[0].source, "explicit", "Traffic should be tagged as explicit");
    } finally {
      targetServer.close();
    }
  });

  it("transparent status included in main proxy status", async (t) => {
    pm = new ProxyManager();
    try {
      await pm.start(0);
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }

    const status = pm.getStatus() as any;
    assert.ok("transparentProxy" in status, "Status should include transparentProxy");
    assert.equal(status.transparentProxy.running, false);

    await pm.startTransparent(0);
    const statusAfter = pm.getStatus() as any;
    assert.equal(statusAfter.transparentProxy.running, true);
    assert.ok(statusAfter.transparentProxy.port > 0);
  });

  it("stop() also stops transparent listener", async (t) => {
    pm = new ProxyManager();
    try {
      await pm.start(0);
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }

    await pm.startTransparent(0);
    assert.ok(pm.isTransparentRunning());

    // Stopping the main proxy should also stop transparent
    await pm.stop();
    assert.ok(!pm.isTransparentRunning(), "Transparent should be stopped when main proxy stops");
  });
});
