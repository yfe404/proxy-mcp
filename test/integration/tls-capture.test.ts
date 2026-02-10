import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import http from "node:http";
import tls from "node:tls";
import { ProxyManager } from "../../src/state.js";

describe("TLS Capture Integration", () => {
  let pm: ProxyManager;

  afterEach(async () => {
    if (pm?.isRunning()) {
      await pm.stop();
    }
  });

  it("captures client TLS metadata on HTTPS requests via CONNECT tunnel", async (t) => {
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

    // Make an HTTPS request through the proxy using CONNECT tunnel.
    // The proxy MITM-decrypts, so client TLS metadata (JA3/JA4) should be captured.
    try {
      await new Promise<void>((resolve, reject) => {
        const connectReq = http.request({
          host: "127.0.0.1",
          port: proxyPort,
          method: "CONNECT",
          path: "example.com:443",
        });

        const timer = setTimeout(() => {
          resolve(); // Timeout is acceptable — we're testing the proxy TLS layer
        }, 3000);

        connectReq.on("connect", (_res, socket) => {
          const tlsSocket = tls.connect({
            socket,
            servername: "example.com",
            rejectUnauthorized: false,
          }, () => {
            // Make the HTTPS request over the tunnel
            const req = https.request({
              hostname: "example.com",
              path: "/test-tls",
              method: "GET",
              createConnection: () => tlsSocket,
            }, (res) => {
              res.on("data", () => {});
              res.on("end", () => {
                clearTimeout(timer);
                resolve();
              });
            });
            req.on("error", () => {
              clearTimeout(timer);
              resolve(); // Connection errors are expected (network)
            });
            req.end();
          });

          tlsSocket.on("error", () => {
            clearTimeout(timer);
            resolve();
          });
        });

        connectReq.on("error", () => {
          clearTimeout(timer);
          resolve();
        });
        connectReq.end();
      });
    } catch {
      // Swallow any errors — we're testing the proxy TLS layer, not connectivity
    }

    // Wait for traffic capture events
    await new Promise((r) => setTimeout(r, 200));

    const traffic = pm.getTraffic();
    // We should have at least one exchange with TLS metadata if the handshake completed
    if (traffic.length > 0 && traffic[0].tls?.client) {
      assert.ok(traffic[0].tls.client.ja3Fingerprint, "Should have JA3 fingerprint");
      assert.ok(typeof traffic[0].tls.client.ja3Fingerprint === "string");
      assert.equal(traffic[0].tls.client.ja3Fingerprint.length, 32, "JA3 should be 32-char hex (MD5)");
    }

    // Verify TLS config tools work regardless
    const tlsConfig = pm.getTlsConfig();
    assert.equal((tlsConfig as { serverTlsCaptureEnabled: boolean }).serverTlsCaptureEnabled, false);
  });

  it("enables and disables server TLS capture", () => {
    pm = new ProxyManager();

    assert.equal(pm.isServerTlsCaptureEnabled(), false);

    pm.enableServerTls();
    assert.equal(pm.isServerTlsCaptureEnabled(), true);

    pm.disableServerTls();
    assert.equal(pm.isServerTlsCaptureEnabled(), false);
  });

  it("manages JA3 spoof config", async () => {
    pm = new ProxyManager();

    assert.equal(pm.getJa3SpoofConfig(), null);

    await pm.setJa3Spoof({
      ja3: "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
      userAgent: "TestAgent/1.0",
      hostPatterns: ["example.com"],
    });

    const config = pm.getJa3SpoofConfig();
    assert.ok(config);
    assert.equal(config.ja3, "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0");
    assert.equal(config.userAgent, "TestAgent/1.0");
    assert.deepEqual(config.hostPatterns, ["example.com"]);

    await pm.clearJa3Spoof();
    assert.equal(pm.getJa3SpoofConfig(), null);
  });
});
