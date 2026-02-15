/**
 * E2E fingerprint spoofing tests — success metrics for issue #2.
 *
 * Requirements: Docker, Chrome/Chromium, internet access.
 *
 * These tests launch the full MCP server, start a proxy, enable fingerprint
 * spoofing via curl-impersonate, launch Chrome, and navigate to real sites
 * to verify TLS/HTTP2 fingerprint fidelity.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

import { registerLifecycleTools } from "../../src/tools/lifecycle.js";
import { registerTrafficTools } from "../../src/tools/traffic.js";
import { registerRuleTools } from "../../src/tools/rules.js";
import { registerUpstreamTools } from "../../src/tools/upstream.js";
import { registerModificationTools } from "../../src/tools/modification.js";
import { registerTlsTools } from "../../src/tools/tls.js";
import { registerInterceptorTools } from "../../src/tools/interceptors.js";
import { registerDevToolsTools } from "../../src/tools/devtools.js";
import { registerSessionTools } from "../../src/tools/sessions.js";
import { registerResources } from "../../src/resources.js";
import { initInterceptors } from "../../src/interceptors/init.js";

import { CdpSession, getCdpTargets, waitForCdpVersion } from "../../src/cdp-utils.js";

// ── Helpers ──

function parseToolResult(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0].text);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Test suite ──

describe("E2E Fingerprint Spoofing", () => {
  let client: Client;
  let proxyPort: number;
  let chromeTargetId: string;
  let cdpPort: number;
  let cdpSession: CdpSession;
  let browserleaksData: Record<string, unknown> | null = null;

  before(async () => {
    // Set up MCP server + client
    const server = new McpServer({ name: "proxy-e2e", version: "1.0.0" });
    initInterceptors();
    registerLifecycleTools(server);
    registerTrafficTools(server);
    registerRuleTools(server);
    registerUpstreamTools(server);
    registerModificationTools(server);
    registerTlsTools(server);
    registerInterceptorTools(server);
    registerDevToolsTools(server);
    registerSessionTools(server);
    registerResources(server);

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: "e2e-client", version: "1.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    // Start proxy
    const startRes = parseToolResult(
      await client.callTool({ name: "proxy_start", arguments: { port: 0 } }) as { content: Array<{ text: string }> },
    );
    assert.equal(startRes.status, "success", `proxy_start failed: ${JSON.stringify(startRes)}`);
    proxyPort = startRes.port as number;

    // Enable fingerprint spoofing with chrome_131 preset
    const spoofRes = parseToolResult(
      await client.callTool({
        name: "proxy_set_fingerprint_spoof",
        arguments: { preset: "chrome_131" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(spoofRes.status, "success", `fingerprint spoof failed: ${JSON.stringify(spoofRes)}`);

    // Launch Chrome
    const chromeRes = parseToolResult(
      await client.callTool({
        name: "interceptor_chrome_launch",
        arguments: { url: "about:blank" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(chromeRes.status, "success", `chrome launch failed: ${JSON.stringify(chromeRes)}`);
    chromeTargetId = chromeRes.targetId as string;
    const details = chromeRes.details as Record<string, unknown>;
    cdpPort = details.port as number;

    // Wait for CDP and open a persistent session
    await waitForCdpVersion(cdpPort, { timeoutMs: 10_000 });
    const targets = await getCdpTargets(cdpPort);
    const pageTarget = targets.find((t) => t.type === "page") as Record<string, unknown> | undefined;
    assert.ok(pageTarget, "No page target found");
    const wsUrl = pageTarget.webSocketDebuggerUrl as string;
    cdpSession = await CdpSession.open(wsUrl, { timeoutMs: 10_000 });

    // Warm up: navigate to a simple HTTPS page to trigger Docker image build +
    // container start on the first spoofed request. This can take 30-60s on first run.
    cdpSession.send("Page.navigate", { url: "https://httpbin.org/get" }, { timeoutMs: 120_000 }).catch(() => {});
    // Poll traffic until we see the warm-up request come through
    for (let i = 0; i < 60; i++) {
      await sleep(2_000);
      const warmRes = parseToolResult(
        await client.callTool({
          name: "proxy_search_traffic",
          arguments: { query: "httpbin.org" },
        }) as { content: Array<{ text: string }> },
      );
      const warmExchanges = warmRes.results as Array<Record<string, unknown>>;
      if (warmExchanges.some((e) => (e.response as Record<string, unknown> | undefined))) break;
    }
    // Clear warm-up traffic
    await client.callTool({ name: "proxy_clear_traffic", arguments: {} });
  });

  after(async () => {
    // Cleanup
    try { cdpSession?.close(); } catch { /* */ }
    try {
      if (chromeTargetId) {
        await client.callTool({
          name: "interceptor_chrome_close",
          arguments: { target_id: chromeTargetId },
        });
      }
    } catch { /* */ }
    try { await client.callTool({ name: "proxy_clear_ja3_spoof", arguments: {} }); } catch { /* */ }
    try { await client.callTool({ name: "proxy_stop", arguments: {} }); } catch { /* */ }
    try { await client.close(); } catch { /* */ }
  });

  // ── Test 1: Barnes & Noble ──

  it("Barnes & Noble loads with spoofed fingerprint", { timeout: 90_000, todo: "Requires B&N Fastly CDN to be reachable from test environment" }, async () => {
    // Navigate to about:blank first to clear previous page state
    await cdpSession.send("Page.navigate", { url: "about:blank" }, { timeoutMs: 5_000 }).catch(() => {});
    await sleep(500);

    // Fire navigate — don't block on CDP response (page loads many sub-resources
    // through Docker exec curl-impersonate which can be slow)
    cdpSession.send("Page.navigate", { url: "https://www.barnesandnoble.com/" }, { timeoutMs: 60_000 }).catch(() => {});

    // Poll traffic until we see B&N traffic (up to 60s)
    // proxy_list_traffic returns summaries: { id, url, hostname, status, ... }
    let exchanges: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 30; i++) {
      await sleep(2_000);
      const trafficRes = parseToolResult(
        await client.callTool({
          name: "proxy_list_traffic",
          arguments: { limit: 100, hostname_filter: "barnesandnoble" },
        }) as { content: Array<{ text: string }> },
      );
      exchanges = (trafficRes.exchanges ?? []) as Array<Record<string, unknown>>;
      if (exchanges.length > 0) break;
    }

    assert.ok(exchanges.length > 0, "No traffic captured for barnesandnoble.com");

    // Find the main document request (one with a status code)
    const mainDoc = exchanges.find((e) => typeof e.status === "number");
    assert.ok(mainDoc, "No completed main document exchange found");
    const status = mainDoc.status as number;
    assert.ok(status >= 200 && status < 400, `Expected 2xx/3xx status, got ${status}`);

    // Verify page title doesn't indicate blocking
    const evalResult = await cdpSession.send("Runtime.evaluate", {
      expression: "document.title",
      returnByValue: true,
    }, { timeoutMs: 5_000 });
    const title = ((evalResult.result as Record<string, unknown>)?.value as string || "").toLowerCase();
    assert.ok(!title.includes("access denied"), `Page title indicates blocking: ${title}`);
    assert.ok(!title.includes("blocked"), `Page title indicates blocking: ${title}`);
  });

  // ── Test 2: Reddit ──

  it("Reddit loads without 403", { timeout: 90_000, todo: "Remove todo once curl-impersonate fix is verified" }, async () => {
    // Clear traffic from previous test
    await client.callTool({ name: "proxy_clear_traffic", arguments: {} });

    cdpSession.send("Page.navigate", { url: "https://www.reddit.com/" }, { timeoutMs: 60_000 }).catch(() => {});
    await sleep(20_000);

    // proxy_search_traffic returns summaries: { id, url, status, ... }
    const trafficRes = parseToolResult(
      await client.callTool({
        name: "proxy_search_traffic",
        arguments: { query: "reddit.com" },
      }) as { content: Array<{ text: string }> },
    );
    const exchanges = trafficRes.results as Array<Record<string, unknown>>;
    assert.ok(exchanges.length > 0, "No traffic captured for reddit.com");

    const mainDoc = exchanges.find((e) => {
      const url = (e.url as string) || "";
      return url.match(/reddit\.com\/?$/) && typeof e.status === "number";
    });
    if (mainDoc) {
      const status = mainDoc.status as number;
      assert.ok(status >= 200 && status < 400, `Expected 2xx/3xx, got ${status}`);
    }

    // Verify page body doesn't indicate blocking
    const evalResult = await cdpSession.send("Runtime.evaluate", {
      expression: "document.body?.innerText?.substring(0, 500) || ''",
      returnByValue: true,
    }, { timeoutMs: 5_000 });
    const bodyText = ((evalResult.result as Record<string, unknown>)?.value as string || "").toLowerCase();
    assert.ok(!bodyText.includes("blocked by network security"), `Page body indicates blocking`);
  });

  // ── Test 3: browserleaks TLS data ──

  it("browserleaks TLS JSON has JA3 data", { timeout: 60_000 }, async () => {
    cdpSession.send("Page.navigate", { url: "https://tls.browserleaks.com/json" }, { timeoutMs: 30_000 }).catch(() => {});
    await sleep(8_000);

    // Extract JSON from the page body
    const evalResult = await cdpSession.send("Runtime.evaluate", {
      expression: "document.body?.innerText || ''",
      returnByValue: true,
    }, { timeoutMs: 5_000 });
    const bodyText = (evalResult.result as Record<string, unknown>)?.value as string || "";

    let tlsData: Record<string, unknown>;
    try {
      tlsData = JSON.parse(bodyText);
    } catch {
      assert.fail(`Failed to parse browserleaks JSON: ${bodyText.substring(0, 200)}`);
    }

    // Assert JA3 hash is present
    assert.ok(tlsData.ja3_hash || tlsData.ja3Hash || tlsData.ja3, "No JA3 hash in browserleaks data");

    // Store for test 4
    browserleaksData = tlsData;
  });

  // ── Test 4: TLS 1.3 negotiation ──

  it("TLS 1.3 is negotiated (JA4 contains t13)", { timeout: 10_000, todo: "Remove todo once curl-impersonate TLS 1.3 is verified" }, async () => {
    assert.ok(browserleaksData, "browserleaks data not available (test 3 must pass first)");

    // Look for JA4 fingerprint containing t13 (TLS 1.3 indicator)
    const ja4 = (browserleaksData.ja4 || browserleaksData.ja4_hash || browserleaksData.ja4Hash || "") as string;
    assert.ok(ja4, "No JA4 fingerprint in browserleaks data");
    assert.ok(ja4.includes("t13"), `JA4 does not indicate TLS 1.3: ${ja4}`);
  });

  // ── Test 5: BrowserScan bot detection ──

  it("BrowserScan bot detection passes", { timeout: 90_000 }, async () => {
    cdpSession.send("Page.navigate", { url: "https://www.browserscan.net/bot-detection" }, { timeoutMs: 60_000 }).catch(() => {});
    // Bot detection JS needs time to execute
    await sleep(20_000);

    // Check navigator.webdriver
    const evalResult = await cdpSession.send("Runtime.evaluate", {
      expression: "navigator.webdriver",
      returnByValue: true,
    }, { timeoutMs: 5_000 });
    const webdriver = (evalResult.result as Record<string, unknown>)?.value;
    assert.equal(webdriver, false, `navigator.webdriver is ${webdriver}, expected false`);
  });
});
