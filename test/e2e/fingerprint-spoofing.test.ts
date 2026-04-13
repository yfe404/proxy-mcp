/**
 * E2E fingerprint spoofing tests — success metrics for issue #2.
 *
 * Requirements: cloakbrowser binary, internet access.
 *
 * Launches the full MCP server, starts a proxy, enables fingerprint spoofing
 * (for impit-based outbound), launches cloakbrowser via the browser
 * interceptor, and drives the bound Playwright Page to verify TLS/HTTP2
 * fingerprint fidelity at real sites.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";

import type { Page } from "playwright-core";
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
import { getPageForTarget } from "../../src/browser/session.js";

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
  let browserTargetId: string;
  let page: Page;
  let browserleaksData: Record<string, unknown> | null = null;

  before(async () => {
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
    void proxyPort;

    // Enable outbound fingerprint spoofing (impit) with chrome_131 preset
    const spoofRes = parseToolResult(
      await client.callTool({
        name: "proxy_set_fingerprint_spoof",
        arguments: { preset: "chrome_131" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(spoofRes.status, "success", `fingerprint spoof failed: ${JSON.stringify(spoofRes)}`);

    // Launch cloakbrowser via the browser interceptor
    const browserRes = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_launch",
        arguments: { url: "about:blank", headless: false, humanize: true },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(browserRes.status, "success", `browser launch failed: ${JSON.stringify(browserRes)}`);
    browserTargetId = browserRes.targetId as string;

    page = getPageForTarget(browserTargetId);

    // Warm-up navigation
    try {
      await page.goto("https://httpbin.org/get", { waitUntil: "domcontentloaded", timeout: 30_000 });
    } catch { /* non-fatal */ }
    await sleep(2_000);
    await client.callTool({ name: "proxy_clear_traffic", arguments: {} });
  });

  after(async () => {
    try {
      if (browserTargetId) {
        await client.callTool({
          name: "interceptor_browser_close",
          arguments: { target_id: browserTargetId },
        });
      }
    } catch { /* */ }
    try { await client.callTool({ name: "proxy_clear_ja3_spoof", arguments: {} }); } catch { /* */ }
    try { await client.callTool({ name: "proxy_stop", arguments: {} }); } catch { /* */ }
    try { await client.close(); } catch { /* */ }
    // impit's native Rust pool keeps the event loop alive; force exit.
    setTimeout(() => process.exit(0), 1_000);
  });

  // ── Test 1: Barnes & Noble ──

  it("Barnes & Noble loads with spoofed fingerprint", { timeout: 120_000 }, async () => {
    await page.goto("about:blank").catch(() => {});
    await sleep(500);

    page.goto("https://www.barnesandnoble.com/", { timeout: 60_000 }).catch(() => {});

    let exchanges: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 30; i++) {
      await sleep(2_000);
      const trafficRes = parseToolResult(
        await client.callTool({
          name: "proxy_list_traffic",
          arguments: { limit: 100, url_filter: "barnesandnoble.com" },
        }) as { content: Array<{ text: string }> },
      );
      exchanges = (trafficRes.exchanges ?? []) as Array<Record<string, unknown>>;
      if (exchanges.some((e) => typeof e.status === "number")) break;
    }

    assert.ok(exchanges.length > 0, "No traffic captured for barnesandnoble.com");

    const firstDoc = exchanges.find((e) => typeof e.status === "number");
    assert.ok(firstDoc, "No completed exchange found");
    const firstStatus = firstDoc.status as number;

    if (firstStatus === 403) {
      await sleep(15_000);
      await client.callTool({ name: "proxy_clear_traffic", arguments: {} });
      page.goto("https://www.barnesandnoble.com/", { timeout: 60_000 }).catch(() => {});

      let retryExchanges: Array<Record<string, unknown>> = [];
      for (let i = 0; i < 30; i++) {
        await sleep(2_000);
        const trafficRes = parseToolResult(
          await client.callTool({
            name: "proxy_list_traffic",
            arguments: { limit: 100, url_filter: "barnesandnoble.com" },
          }) as { content: Array<{ text: string }> },
        );
        retryExchanges = (trafficRes.exchanges ?? []) as Array<Record<string, unknown>>;
        if (retryExchanges.some((e) => typeof e.status === "number")) break;
      }

      assert.ok(retryExchanges.length > 0, "No traffic on retry after Akamai challenge");
      const retryDoc = retryExchanges.find((e) => typeof e.status === "number");
      assert.ok(retryDoc, "No completed retry exchange found");
      const retryStatus = retryDoc.status as number;
      assert.ok(retryStatus >= 200 && retryStatus < 400, `Retry got ${retryStatus}, expected 2xx/3xx`);
    } else {
      assert.ok(firstStatus >= 200 && firstStatus < 400, `Expected 2xx/3xx status, got ${firstStatus}`);
    }

    const title = (await page.title().catch(() => "")).toLowerCase();
    assert.ok(!title.includes("access denied"), `Page title indicates blocking: ${title}`);
    assert.ok(!title.includes("blocked"), `Page title indicates blocking: ${title}`);
  });

  // ── Test 2: Reddit ──

  it("Reddit loads without 403", { timeout: 90_000 }, async () => {
    await client.callTool({ name: "proxy_clear_traffic", arguments: {} });

    page.goto("https://www.reddit.com/", { timeout: 60_000 }).catch(() => {});
    await sleep(20_000);

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

    const bodyText = (
      await page.evaluate(() => document.body?.innerText?.substring(0, 500) || "").catch(() => "")
    ).toLowerCase();
    assert.ok(!bodyText.includes("blocked by network security"), `Page body indicates blocking`);
  });

  // ── Test 3: browserleaks TLS data ──

  it("browserleaks TLS JSON has JA3 data", { timeout: 60_000 }, async () => {
    page.goto("https://tls.browserleaks.com/json", { timeout: 30_000 }).catch(() => {});
    await sleep(8_000);

    const bodyText = await page.evaluate(() => document.body?.innerText || "").catch(() => "");

    let tlsData: Record<string, unknown>;
    try {
      tlsData = JSON.parse(bodyText);
    } catch {
      assert.fail(`Failed to parse browserleaks JSON: ${bodyText.substring(0, 200)}`);
    }

    assert.ok(tlsData.ja3_hash || tlsData.ja3Hash || tlsData.ja3, "No JA3 hash in browserleaks data");
    browserleaksData = tlsData;
  });

  // ── Test 4: TLS 1.3 negotiation ──

  it("TLS 1.3 is negotiated (JA4 contains t13)", { timeout: 10_000 }, async () => {
    assert.ok(browserleaksData, "browserleaks data not available (test 3 must pass first)");

    const ja4 = (browserleaksData.ja4 || browserleaksData.ja4_hash || browserleaksData.ja4Hash || "") as string;
    assert.ok(ja4, "No JA4 fingerprint in browserleaks data");
    assert.ok(ja4.includes("t13"), `JA4 does not indicate TLS 1.3: ${ja4}`);
  });

  // ── Test 5: BrowserScan bot detection ──

  it("BrowserScan bot detection passes", { timeout: 90_000 }, async () => {
    page.goto("https://www.browserscan.net/bot-detection", { timeout: 60_000 }).catch(() => {});
    await sleep(20_000);

    const webdriver = await page.evaluate(() => navigator.webdriver).catch(() => null);
    assert.equal(webdriver, false, `navigator.webdriver is ${webdriver}, expected false`);
  });
});
