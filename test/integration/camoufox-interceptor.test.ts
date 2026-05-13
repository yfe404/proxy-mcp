/**
 * Integration test for the Camoufox interceptor.
 *
 * Skipped automatically if `python3 -c 'import camoufox'` fails on the host.
 *
 * Verifies end-to-end:
 *   - launch_server spawns and emits a wsUrl
 *   - Playwright firefox.connect(wsUrl) succeeds
 *   - a real navigation through the proxy is captured by proxy_list_traffic
 *   - close cleans up the launcher dir and the python process
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

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
import { registerCamoufoxTools } from "../../src/tools/camoufox.js";
import { registerDevToolsTools } from "../../src/tools/devtools.js";
import { registerSessionTools } from "../../src/tools/sessions.js";
import { registerResources } from "../../src/resources.js";
import { initInterceptors } from "../../src/interceptors/init.js";
import { interceptorManager } from "../../src/interceptors/manager.js";
import type { CamoufoxInterceptor } from "../../src/interceptors/camoufox.js";

function camoufoxAvailable(): boolean {
  try {
    const r = spawnSync("python3", ["-c", "import camoufox"], { stdio: "ignore" });
    return r.status === 0;
  } catch {
    return false;
  }
}

function parseToolResult(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0].text);
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

const SUITE_TIMEOUT = 90_000;

describe("Camoufox interceptor (integration)", { skip: !camoufoxAvailable() ? "camoufox not installed (pip install camoufox[geoip])" : false }, () => {
  let client: Client;
  let targetId: string;
  let wsUrl: string;
  let launcherDir: string;
  let pid: number;

  before(async () => {
    const server = new McpServer({ name: "camoufox-test", version: "1.0.0" });
    initInterceptors();
    registerLifecycleTools(server);
    registerTrafficTools(server);
    registerRuleTools(server);
    registerUpstreamTools(server);
    registerModificationTools(server);
    registerTlsTools(server);
    registerInterceptorTools(server);
    registerCamoufoxTools(server);
    registerDevToolsTools(server);
    registerSessionTools(server);
    registerResources(server);

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: "camoufox-test-client", version: "1.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const startRes = parseToolResult(
      await client.callTool({ name: "proxy_start", arguments: { port: 0 } }) as { content: Array<{ text: string }> },
    );
    assert.equal(startRes.status, "success", `proxy_start failed: ${JSON.stringify(startRes)}`);
  });

  after(async () => {
    if (targetId) {
      try {
        await client.callTool({ name: "interceptor_camoufox_close", arguments: { target_id: targetId } });
      } catch { /* */ }
    }
    try { await client.callTool({ name: "proxy_stop", arguments: {} }); } catch { /* */ }
    try { await client.close(); } catch { /* */ }
    setTimeout(() => process.exit(0), 1_000);
  });

  it("launches camoufox and emits a wsUrl", { timeout: SUITE_TIMEOUT }, async () => {
    const launchRes = parseToolResult(
      await client.callTool({
        name: "interceptor_camoufox_launch",
        arguments: { headless: true, humanize: false, geoip: false, trust_proxy_cert: true },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(launchRes.status, "success", `launch failed: ${JSON.stringify(launchRes)}`);
    targetId = launchRes.targetId as string;
    wsUrl = launchRes.wsUrl as string;
    assert.match(targetId, /^camoufox_\d+_\d+$/);
    assert.match(wsUrl, /^ws:\/\//);

    const fox = interceptorManager.get("camoufox") as CamoufoxInterceptor;
    const entry = fox.getEntry(targetId)!;
    launcherDir = entry.launcherDir;
    pid = entry.process.pid as number;
    assert.ok(existsSync(launcherDir), "launcher dir should exist after launch");
    assert.ok(pidAlive(pid), "python launcher should be alive after launch");
  });

  it("drives the camoufox target via interceptor_browser_navigate and routes traffic through the proxy", { timeout: SUITE_TIMEOUT }, async () => {
    const beforeRes = parseToolResult(
      await client.callTool({ name: "proxy_list_traffic", arguments: {} }) as { content: Array<{ text: string }> },
    );
    const beforeCount = ((beforeRes.exchanges as unknown[]) ?? []).length;

    const navRes = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_navigate",
        arguments: {
          target_id: targetId,
          url: "https://example.com",
          wait_until: "domcontentloaded",
          timeout_ms: 30_000,
          wait_for_proxy_capture: true,
        },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(navRes.status, "success", `navigate failed: ${JSON.stringify(navRes)}`);
    assert.equal(navRes.http_status, 200, `expected 200 from example.com, got ${JSON.stringify(navRes)}`);

    const afterRes = parseToolResult(
      await client.callTool({ name: "proxy_list_traffic", arguments: {} }) as { content: Array<{ text: string }> },
    );
    const exchanges = (afterRes.exchanges as Array<{ hostname: string; status: number | null }>) ?? [];
    assert.ok(exchanges.length > beforeCount, `expected new proxy traffic; before=${beforeCount} after=${exchanges.length}`);
    const example = exchanges.find((t) => t.hostname === "example.com");
    assert.ok(example, "expected an example.com entry in proxy traffic");
    void wsUrl;
  });

  it("closes the instance and cleans up", { timeout: SUITE_TIMEOUT }, async () => {
    const closeRes = parseToolResult(
      await client.callTool({ name: "interceptor_camoufox_close", arguments: { target_id: targetId } }) as { content: Array<{ text: string }> },
    );
    assert.equal(closeRes.status, "success", `close failed: ${JSON.stringify(closeRes)}`);

    // give the OS a beat to drain the dir removal
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(existsSync(launcherDir), false, "launcher dir should be removed after close");
    assert.equal(pidAlive(pid), false, "python launcher should be gone after close");

    targetId = "";
  });
});
