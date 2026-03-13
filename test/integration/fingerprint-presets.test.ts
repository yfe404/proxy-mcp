/**
 * Integration tests for fingerprint spoofing presets via impit.
 *
 * Requirements: internet access (hits tls.peet.ws), curl on PATH.
 *
 * Verifies that each preset produces the expected TLS fingerprint and
 * User-Agent when proxied through impit.
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

// ── Helpers ──

function parseToolResult(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0].text);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Enable a preset, spawn curl to tls.peet.ws, and return the parsed
 * TLS fingerprint JSON via persistent session full-body capture.
 */
async function fetchFingerprintWithPreset(
  client: Client,
  sessionId: string,
  preset: string,
): Promise<Record<string, unknown>> {
  // Set preset
  const spoofRes = parseToolResult(
    await client.callTool({
      name: "proxy_set_fingerprint_spoof",
      arguments: { preset },
    }) as { content: Array<{ text: string }> },
  );
  assert.equal(spoofRes.status, "success", `spoof failed for ${preset}: ${JSON.stringify(spoofRes)}`);

  // Clear traffic
  await client.callTool({ name: "proxy_clear_traffic", arguments: {} });

  // Spawn curl
  const spawnRes = parseToolResult(
    await client.callTool({
      name: "interceptor_spawn",
      arguments: { command: "curl", args: ["-s", "https://tls.peet.ws/api/all"] },
    }) as { content: Array<{ text: string }> },
  );
  assert.equal(spawnRes.status, "success", `spawn failed for ${preset}`);

  // Wait for traffic to appear
  let exchangeId: string | undefined;
  for (let i = 0; i < 15; i++) {
    await sleep(1_000);
    const searchRes = parseToolResult(
      await client.callTool({
        name: "proxy_search_traffic",
        arguments: { query: "tls.peet.ws" },
      }) as { content: Array<{ text: string }> },
    );
    const results = searchRes.results as Array<Record<string, unknown>>;
    const completed = results.find((r) => typeof r.status === "number");
    if (completed) {
      exchangeId = completed.id as string;
      break;
    }
  }
  assert.ok(exchangeId, `No completed exchange for preset ${preset}`);

  // Retrieve full body from session (not truncated like bodyPreview)
  const sessionExRes = parseToolResult(
    await client.callTool({
      name: "proxy_get_session_exchange",
      arguments: { session_id: sessionId, exchange_id: exchangeId, include_body: true },
    }) as { content: Array<{ text: string }> },
  );
  assert.equal(sessionExRes.status, "success", `session exchange failed for ${preset}`);
  const record = sessionExRes.record as Record<string, unknown>;
  const responseBody = (record.responseBodyText as string) || "";
  assert.ok(responseBody.length > 0, `Empty response body for preset ${preset}`);
  return JSON.parse(responseBody);
}

// ── Test suite ──

describe("Fingerprint Preset Spoofing", () => {
  let client: Client;
  let sessionId: string;

  before(async () => {
    const server = new McpServer({ name: "preset-test", version: "1.0.0" });
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
    client = new Client({ name: "preset-test-client", version: "1.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    // Start proxy with full-body session capture
    const startRes = parseToolResult(
      await client.callTool({
        name: "proxy_start",
        arguments: { port: 0, persistence_enabled: true, capture_profile: "full" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(startRes.status, "success", `proxy_start failed: ${JSON.stringify(startRes)}`);

    // Get session ID
    const persistence = startRes.persistence as Record<string, unknown>;
    sessionId = persistence.sessionId as string;
    assert.ok(sessionId, "No session ID returned");
  });

  after(async () => {
    try { await client.callTool({ name: "proxy_clear_ja3_spoof", arguments: {} }); } catch { /* */ }
    try { await client.callTool({ name: "proxy_session_stop", arguments: {} }); } catch { /* */ }
    try { await client.callTool({ name: "proxy_stop", arguments: {} }); } catch { /* */ }
    try { await client.close(); } catch { /* */ }
    // impit's native connection pool keeps the event loop alive
    setTimeout(() => process.exit(0), 1_000);
  });

  // ── Chrome presets ──

  it("chrome_131 produces Chrome TLS 1.3 fingerprint", { timeout: 30_000 }, async () => {
    const data = await fetchFingerprintWithPreset(client, sessionId, "chrome_131");
    const tls = data.tls as Record<string, unknown>;
    assert.ok(tls.ja3_hash, "No JA3 hash");
    assert.equal(tls.tls_version_negotiated, "772", "Expected TLS 1.3 (772)");
    assert.ok((data.user_agent as string).includes("Chrome/131"));
    const h2 = data.http2 as Record<string, unknown>;
    assert.ok((h2.akamai_fingerprint as string).endsWith("|m,a,s,p"), "Expected Chrome pseudo-header order m,a,s,p");
  });

  it("chrome_136 produces Chrome TLS 1.3 fingerprint", { timeout: 30_000 }, async () => {
    const data = await fetchFingerprintWithPreset(client, sessionId, "chrome_136");
    const tls = data.tls as Record<string, unknown>;
    assert.equal(tls.tls_version_negotiated, "772", "Expected TLS 1.3 (772)");
    assert.ok((data.user_agent as string).includes("Chrome/136"));
    const h2 = data.http2 as Record<string, unknown>;
    assert.ok((h2.akamai_fingerprint as string).endsWith("|m,a,s,p"), "Expected Chrome pseudo-header order m,a,s,p");
  });

  // ── Firefox preset ──

  it("firefox_133 produces Firefox TLS fingerprint", { timeout: 30_000 }, async () => {
    const data = await fetchFingerprintWithPreset(client, sessionId, "firefox_133");
    const tls = data.tls as Record<string, unknown>;
    assert.ok(tls.ja3_hash, "No JA3 hash");
    assert.ok((data.user_agent as string).includes("Firefox/133"));
    const h2 = data.http2 as Record<string, unknown>;
    // Real Firefox uses m,p,a,s pseudo-header order (not Chrome's m,a,s,p)
    assert.ok((h2.akamai_fingerprint as string).endsWith("|m,p,a,s"), "Expected Firefox pseudo-header order m,p,a,s");
  });

  // ── OkHttp presets ──

  it("okhttp3 produces OkHttp3 TLS 1.2 fingerprint", { timeout: 30_000 }, async () => {
    const data = await fetchFingerprintWithPreset(client, sessionId, "okhttp3");
    const tls = data.tls as Record<string, unknown>;
    assert.equal(tls.tls_version_negotiated, "771", "Expected TLS 1.2 (771) for OkHttp3");
    assert.equal(data.user_agent, "okhttp/3.14.9");
    const h2 = data.http2 as Record<string, unknown>;
    assert.ok((h2.akamai_fingerprint as string).endsWith("|m,p,a,s"), "Expected OkHttp pseudo-header order m,p,a,s");
  });

  it("okhttp4 produces OkHttp4 TLS 1.3 fingerprint", { timeout: 30_000 }, async () => {
    const data = await fetchFingerprintWithPreset(client, sessionId, "okhttp4");
    const tls = data.tls as Record<string, unknown>;
    assert.equal(tls.tls_version_negotiated, "772", "Expected TLS 1.3 (772) for OkHttp4");
    assert.equal(data.user_agent, "okhttp/4.12.0");
    const h2 = data.http2 as Record<string, unknown>;
    assert.ok((h2.akamai_fingerprint as string).endsWith("|m,p,a,s"), "Expected OkHttp pseudo-header order m,p,a,s");
  });

  it("okhttp5 produces OkHttp5 TLS 1.3 fingerprint", { timeout: 30_000 }, async () => {
    const data = await fetchFingerprintWithPreset(client, sessionId, "okhttp5");
    const tls = data.tls as Record<string, unknown>;
    assert.equal(tls.tls_version_negotiated, "772", "Expected TLS 1.3 (772) for OkHttp5");
    assert.equal(data.user_agent, "okhttp/5.0.0");
    const h2 = data.http2 as Record<string, unknown>;
    assert.ok((h2.akamai_fingerprint as string).endsWith("|m,p,a,s"), "Expected OkHttp pseudo-header order m,p,a,s");
  });

  // ── Cross-preset: JA3 differs between families ──

  it("okhttp3 JA3 differs from okhttp4/5 (TLS 1.2 vs 1.3)", { timeout: 60_000 }, async () => {
    const data3 = await fetchFingerprintWithPreset(client, sessionId, "okhttp3");
    const data4 = await fetchFingerprintWithPreset(client, sessionId, "okhttp4");
    const ja3_3 = (data3.tls as Record<string, unknown>).ja3_hash as string;
    const ja3_4 = (data4.tls as Record<string, unknown>).ja3_hash as string;
    assert.notEqual(ja3_3, ja3_4, "OkHttp3 and OkHttp4 should have different JA3 (TLS 1.2 vs 1.3)");
  });
});
