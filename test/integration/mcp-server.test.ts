import { describe, it, afterEach } from "node:test";
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
import { registerResources } from "../../src/resources.js";
import { initInterceptors } from "../../src/interceptors/init.js";

async function createTestSetup() {
  const server = new McpServer({ name: "proxy-test", version: "1.0.0" });
  initInterceptors();
  registerLifecycleTools(server);
  registerTrafficTools(server);
  registerRuleTools(server);
  registerUpstreamTools(server);
  registerModificationTools(server);
  registerTlsTools(server);
  registerInterceptorTools(server);
  registerResources(server);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0.0" });

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  return { server, client, cleanup: async () => {
    // Stop proxy if running
    try { await client.callTool({ name: "proxy_stop", arguments: {} }); } catch {}
    await client.close();
  }};
}

describe("MCP Server Integration", () => {
  let cleanup: () => Promise<void>;

  afterEach(async () => {
    if (cleanup) await cleanup();
  });

  it("lists all 44 tools", async () => {
    const { client, cleanup: c } = await createTestSetup();
    cleanup = c;

    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();

    assert.ok(names.includes("proxy_start"));
    assert.ok(names.includes("proxy_stop"));
    assert.ok(names.includes("proxy_status"));
    assert.ok(names.includes("proxy_get_ca_cert"));
    assert.ok(names.includes("proxy_set_upstream"));
    assert.ok(names.includes("proxy_add_rule"));
    assert.ok(names.includes("proxy_list_traffic"));
    assert.ok(names.includes("proxy_inject_headers"));
    // TLS tools
    assert.ok(names.includes("proxy_get_tls_fingerprints"));
    assert.ok(names.includes("proxy_list_tls_fingerprints"));
    assert.ok(names.includes("proxy_set_ja3_spoof"));
    assert.ok(names.includes("proxy_clear_ja3_spoof"));
    assert.ok(names.includes("proxy_get_tls_config"));
    assert.ok(names.includes("proxy_enable_server_tls_capture"));
    // Interceptor tools
    assert.ok(names.includes("interceptor_list"));
    assert.ok(names.includes("interceptor_status"));
    assert.ok(names.includes("interceptor_deactivate_all"));
    assert.ok(names.includes("interceptor_chrome_launch"));
    assert.ok(names.includes("interceptor_chrome_cdp_info"));
    assert.ok(names.includes("interceptor_spawn"));
    assert.ok(names.includes("interceptor_android_devices"));
    assert.ok(names.includes("interceptor_frida_apps"));
    assert.ok(names.includes("interceptor_docker_attach"));
    assert.equal(names.length, 44);
  });

  it("start/status/stop lifecycle via MCP", async (t) => {
    const { client, cleanup: c } = await createTestSetup();
    cleanup = c;

    // Start
    const startResult = await client.callTool({ name: "proxy_start", arguments: { port: 0 } });
    const startData = JSON.parse((startResult.content as Array<{ text: string }>)[0].text);
    if (startData.status !== "success") {
      const err = String(startData.error ?? "");
      if (/EPERM|EACCES/i.test(err)) {
        t.skip("listen() not permitted in this environment");
        return;
      }
    }
    assert.equal(startData.status, "success");
    assert.ok(startData.port > 0);

    // Status
    const statusResult = await client.callTool({ name: "proxy_status", arguments: {} });
    const statusData = JSON.parse((statusResult.content as Array<{ text: string }>)[0].text);
    assert.equal(statusData.running, true);
    assert.equal(statusData.port, startData.port);

    // Cert
    const certResult = await client.callTool({ name: "proxy_get_ca_cert", arguments: { format: "both" } });
    const certData = JSON.parse((certResult.content as Array<{ text: string }>)[0].text);
    assert.ok(certData.certPem.includes("BEGIN CERTIFICATE"));
    assert.ok(certData.fingerprint.length > 0);

    // Stop
    const stopResult = await client.callTool({ name: "proxy_stop", arguments: {} });
    const stopData = JSON.parse((stopResult.content as Array<{ text: string }>)[0].text);
    assert.equal(stopData.status, "success");
  });

  it("lists resources", async () => {
    const { client, cleanup: c } = await createTestSetup();
    cleanup = c;

    const { resources } = await client.listResources();
    const uris = resources.map((r) => r.uri);
    assert.ok(uris.includes("proxy://status"));
    assert.ok(uris.includes("proxy://ca-cert"));
    assert.ok(uris.includes("proxy://traffic/summary"));
    assert.ok(uris.includes("proxy://interceptors"));
    assert.ok(uris.includes("proxy://chrome/targets"));
  });
});
