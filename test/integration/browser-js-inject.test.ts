/**
 * Integration tests for the browser JS execution / injection tools:
 *   - interceptor_browser_evaluate
 *   - interceptor_browser_inject_init_script
 *   - interceptor_browser_add_script_tag
 *
 * Drives both backends end-to-end through the MCP server with an in-memory
 * transport. Auto-skips when the corresponding backend is unavailable.
 *
 * Uses `data:` URLs to avoid network requirements; navigation goes through
 * `interceptor_browser_navigate` with `wait_for_proxy_capture: false`
 * because data: URLs do not traverse the proxy.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

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

const PAGE_HTML = "data:text/html,<html><head><title>probe</title></head><body><h1 id=hello>hi</h1></body></html>";
const SUITE_TIMEOUT = 90_000;

function parseToolResult(result: { content: Array<{ text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0].text);
}

async function cloakbrowserAvailable(): Promise<boolean> {
  try {
    await import("cloakbrowser");
    return true;
  } catch {
    return false;
  }
}

function camoufoxAvailable(): boolean {
  try {
    const r = spawnSync("python3", ["-c", "import camoufox"], { stdio: "ignore" });
    return r.status === 0;
  } catch {
    return false;
  }
}

async function setupMcp(): Promise<{ client: Client; cleanup: () => Promise<void> }> {
  const server = new McpServer({ name: "js-inject-test", version: "1.0.0" });
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
  const client = new Client({ name: "js-inject-test-client", version: "1.0.0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const startRes = parseToolResult(
    await client.callTool({ name: "proxy_start", arguments: { port: 0 } }) as { content: Array<{ text: string }> },
  );
  assert.equal(startRes.status, "success", `proxy_start failed: ${JSON.stringify(startRes)}`);

  return {
    client,
    cleanup: async () => {
      try { await client.callTool({ name: "proxy_stop", arguments: {} }); } catch { /* */ }
      try { await client.close(); } catch { /* */ }
    },
  };
}

interface ScriptFile { path: string; cleanup: () => Promise<void> }

async function makeScript(body: string): Promise<ScriptFile> {
  const dir = await mkdtemp(join(tmpdir(), "proxy-mcp-jsinject-"));
  const path = join(dir, "script.js");
  await writeFile(path, body, "utf-8");
  return { path, cleanup: async () => { await rm(dir, { recursive: true, force: true }).catch(() => {}); } };
}

async function navigateToProbe(client: Client, targetId: string): Promise<void> {
  const r = parseToolResult(
    await client.callTool({
      name: "interceptor_browser_navigate",
      arguments: {
        target_id: targetId,
        url: PAGE_HTML,
        wait_until: "domcontentloaded",
        wait_for_proxy_capture: false,
        timeout_ms: 10_000,
      },
    }) as { content: Array<{ text: string }> },
  );
  assert.equal(r.status, "success", `navigate failed: ${JSON.stringify(r)}`);
}

// ── Cloakbrowser ──────────────────────────────────────────────────

const cloakOk = await cloakbrowserAvailable();
describe("Browser JS inject tools — cloakbrowser", {
  skip: !cloakOk ? "cloakbrowser not installed" : false,
}, () => {
  let client: Client;
  let cleanup: () => Promise<void>;
  let targetId: string;
  const scripts: ScriptFile[] = [];

  before(async () => {
    ({ client, cleanup } = await setupMcp());
    const launchRes = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_launch",
        arguments: { headless: true, humanize: false },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(launchRes.status, "success", `browser launch failed: ${JSON.stringify(launchRes)}`);
    targetId = launchRes.targetId as string;
    await navigateToProbe(client, targetId);
  });

  after(async () => {
    for (const s of scripts) await s.cleanup();
    try { await client.callTool({ name: "interceptor_browser_close", arguments: { target_id: targetId } }); } catch { /* */ }
    await cleanup();
  });

  it("evaluate returns JSON-serialisable value with args", { timeout: SUITE_TIMEOUT }, async () => {
    const s = await makeScript("return { title: document.title, n: __args.n + 1 };");
    scripts.push(s);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: s.path, args: { n: 41 } },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "success", JSON.stringify(r));
    assert.equal(r.backend, "cloakbrowser");
    assert.equal(r.world, "isolated");
    const parsed = JSON.parse(r.value as string) as { title: string; n: number };
    assert.equal(parsed.title, "probe");
    assert.equal(parsed.n, 42);
  });

  it("evaluate rejects non-absolute script_path", { timeout: SUITE_TIMEOUT }, async () => {
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: "relative/path.js" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "error");
    assert.match(String(r.error), /absolute/);
  });

  it("evaluate world='main' on cloakbrowser returns a helpful error", { timeout: SUITE_TIMEOUT }, async () => {
    const s = await makeScript("return 1;");
    scripts.push(s);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: s.path, world: "main" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "error");
    assert.match(String(r.error), /camoufox/i);
  });

  it("inject_init_script patches survive across navigations (visible to subsequent evaluate)", { timeout: SUITE_TIMEOUT }, async () => {
    const hook = await makeScript("Object.defineProperty(navigator, 'webdriver', { configurable: true, get: () => 'patched' });");
    scripts.push(hook);
    const injectRes = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_inject_init_script",
        arguments: { target_id: targetId, script_path: hook.path },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(injectRes.status, "success", JSON.stringify(injectRes));

    await navigateToProbe(client, targetId);

    const probe = await makeScript("return { wd: navigator.webdriver };");
    scripts.push(probe);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: probe.path },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "success", JSON.stringify(r));
    const parsed = JSON.parse(r.value as string) as { wd: string };
    // On cloakbrowser, init scripts apply to the page's world — evaluate sees the patched value.
    assert.equal(parsed.wd, "patched", `cloakbrowser addInitScript should reach evaluate's world: got ${JSON.stringify(parsed)}`);
  });

  it("add_script_tag appends a script and the body executes (visible to evaluate)", { timeout: SUITE_TIMEOUT }, async () => {
    const tag = await makeScript("window.__tag_signal = 'set-by-tag';");
    scripts.push(tag);
    const tagRes = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_add_script_tag",
        arguments: { target_id: targetId, script_path: tag.path },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(tagRes.status, "success", JSON.stringify(tagRes));

    const probe = await makeScript("return { sig: window.__tag_signal, scripts: document.scripts.length };");
    scripts.push(probe);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: probe.path },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "success", JSON.stringify(r));
    const parsed = JSON.parse(r.value as string) as { sig: string; scripts: number };
    assert.equal(parsed.sig, "set-by-tag");
    assert.ok(parsed.scripts >= 1);
  });
});

// ── Camoufox ──────────────────────────────────────────────────────

describe("Browser JS inject tools — camoufox (main_world_eval ON)", {
  skip: !camoufoxAvailable() ? "camoufox not installed (pip install camoufox[geoip])" : false,
}, () => {
  let client: Client;
  let cleanup: () => Promise<void>;
  let targetId: string;
  const scripts: ScriptFile[] = [];

  before(async () => {
    ({ client, cleanup } = await setupMcp());
    const launchRes = parseToolResult(
      await client.callTool({
        name: "interceptor_camoufox_launch",
        arguments: { headless: true, humanize: false, geoip: false, main_world_eval: true, trust_proxy_cert: false },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(launchRes.status, "success", `camoufox launch failed: ${JSON.stringify(launchRes)}`);
    targetId = launchRes.targetId as string;
    await navigateToProbe(client, targetId);
  });

  after(async () => {
    for (const s of scripts) await s.cleanup();
    try { await client.callTool({ name: "interceptor_camoufox_close", arguments: { target_id: targetId } }); } catch { /* */ }
    await cleanup();
  });

  it("evaluate isolated returns JSON + args", { timeout: SUITE_TIMEOUT }, async () => {
    const s = await makeScript("return { title: document.title, n: __args.n + 1 };");
    scripts.push(s);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: s.path, args: { n: 41 } },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "success", JSON.stringify(r));
    assert.equal(r.backend, "camoufox");
    assert.equal(r.world, "isolated");
    const parsed = JSON.parse(r.value as string) as { title: string; n: number };
    assert.equal(parsed.title, "probe");
    assert.equal(parsed.n, 42);
  });

  it("evaluate world='main' (mw:) sets a global readable by another main-world eval", { timeout: SUITE_TIMEOUT }, async () => {
    const setter = await makeScript("window.__mw_signal = 'set-by-mw'; return window.__mw_signal;");
    scripts.push(setter);
    const r1 = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: setter.path, world: "main" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r1.status, "success", JSON.stringify(r1));
    assert.equal(r1.world, "main");
    assert.equal(JSON.parse(r1.value as string), "set-by-mw");

    const reader = await makeScript("return window.__mw_signal;");
    scripts.push(reader);
    const r2 = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: reader.path, world: "main" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r2.status, "success", JSON.stringify(r2));
    assert.equal(JSON.parse(r2.value as string), "set-by-mw");
  });

  it("isolated world cannot see main-world globals (camoufox stealth boundary)", { timeout: SUITE_TIMEOUT }, async () => {
    // After the previous test sets window.__mw_signal in main world, an
    // isolated eval reads a *different* window object — the global must be absent.
    const probe = await makeScript("return { mw: window.__mw_signal };");
    scripts.push(probe);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: probe.path },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "success", JSON.stringify(r));
    const parsed = JSON.parse(r.value as string) as { mw: unknown };
    assert.ok(parsed.mw === undefined || parsed.mw === null,
      `camoufox isolated world should not see main-world global; got ${JSON.stringify(parsed)}`);
  });

  it("add_script_tag adds a DOM node visible via document.scripts", { timeout: SUITE_TIMEOUT }, async () => {
    const tag = await makeScript("/* no-op */");
    scripts.push(tag);
    const tagRes = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_add_script_tag",
        arguments: { target_id: targetId, script_path: tag.path },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(tagRes.status, "success", JSON.stringify(tagRes));

    const probe = await makeScript("return document.scripts.length;");
    scripts.push(probe);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: probe.path },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "success", JSON.stringify(r));
    assert.ok(Number(JSON.parse(r.value as string)) >= 1);
  });
});

describe("Browser JS inject tools — camoufox (main_world_eval OFF)", {
  skip: !camoufoxAvailable() ? "camoufox not installed" : false,
}, () => {
  let client: Client;
  let cleanup: () => Promise<void>;
  let targetId: string;
  const scripts: ScriptFile[] = [];

  before(async () => {
    ({ client, cleanup } = await setupMcp());
    const launchRes = parseToolResult(
      await client.callTool({
        name: "interceptor_camoufox_launch",
        arguments: { headless: true, humanize: false, geoip: false, trust_proxy_cert: false },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(launchRes.status, "success", `camoufox launch failed: ${JSON.stringify(launchRes)}`);
    targetId = launchRes.targetId as string;
    await navigateToProbe(client, targetId);
  });

  after(async () => {
    for (const s of scripts) await s.cleanup();
    try { await client.callTool({ name: "interceptor_camoufox_close", arguments: { target_id: targetId } }); } catch { /* */ }
    await cleanup();
  });

  it("evaluate world='main' returns a helpful error when main_world_eval was not enabled at launch", { timeout: SUITE_TIMEOUT }, async () => {
    const s = await makeScript("return 1;");
    scripts.push(s);
    const r = parseToolResult(
      await client.callTool({
        name: "interceptor_browser_evaluate",
        arguments: { target_id: targetId, script_path: s.path, world: "main" },
      }) as { content: Array<{ text: string }> },
    );
    assert.equal(r.status, "error");
    assert.match(String(r.error), /main_world_eval/);
  });
});
