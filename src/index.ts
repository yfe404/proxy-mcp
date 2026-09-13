#!/usr/bin/env node
/**
 * Proxy MCP Server — entry point.
 *
 * HTTPS MITM proxy via mockttp with lifecycle/rules/traffic/TLS/interceptors/session tools and resources.
 * Browser automation via cloakbrowser (stealth Chromium, Playwright API).
 * Tools organized into 10 modules:
 *   lifecycle, upstream, rules, traffic, modification, tls, interceptors, devtools, sessions, humanizer
 *
 * Transports:
 *   --transport stdio   (default) communicate over stdin/stdout
 *   --transport http    Streamable HTTP on --port (default 3001)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { startHttp } from "./http-server.js";

import { registerLifecycleTools } from "./tools/lifecycle.js";
import { registerUpstreamTools } from "./tools/upstream.js";
import { registerRuleTools } from "./tools/rules.js";
import { registerTrafficTools } from "./tools/traffic.js";
import { registerModificationTools } from "./tools/modification.js";
import { registerTlsTools } from "./tools/tls.js";
import { registerInterceptorTools } from "./tools/interceptors.js";
import { registerDevToolsTools } from "./tools/devtools.js";
import { registerSessionTools } from "./tools/sessions.js";
import { registerHumanizerTools } from "./tools/humanizer.js";
import { registerResources } from "./resources.js";
import { initInterceptors } from "./interceptors/init.js";

/* ------------------------------------------------------------------ */
/*  CLI helpers                                                        */
/* ------------------------------------------------------------------ */

function arg(name: string, fallback: string): string {
  const prefix = `--${name}=`;
  const found = process.argv.find((a) => a.startsWith(prefix));
  if (found) return found.slice(prefix.length);

  const idx = process.argv.indexOf(`--${name}`);
  if (idx !== -1 && idx + 1 < process.argv.length) return process.argv[idx + 1];

  return process.env[name.toUpperCase().replace(/-/g, "_")] ?? fallback;
}

/* ------------------------------------------------------------------ */
/*  Server factory                                                     */
/* ------------------------------------------------------------------ */

function createMcpServer(): McpServer {
  const server = new McpServer({ name: "proxy", version: "3.5.3" });

  initInterceptors();

  registerLifecycleTools(server);
  registerUpstreamTools(server);
  registerRuleTools(server);
  registerTrafficTools(server);
  registerModificationTools(server);
  registerTlsTools(server);
  registerInterceptorTools(server);
  registerDevToolsTools(server);
  registerSessionTools(server);
  registerHumanizerTools(server);
  registerResources(server);

  return server;
}

/* ------------------------------------------------------------------ */
/*  Stdio transport                                                    */
/* ------------------------------------------------------------------ */

async function startStdio() {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

async function main() {
  const transport = arg("transport", "stdio");

  if (transport === "stdio") {
    await startStdio();
  } else if (transport === "http") {
    const port = parseInt(arg("port", "3001"), 10);
    const handle = await startHttp(port, createMcpServer);
    console.error(`Proxy MCP server (Streamable HTTP) listening on http://127.0.0.1:${handle.port}/mcp`);
    process.on("SIGINT", async () => {
      console.error("Shutting down…");
      await handle.close().catch(() => {});
      process.exit(0);
    });
  } else {
    console.error(`Unknown transport: ${transport}. Use "stdio" or "http".`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
