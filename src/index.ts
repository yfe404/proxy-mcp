/**
 * Proxy MCP Server — entry point.
 *
 * HTTPS MITM proxy via mockttp with lifecycle/rules/traffic/TLS/interceptors/session tools and resources.
 * Tools organized into 7 modules:
 *   lifecycle, upstream, rules, traffic, modification, tls, interceptors
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerLifecycleTools } from "./tools/lifecycle.js";
import { registerUpstreamTools } from "./tools/upstream.js";
import { registerRuleTools } from "./tools/rules.js";
import { registerTrafficTools } from "./tools/traffic.js";
import { registerModificationTools } from "./tools/modification.js";
import { registerTlsTools } from "./tools/tls.js";
import { registerInterceptorTools } from "./tools/interceptors.js";
import { registerSessionTools } from "./tools/sessions.js";
import { registerResources } from "./resources.js";
import { initInterceptors } from "./interceptors/init.js";

async function main() {
  const server = new McpServer({
    name: "proxy",
    version: "1.0.0",
  });

  // Initialize interceptor registry
  initInterceptors();

  // Register all tool modules
  registerLifecycleTools(server);
  registerUpstreamTools(server);
  registerRuleTools(server);
  registerTrafficTools(server);
  registerModificationTools(server);
  registerTlsTools(server);
  registerInterceptorTools(server);
  registerSessionTools(server);

  // Register resources
  registerResources(server);

  // Connect via stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
