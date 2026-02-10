/**
 * Upstream proxy tools — configure SOCKS/HTTP proxies for outgoing traffic.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";

export function registerUpstreamTools(server: McpServer): void {
  server.tool(
    "proxy_set_upstream",
    "Set a global upstream proxy for all outgoing traffic. Supports socks4://, socks5://, http://, https://, and pac+http:// URLs.",
    {
      proxy_url: z.string().describe("Upstream proxy URL (e.g., socks5://user:pass@host:port)"),
      no_proxy: z.array(z.string()).optional().describe("Hostnames to bypass the upstream proxy"),
    },
    async ({ proxy_url, no_proxy }) => {
      try {
        await proxyManager.setGlobalUpstream({ proxyUrl: proxy_url, noProxy: no_proxy });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              message: `Global upstream set to ${proxy_url}`,
              noProxy: no_proxy || [],
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_clear_upstream",
    "Remove the global upstream proxy. Traffic will go directly to target servers.",
    {},
    async () => {
      try {
        await proxyManager.clearGlobalUpstream();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: "Global upstream cleared." }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_set_host_upstream",
    "Set a per-host upstream proxy override. Traffic to this hostname will use the specified proxy instead of the global one.",
    {
      hostname: z.string().describe("Hostname to override (e.g., api.example.com)"),
      proxy_url: z.string().describe("Upstream proxy URL for this host"),
      no_proxy: z.array(z.string()).optional().describe("Hostnames to bypass this proxy"),
    },
    async ({ hostname, proxy_url, no_proxy }) => {
      try {
        await proxyManager.setHostUpstream(hostname, { proxyUrl: proxy_url, noProxy: no_proxy });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              message: `Upstream for '${hostname}' set to ${proxy_url}`,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_remove_host_upstream",
    "Remove a per-host upstream proxy override.",
    {
      hostname: z.string().describe("Hostname to remove override for"),
    },
    async ({ hostname }) => {
      const removed = await proxyManager.removeHostUpstream(hostname);
      if (!removed) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `No upstream override for '${hostname}'` }) }] };
      }
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "success", message: `Upstream override for '${hostname}' removed.` }),
        }],
      };
    },
  );
}
