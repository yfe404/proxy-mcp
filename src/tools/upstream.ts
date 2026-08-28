/**
 * Upstream proxy tools — configure SOCKS/HTTP proxies for outgoing traffic.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import { mergeUpstreamPassword, redactProxyUrl, upstreamPasswordSource } from "../utils.js";

/**
 * A proxy_url the code cannot parse must not report success: redaction removed
 * the echo that used to make a typo self-evident, and nothing downstream
 * validates it either. The value is not repeated back — it may hold a password.
 */
function unparseable() {
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify({
        status: "error",
        error: "proxy_url is not a parseable URL — check the scheme, e.g. socks5://host:1080",
      }),
    }],
  };
}

export function registerUpstreamTools(server: McpServer): void {
  server.tool(
    "proxy_set_upstream",
    "Set a global upstream proxy for all outgoing traffic. Supports socks4://, socks5://, http://, https://, and pac+http:// URLs.",
    {
      proxy_url: z.string().describe("Upstream proxy URL (e.g., socks5://user:pass@host:port). If the URL has a username but no password, and the server has both PROXY_MCP_UPSTREAM_PASSWORD and PROXY_MCP_UPSTREAM_HOST set with the host matching this URL's hostname, the password is filled in from the environment so it need not appear in this call. Otherwise the URL is used as given; the response reports passwordSource: env | url | none."),
      no_proxy: z.array(z.string()).optional().describe("Hostnames to bypass the upstream proxy"),
    },
    async ({ proxy_url, no_proxy }) => {
      try {
        if (!URL.canParse(proxy_url)) return unparseable();
        const resolved = mergeUpstreamPassword(proxy_url);
        const passwordSource = upstreamPasswordSource(proxy_url, resolved);
        await proxyManager.setGlobalUpstream({ proxyUrl: resolved, noProxy: no_proxy });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              message: `Global upstream set to ${redactProxyUrl(resolved)}`,
              ...(passwordSource ? { passwordSource } : {}),
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
      proxy_url: z.string().describe("Upstream proxy URL for this host. If it has a username but no password, the password is filled in from PROXY_MCP_UPSTREAM_PASSWORD, but only when PROXY_MCP_UPSTREAM_HOST is also set and matches this URL's hostname. The response reports passwordSource: env | url | none."),
      no_proxy: z.array(z.string()).optional().describe("Hostnames to bypass this proxy"),
    },
    async ({ hostname, proxy_url, no_proxy }) => {
      try {
        if (!URL.canParse(proxy_url)) return unparseable();
        const resolved = mergeUpstreamPassword(proxy_url);
        const passwordSource = upstreamPasswordSource(proxy_url, resolved);
        await proxyManager.setHostUpstream(hostname, { proxyUrl: resolved, noProxy: no_proxy });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              message: `Upstream for '${hostname}' set to ${redactProxyUrl(resolved)}`,
              ...(passwordSource ? { passwordSource } : {}),
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
