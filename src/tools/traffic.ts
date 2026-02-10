/**
 * Traffic capture tools — list, search, inspect, and clear captured exchanges.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import { truncateResult } from "../utils.js";

export function registerTrafficTools(server: McpServer): void {
  server.tool(
    "proxy_list_traffic",
    "List captured HTTP exchanges with optional filters. Returns paginated results.",
    {
      limit: z.number().optional().default(50).describe("Max entries to return (default: 50)"),
      offset: z.number().optional().default(0).describe("Skip first N entries (default: 0)"),
      method_filter: z.string().optional().describe("Filter by HTTP method (e.g., GET, POST)"),
      url_filter: z.string().optional().describe("Filter by URL substring"),
      status_filter: z.number().optional().describe("Filter by response status code"),
      hostname_filter: z.string().optional().describe("Filter by hostname substring"),
    },
    async ({ limit, offset, method_filter, url_filter, status_filter, hostname_filter }) => {
      let traffic = proxyManager.getTraffic();

      if (method_filter) {
        const m = method_filter.toUpperCase();
        traffic = traffic.filter((t) => t.request.method === m);
      }
      if (url_filter) {
        const u = url_filter.toLowerCase();
        traffic = traffic.filter((t) => t.request.url.toLowerCase().includes(u));
      }
      if (status_filter !== undefined) {
        traffic = traffic.filter((t) => t.response?.statusCode === status_filter);
      }
      if (hostname_filter) {
        const h = hostname_filter.toLowerCase();
        traffic = traffic.filter((t) => t.request.hostname.toLowerCase().includes(h));
      }

      const total = traffic.length;
      const page = traffic.slice(offset, offset + limit);

      // Create summary view (no body previews to save space)
      const summaries = page.map((t) => ({
        id: t.id,
        timestamp: t.timestamp,
        method: t.request.method,
        url: t.request.url,
        hostname: t.request.hostname,
        status: t.response?.statusCode ?? null,
        duration: t.duration ?? null,
        requestSize: t.request.bodySize,
        responseSize: t.response?.bodySize ?? null,
        ...(t.tls?.client?.ja3Fingerprint ? { ja3: t.tls.client.ja3Fingerprint } : {}),
        ...(t.tls?.client?.ja4Fingerprint ? { ja4: t.tls.client.ja4Fingerprint } : {}),
      }));

      return {
        content: [{
          type: "text",
          text: truncateResult({
            status: "success",
            total,
            offset,
            limit,
            showing: summaries.length,
            exchanges: summaries,
          }),
        }],
      };
    },
  );

  server.tool(
    "proxy_get_exchange",
    "Get full details of a captured HTTP exchange including headers and body previews.",
    {
      exchange_id: z.string().describe("Exchange ID from proxy_list_traffic"),
    },
    async ({ exchange_id }) => {
      const exchange = proxyManager.getExchange(exchange_id);
      if (!exchange) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Exchange '${exchange_id}' not found` }) }] };
      }
      return {
        content: [{
          type: "text",
          text: truncateResult({ status: "success", exchange }),
        }],
      };
    },
  );

  server.tool(
    "proxy_search_traffic",
    "Full-text search across URLs, headers, and body previews of captured traffic.",
    {
      query: z.string().describe("Search string"),
      limit: z.number().optional().default(20).describe("Max results (default: 20)"),
    },
    async ({ query, limit }) => {
      const results = proxyManager.searchTraffic(query).slice(0, limit);
      const summaries = results.map((t) => ({
        id: t.id,
        timestamp: t.timestamp,
        method: t.request.method,
        url: t.request.url,
        status: t.response?.statusCode ?? null,
        duration: t.duration ?? null,
      }));

      return {
        content: [{
          type: "text",
          text: truncateResult({
            status: "success",
            query,
            matches: summaries.length,
            results: summaries,
          }),
        }],
      };
    },
  );

  server.tool(
    "proxy_clear_traffic",
    "Clear all captured traffic from the buffer.",
    {},
    async () => {
      const count = proxyManager.clearTraffic();
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "success", cleared: count }),
        }],
      };
    },
  );
}
