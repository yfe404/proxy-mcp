/**
 * TLS fingerprinting tools — capture JA3/JA4, JA3S, and spoof outgoing JA3.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import { truncateResult } from "../utils.js";

export function registerTlsTools(server: McpServer): void {
  // ── Get TLS fingerprints for a specific exchange ──
  server.tool(
    "proxy_get_tls_fingerprints",
    "Get JA3/JA4 client fingerprints and JA3S server fingerprint for a specific captured exchange.",
    {
      exchange_id: z.string().describe("Exchange ID from proxy_list_traffic"),
    },
    async ({ exchange_id }) => {
      const exchange = proxyManager.getExchange(exchange_id);
      if (!exchange) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "error", error: `Exchange '${exchange_id}' not found` }) }] };
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            status: "success",
            exchange_id,
            hostname: exchange.request.hostname,
            tls: exchange.tls ?? null,
          }),
        }],
      };
    },
  );

  // ── List unique TLS fingerprints across traffic ──
  server.tool(
    "proxy_list_tls_fingerprints",
    "List unique client JA3/JA4 fingerprints across captured traffic with occurrence counts.",
    {
      limit: z.number().optional().default(20).describe("Max fingerprints to return (default: 20)"),
      hostname_filter: z.string().optional().describe("Filter by hostname substring"),
    },
    async ({ limit, hostname_filter }) => {
      let traffic = proxyManager.getTraffic();

      if (hostname_filter) {
        const h = hostname_filter.toLowerCase();
        traffic = traffic.filter((t) => t.request.hostname.toLowerCase().includes(h));
      }

      // Aggregate JA3 fingerprints
      const ja3Counts = new Map<string, { count: number; hostnames: Set<string> }>();
      const ja4Counts = new Map<string, { count: number; hostnames: Set<string> }>();

      for (const t of traffic) {
        if (t.tls?.client?.ja3Fingerprint) {
          const fp = t.tls.client.ja3Fingerprint;
          const entry = ja3Counts.get(fp) || { count: 0, hostnames: new Set() };
          entry.count++;
          entry.hostnames.add(t.request.hostname);
          ja3Counts.set(fp, entry);
        }
        if (t.tls?.client?.ja4Fingerprint) {
          const fp = t.tls.client.ja4Fingerprint;
          const entry = ja4Counts.get(fp) || { count: 0, hostnames: new Set() };
          entry.count++;
          entry.hostnames.add(t.request.hostname);
          ja4Counts.set(fp, entry);
        }
      }

      // Sort by count descending
      const ja3List = [...ja3Counts.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, limit)
        .map(([fp, { count, hostnames }]) => ({
          fingerprint: fp,
          count,
          hostnames: [...hostnames].slice(0, 5),
        }));

      const ja4List = [...ja4Counts.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, limit)
        .map(([fp, { count, hostnames }]) => ({
          fingerprint: fp,
          count,
          hostnames: [...hostnames].slice(0, 5),
        }));

      return {
        content: [{
          type: "text" as const,
          text: truncateResult({
            status: "success",
            totalExchangesWithTls: traffic.filter((t) => t.tls?.client).length,
            ja3: ja3List,
            ja4: ja4List,
          }),
        }],
      };
    },
  );

  // ── Set JA3 spoof ──
  server.tool(
    "proxy_set_ja3_spoof",
    "Enable outgoing JA3 fingerprint spoofing via CycleTLS. HTTPS requests matching host patterns will be re-issued with the specified JA3 string.",
    {
      ja3: z.string().describe("JA3 fingerprint string to spoof (e.g., '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0')"),
      user_agent: z.string().optional().describe("User-Agent header to use with spoofed requests"),
      host_patterns: z.array(z.string()).optional().describe("Only spoof requests to hostnames containing these substrings. Empty = spoof all HTTPS."),
    },
    async ({ ja3, user_agent, host_patterns }) => {
      try {
        await proxyManager.setJa3Spoof({
          ja3,
          userAgent: user_agent,
          hostPatterns: host_patterns,
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "success",
              message: "JA3 spoofing enabled",
              config: { ja3, userAgent: user_agent, hostPatterns: host_patterns ?? [] },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  // ── Clear JA3 spoof ──
  server.tool(
    "proxy_clear_ja3_spoof",
    "Disable outgoing JA3 fingerprint spoofing and shut down CycleTLS subprocess.",
    {},
    async () => {
      try {
        await proxyManager.clearJa3Spoof();
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ status: "success", message: "JA3 spoofing disabled" }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  // ── Get TLS config ──
  server.tool(
    "proxy_get_tls_config",
    "Get current TLS capture and spoofing configuration.",
    {},
    async () => {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            status: "success",
            ...proxyManager.getTlsConfig(),
          }),
        }],
      };
    },
  );

  // ── Enable/disable server TLS capture ──
  server.tool(
    "proxy_enable_server_tls_capture",
    "Toggle server-side JA3S capture. When enabled, outgoing TLS connections are intercepted to extract the server's negotiated TLS parameters.",
    {
      enabled: z.boolean().describe("true to enable, false to disable"),
    },
    async ({ enabled }) => {
      if (enabled) {
        proxyManager.enableServerTls();
      } else {
        proxyManager.disableServerTls();
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            status: "success",
            serverTlsCaptureEnabled: proxyManager.isServerTlsCaptureEnabled(),
          }),
        }],
      };
    },
  );
}
