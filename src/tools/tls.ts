/**
 * TLS fingerprinting tools — capture JA3/JA4, JA3S, and spoof outgoing JA3.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import type { FingerprintSpoofConfig } from "../state.js";
import { truncateResult } from "../utils.js";
import { resolveBrowserPreset, listBrowserPresets } from "../browser-presets.js";
import { checkSpoofRuntime } from "../tls-spoof.js";

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

  // ── Set JA3 spoof (legacy — kept for backward compat) ──
  server.tool(
    "proxy_set_ja3_spoof",
    "Legacy: enable fingerprint spoofing (deprecated, use proxy_set_fingerprint_spoof with a preset). The ja3 parameter is accepted but ignored — the default Chrome preset is used.",
    {
      ja3: z.string().describe("JA3 fingerprint string (ignored — use proxy_set_fingerprint_spoof with a preset instead)"),
      user_agent: z.string().optional().describe("User-Agent header to use with spoofed requests"),
      host_patterns: z.array(z.string()).optional().describe("Only spoof requests to hostnames containing these substrings. Empty = spoof all HTTPS."),
    },
    async ({ ja3: _ja3, user_agent, host_patterns }) => {
      try {
        await proxyManager.setJa3Spoof({
          userAgent: user_agent,
          hostPatterns: host_patterns,
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "success",
              message: "Fingerprint spoofing enabled with default Chrome preset. Use proxy_set_fingerprint_spoof with a preset for explicit control.",
              config: { userAgent: user_agent, hostPatterns: host_patterns ?? [] },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  // ── Set full fingerprint spoof ──
  server.tool(
    "proxy_set_fingerprint_spoof",
    "Enable outgoing TLS + HTTP/2 fingerprint spoofing via impit (native TLS impersonation, no Docker required). Supports browser presets that select an impit target (rustls, matching real Chrome/Firefox).",
    {
      preset: z.string().optional().describe("Browser preset name (e.g. 'chrome_131', 'chrome_136'). Use proxy_list_fingerprint_presets to see available options."),
      user_agent: z.string().optional().describe("User-Agent header to use with spoofed requests (overrides preset UA)"),
      host_patterns: z.array(z.string()).optional().describe("Only spoof requests to hostnames containing these substrings. Empty = spoof all HTTPS."),
      disable_redirect: z.boolean().optional().describe("Disable automatic redirect following"),
      insecure_skip_verify: z.boolean().optional().describe("Skip TLS certificate verification"),
    },
    async ({ preset, user_agent, host_patterns, disable_redirect, insecure_skip_verify }) => {
      try {
        let config: FingerprintSpoofConfig;

        if (preset) {
          const base = resolveBrowserPreset(preset);
          config = {
            userAgent: user_agent ?? base.userAgent,
            hostPatterns: host_patterns,
            disableRedirect: disable_redirect,
            insecureSkipVerify: insecure_skip_verify,
            preset,
          };
        } else {
          config = {
            userAgent: user_agent,
            hostPatterns: host_patterns,
            disableRedirect: disable_redirect,
            insecureSkipVerify: insecure_skip_verify,
          };
        }

        await proxyManager.setFingerprintSpoof(config);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "success",
              message: "Fingerprint spoofing enabled",
              config,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  // ── List fingerprint presets ──
  server.tool(
    "proxy_list_fingerprint_presets",
    "List available browser fingerprint presets for use with proxy_set_fingerprint_spoof.",
    {},
    async () => {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            status: "success",
            presets: listBrowserPresets(),
          }),
        }],
      };
    },
  );

  // ── Check fingerprint spoof runtime readiness ──
  server.tool(
    "proxy_check_fingerprint_runtime",
    "Check fingerprint spoofing backend readiness without sending traffic.",
    {},
    async () => {
      try {
        const runtime = await checkSpoofRuntime();
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(runtime),
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
    "Disable fingerprint spoofing.",
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
