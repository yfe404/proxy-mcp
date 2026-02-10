/**
 * MCP Resources — proxy status, CA certificate, traffic summary, interceptors.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { proxyManager } from "./state.js";
import { interceptorManager } from "./interceptors/manager.js";
import { getCdpBaseUrl, getCdpTargets, getCdpTargetsUrl, getCdpVersion, getCdpVersionUrl } from "./cdp-utils.js";

export function registerResources(server: McpServer): void {
  server.resource(
    "proxy_status",
    "proxy://status",
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: JSON.stringify(proxyManager.getStatus(), null, 2),
      }],
    }),
  );

  server.resource(
    "proxy_ca_cert",
    "proxy://ca-cert",
    async (uri) => {
      const cert = proxyManager.getCert();
      if (!cert) {
        return { contents: [{ uri: uri.href, text: "No certificate. Start the proxy first." }] };
      }
      return {
        contents: [{
          uri: uri.href,
          text: cert.cert,
          mimeType: "application/x-pem-file",
        }],
      };
    },
  );

  server.resource(
    "proxy_traffic_summary",
    "proxy://traffic/summary",
    async (uri) => {
      const traffic = proxyManager.getTraffic();

      // Method breakdown
      const methods: Record<string, number> = {};
      const statuses: Record<string, number> = {};
      const hostnames: Record<string, number> = {};
      let totalDuration = 0;
      let durationCount = 0;

      for (const t of traffic) {
        methods[t.request.method] = (methods[t.request.method] || 0) + 1;
        if (t.response) {
          const s = String(t.response.statusCode);
          statuses[s] = (statuses[s] || 0) + 1;
        }
        if (t.request.hostname) {
          hostnames[t.request.hostname] = (hostnames[t.request.hostname] || 0) + 1;
        }
        if (t.duration !== undefined) {
          totalDuration += t.duration;
          durationCount++;
        }
      }

      // Top 10 hostnames by frequency
      const topHostnames = Object.entries(hostnames)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([host, count]) => ({ host, count }));

      // TLS fingerprint stats
      const ja3Counts: Record<string, number> = {};
      const ja4Counts: Record<string, number> = {};
      for (const t of traffic) {
        if (t.tls?.client?.ja3Fingerprint) {
          const fp = t.tls.client.ja3Fingerprint;
          ja3Counts[fp] = (ja3Counts[fp] || 0) + 1;
        }
        if (t.tls?.client?.ja4Fingerprint) {
          const fp = t.tls.client.ja4Fingerprint;
          ja4Counts[fp] = (ja4Counts[fp] || 0) + 1;
        }
      }

      const topJa3 = Object.entries(ja3Counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([fingerprint, count]) => ({ fingerprint, count }));

      const topJa4 = Object.entries(ja4Counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([fingerprint, count]) => ({ fingerprint, count }));

      const summary = {
        totalExchanges: traffic.length,
        methods,
        statuses,
        topHostnames,
        avgDurationMs: durationCount > 0 ? Math.round(totalDuration / durationCount) : null,
        tls: {
          exchangesWithTls: traffic.filter((t) => t.tls?.client).length,
          topJa3,
          topJa4,
        },
      };

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify(summary, null, 2),
        }],
      };
    },
  );

  server.resource(
    "proxy_interceptors",
    "proxy://interceptors",
    async (uri) => {
      const list = await interceptorManager.list();
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify(list, null, 2),
        }],
      };
    },
  );

  server.resource(
    "proxy_chrome_targets",
    "proxy://chrome/targets",
    async (uri) => {
      const chrome = interceptorManager.get("chrome");
      const proxy = {
        running: proxyManager.isRunning(),
        port: proxyManager.getPort(),
        certFingerprint: proxyManager.getCert()?.fingerprint ?? null,
      };

      if (!chrome) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ proxy, chrome: { error: "Chrome interceptor not registered.", targets: [] } }, null, 2),
          }],
        };
      }

      const meta = await chrome.getMetadata();

      const targets = await Promise.all(meta.activeTargets.map(async (t) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const details: any = t.details ?? {};
        const port = details.port;
        if (typeof port !== "number" || !Number.isFinite(port) || port <= 0) {
          return { target: t, cdp: null, cdpTargets: null };
        }

        const httpUrl = getCdpBaseUrl(port);
        const versionUrl = getCdpVersionUrl(port);
        const targetsUrl = getCdpTargetsUrl(port);

        let version: Record<string, unknown> | null = null;
        let cdpTargets: Array<Record<string, unknown>> | null = null;

        try {
          version = await getCdpVersion(port, { timeoutMs: 500 });
        } catch {
          // Best effort only
        }

        try {
          cdpTargets = await getCdpTargets(port, { timeoutMs: 500 });
        } catch {
          // Best effort only
        }

        return {
          target: t,
          cdp: {
            httpUrl,
            versionUrl,
            targetsUrl,
            browserWebSocketDebuggerUrl: typeof version?.webSocketDebuggerUrl === "string" ? version.webSocketDebuggerUrl : null,
          },
          cdpTargets,
        };
      }));

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            proxy,
            chrome: {
              interceptorId: meta.id,
              interceptorName: meta.name,
              activeCount: meta.activeTargets.length,
              targets,
            },
          }, null, 2),
        }],
      };
    },
  );
}
