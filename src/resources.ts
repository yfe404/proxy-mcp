/**
 * MCP Resources — proxy status, CA certificate, traffic summary, interceptors.
 */

import { ResourceTemplate, type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { proxyManager } from "./state.js";
import { interceptorManager } from "./interceptors/manager.js";
import type { BrowserInterceptor } from "./interceptors/browser.js";

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
    "proxy_sessions",
    "proxy://sessions",
    async (uri) => {
      const runtime = proxyManager.getSessionStatus();
      const sessions = await proxyManager.listSessions();
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            runtime,
            count: sessions.length,
            sessions,
          }, null, 2),
        }],
      };
    },
  );

  const sessionSummaryTemplate = new ResourceTemplate(
    "proxy://sessions/{session_id}/summary",
    {
      list: async () => {
        const sessions = await proxyManager.listSessions();
        return {
          resources: sessions.map((s) => ({
            uri: `proxy://sessions/${s.id}/summary`,
            name: `Session Summary (${s.id})`,
            description: s.name ?? "Persisted proxy session summary",
          })),
        };
      },
      complete: {
        session_id: async (value) => {
          const sessions = await proxyManager.listSessions();
          return sessions.map((s) => s.id).filter((id) => id.startsWith(value));
        },
      },
    },
  );

  server.resource(
    "proxy_session_summary",
    sessionSummaryTemplate,
    async (uri, vars) => {
      const sessionId = typeof vars.session_id === "string" ? vars.session_id : "";
      if (!sessionId) {
        return { contents: [{ uri: uri.href, text: JSON.stringify({ error: "Missing session_id." }) }] };
      }
      const summary = await proxyManager.getSessionSummary(sessionId);
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify(summary, null, 2),
        }],
      };
    },
  );

  const sessionTimelineTemplate = new ResourceTemplate(
    "proxy://sessions/{session_id}/timeline",
    {
      list: async () => {
        const sessions = await proxyManager.listSessions();
        return {
          resources: sessions.map((s) => ({
            uri: `proxy://sessions/${s.id}/timeline`,
            name: `Session Timeline (${s.id})`,
            description: s.name ?? "Request timeline buckets",
          })),
        };
      },
      complete: {
        session_id: async (value) => {
          const sessions = await proxyManager.listSessions();
          return sessions.map((s) => s.id).filter((id) => id.startsWith(value));
        },
      },
    },
  );

  server.resource(
    "proxy_session_timeline",
    sessionTimelineTemplate,
    async (uri, vars) => {
      const sessionId = typeof vars.session_id === "string" ? vars.session_id : "";
      if (!sessionId) {
        return { contents: [{ uri: uri.href, text: JSON.stringify({ error: "Missing session_id." }) }] };
      }
      const timeline = await proxyManager.getSessionTimeline(sessionId, 60_000);
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({ sessionId, bucketMs: 60_000, timeline }, null, 2),
        }],
      };
    },
  );

  const sessionFindingsTemplate = new ResourceTemplate(
    "proxy://sessions/{session_id}/findings",
    {
      list: async () => {
        const sessions = await proxyManager.listSessions();
        return {
          resources: sessions.map((s) => ({
            uri: `proxy://sessions/${s.id}/findings`,
            name: `Session Findings (${s.id})`,
            description: s.name ?? "Top errors, slow requests, and risk signals",
          })),
        };
      },
      complete: {
        session_id: async (value) => {
          const sessions = await proxyManager.listSessions();
          return sessions.map((s) => s.id).filter((id) => id.startsWith(value));
        },
      },
    },
  );

  server.resource(
    "proxy_session_findings",
    sessionFindingsTemplate,
    async (uri, vars) => {
      const sessionId = typeof vars.session_id === "string" ? vars.session_id : "";
      if (!sessionId) {
        return { contents: [{ uri: uri.href, text: JSON.stringify({ error: "Missing session_id." }) }] };
      }
      const findings = await proxyManager.getSessionFindings(sessionId);
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({ sessionId, findings }, null, 2),
        }],
      };
    },
  );

  // Most recently activated browser instance (fixed resource)
  server.resource(
    "proxy_browser_primary",
    "proxy://browser/primary",
    async (uri) => {
      const browser = interceptorManager.get("browser") as BrowserInterceptor | undefined;
      const proxy = {
        running: proxyManager.isRunning(),
        port: proxyManager.getPort(),
        certFingerprint: proxyManager.getCert()?.fingerprint ?? null,
      };

      if (!browser) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ proxy, browser: { error: "Browser interceptor not registered.", primary: null } }, null, 2),
          }],
        };
      }

      const meta = await browser.getMetadata();
      const primary = [...meta.activeTargets].sort((a, b) => b.activatedAt - a.activatedAt)[0];

      if (!primary) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ proxy, browser: { error: "No active browser targets. Launch one with interceptor_browser_launch.", primary: null } }, null, 2),
          }],
        };
      }

      const entry = browser.getEntry(primary.id);
      const pageInfo = entry && !entry.page.isClosed()
        ? { currentUrl: entry.page.url(), title: await entry.page.title().catch(() => "") }
        : null;

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            proxy,
            browser: {
              primaryTargetId: primary.id,
              target: primary,
              page: pageInfo,
            },
          }, null, 2),
        }],
      };
    },
  );

  server.resource(
    "proxy_browser_targets",
    "proxy://browser/targets",
    async (uri) => {
      const browser = interceptorManager.get("browser") as BrowserInterceptor | undefined;
      const proxy = {
        running: proxyManager.isRunning(),
        port: proxyManager.getPort(),
        certFingerprint: proxyManager.getCert()?.fingerprint ?? null,
      };

      if (!browser) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ proxy, browser: { error: "Browser interceptor not registered.", targets: [] } }, null, 2),
          }],
        };
      }

      const meta = await browser.getMetadata();

      const targets = await Promise.all(meta.activeTargets.map(async (t) => {
        const entry = browser.getEntry(t.id);
        const pageInfo = entry && !entry.page.isClosed()
          ? { currentUrl: entry.page.url(), title: await entry.page.title().catch(() => "") }
          : null;
        return { target: t, page: pageInfo };
      }));

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            proxy,
            browser: {
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
