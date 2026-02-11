/**
 * MCP Resources — proxy status, CA certificate, traffic summary, interceptors.
 */

import { ResourceTemplate, type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { proxyManager } from "./state.js";
import { interceptorManager } from "./interceptors/manager.js";
import { getCdpBaseUrl, getCdpTargets, getCdpTargetsUrl, getCdpVersion, getCdpVersionUrl, waitForCdpVersion } from "./cdp-utils.js";
import { devToolsBridge } from "./devtools/bridge.js";

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
    "proxy_chrome_devtools_sessions",
    "proxy://chrome/devtools/sessions",
    async (uri) => {
      const sessions = devToolsBridge.listSessions();
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            count: sessions.length,
            sessions,
          }, null, 2),
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

  // Dynamic per-Chrome CDP bundle (resource template)
  const chromeCdpTemplate = new ResourceTemplate(
    "proxy://chrome/{target_id}/cdp",
    {
      list: async () => {
        const chrome = interceptorManager.get("chrome");
        if (!chrome) return { resources: [] };
        const meta = await chrome.getMetadata();

        return {
          resources: meta.activeTargets.map((t) => ({
            uri: `proxy://chrome/${t.id}/cdp`,
            name: `Chrome CDP (${t.id})`,
            description: t.description,
          })),
        };
      },
      complete: {
        target_id: async (value) => {
          const chrome = interceptorManager.get("chrome");
          if (!chrome) return [];
          const meta = await chrome.getMetadata();
          return meta.activeTargets
            .map((t) => t.id)
            .filter((id) => id.startsWith(value));
        },
      },
    },
  );

  server.resource(
    "proxy_chrome_cdp",
    chromeCdpTemplate,
    async (uri, variables) => {
      const proxy = {
        running: proxyManager.isRunning(),
        port: proxyManager.getPort(),
        certFingerprint: proxyManager.getCert()?.fingerprint ?? null,
      };

      try {
        const targetId = typeof variables.target_id === "string" ? variables.target_id : null;
        if (!targetId) {
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({ proxy, chrome: { error: "Missing target_id in URI template." } }, null, 2),
            }],
          };
        }

        const chrome = interceptorManager.get("chrome");
        if (!chrome) {
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({ proxy, chrome: { error: "Chrome interceptor not registered." } }, null, 2),
            }],
          };
        }

        const meta = await chrome.getMetadata();
        const target = meta.activeTargets.find((t) => t.id === targetId);
        if (!target) {
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({ proxy, chrome: { error: `Chrome target '${targetId}' not found. Is it still running?` } }, null, 2),
            }],
          };
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const details: any = target.details ?? {};
        const port = details.port;
        if (typeof port !== "number" || !Number.isFinite(port) || port <= 0) {
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({ proxy, chrome: { error: `Chrome target '${targetId}' has no valid CDP port.` } }, null, 2),
            }],
          };
        }

        const httpUrl = getCdpBaseUrl(port);
        const versionUrl = getCdpVersionUrl(port);
        const targetsUrl = getCdpTargetsUrl(port);

        let version: Record<string, unknown> | null = null;
        let versionError: string | null = null;
        let cdpTargets: Array<Record<string, unknown>> | null = null;

        try {
          version = await waitForCdpVersion(port, { timeoutMs: 3000, intervalMs: 200, requestTimeoutMs: 800 });
        } catch (e) {
          versionError = e instanceof Error ? e.message : String(e);
        }

        try {
          cdpTargets = await getCdpTargets(port, { timeoutMs: 1500 });
        } catch {
          // Best effort only
        }

        const ws = version?.webSocketDebuggerUrl;

        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              proxy,
              chrome: {
                target,
                cdp: {
                  httpUrl,
                  versionUrl,
                  targetsUrl,
                  version,
                  browserWebSocketDebuggerUrl: typeof ws === "string" ? ws : null,
                  ...(versionError ? { versionError } : {}),
                },
                cdpTargets,
              },
            }, null, 2),
          }],
        };
      } catch (e) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ proxy, chrome: { error: e instanceof Error ? e.message : String(e) } }, null, 2),
          }],
        };
      }
    },
  );

  // Most recently activated Chrome instance (fixed resource)
  server.resource(
    "proxy_chrome_primary",
    "proxy://chrome/primary",
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
            text: JSON.stringify({ proxy, chrome: { error: "Chrome interceptor not registered.", primary: null } }, null, 2),
          }],
        };
      }

      const meta = await chrome.getMetadata();
      const primary = [...meta.activeTargets].sort((a, b) => b.activatedAt - a.activatedAt)[0];

      if (!primary) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ proxy, chrome: { error: "No active Chrome targets. Launch one with interceptor_chrome_launch.", primary: null } }, null, 2),
          }],
        };
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const details: any = primary.details ?? {};
      const port = details.port;
      if (typeof port !== "number" || !Number.isFinite(port) || port <= 0) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({ proxy, chrome: { error: `Primary Chrome target '${primary.id}' has no valid CDP port.`, primary: null } }, null, 2),
          }],
        };
      }

      const httpUrl = getCdpBaseUrl(port);
      const versionUrl = getCdpVersionUrl(port);
      const targetsUrl = getCdpTargetsUrl(port);

      let version: Record<string, unknown> | null = null;
      let versionError: string | null = null;
      let cdpTargets: Array<Record<string, unknown>> | null = null;

      try {
        version = await waitForCdpVersion(port, { timeoutMs: 3000, intervalMs: 200, requestTimeoutMs: 800 });
      } catch (e) {
        versionError = e instanceof Error ? e.message : String(e);
      }

      try {
        cdpTargets = await getCdpTargets(port, { timeoutMs: 1500 });
      } catch {
        // Best effort only
      }

      const ws = version?.webSocketDebuggerUrl;

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            proxy,
            chrome: {
              primaryTargetId: primary.id,
              target: primary,
              cdp: {
                httpUrl,
                versionUrl,
                targetsUrl,
                version,
                browserWebSocketDebuggerUrl: typeof ws === "string" ? ws : null,
                ...(versionError ? { versionError } : {}),
              },
              cdpTargets,
            },
          }, null, 2),
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
