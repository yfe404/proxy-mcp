/**
 * ProxyManager — singleton managing mockttp MITM proxy state.
 *
 * Manages: server instance, CA cert, upstream proxy config, interception rules,
 * and traffic capture ring buffer.
 *
 * Key design: mockttp's local server only applies rules set BEFORE start().
 * So rebuildMockttpRules() stops the server, creates a new instance with the
 * full rule set, and restarts on the same port.
 */

import type * as mockttp from "mockttp";
import type { CompletedRequest, CompletedResponse, ProxyConfig } from "mockttp";
import { serializeHeaders, capString } from "./utils.js";
import { enableServerTlsCapture, type ServerTlsCapture } from "./tls-utils.js";
import { spoofedRequest, shutdownCycleTLS } from "./tls-spoof.js";
import { interceptorManager } from "./interceptors/manager.js";
import { cleanupTempCerts } from "./interceptors/cert-utils.js";
import { ensureSafeNetworkInterfaces } from "./os-shim.js";
import {
  SessionStore,
  type SessionStartOptions,
  type SessionManifest,
  type SessionQuery,
  type SessionQueryResult,
  type SessionIndexEntry,
} from "./session-store.js";

let mockttpMod: typeof import("mockttp") | null = null;
async function getMockttp(): Promise<typeof import("mockttp")> {
  if (mockttpMod) return mockttpMod;
  ensureSafeNetworkInterfaces();
  mockttpMod = await import("mockttp");
  return mockttpMod;
}

// ── Interfaces ──

export interface CertificateInfo {
  key: string;
  cert: string;
  fingerprint: string;
}

export interface UpstreamProxyConfig {
  proxyUrl: string;
  noProxy?: string[];
}

export interface InterceptionRule {
  id: string;
  priority: number;
  enabled: boolean;
  description: string;
  matcher: RuleMatcher;
  handler: RuleHandler;
  hitCount: number;
  createdAt: number;
}

export interface RuleMatcher {
  method?: string;
  urlPattern?: string;
  hostname?: string;
  pathPattern?: string;
  headers?: Record<string, string>;
  bodyIncludes?: string;
}

export type RuleHandlerType = "passthrough" | "mock" | "forward" | "drop";

export interface RuleHandler {
  type: RuleHandlerType;
  // For mock
  status?: number;
  body?: string;
  headers?: Record<string, string>;
  // For forward
  forwardTo?: string;
  // Transform configs
  transformRequest?: RequestTransformConfig;
  transformResponse?: ResponseTransformConfig;
}

export interface RequestTransformConfig {
  updateHeaders?: Record<string, string | null>;
  replaceMethod?: string;
  matchReplaceBody?: Array<[string, string]>;
}

export interface ResponseTransformConfig {
  updateHeaders?: Record<string, string | null>;
  replaceStatus?: number;
  matchReplaceBody?: Array<[string, string]>;
}

export interface TlsClientMetadata {
  sniHostname?: string;
  clientAlpn?: string[];
  ja3Fingerprint?: string;
  ja4Fingerprint?: string;
}

export interface TlsServerMetadata {
  protocol?: string;
  cipher?: string;
  ja3sFingerprint?: string;
}

export interface Ja3SpoofConfig {
  ja3: string;
  userAgent?: string;
  hostPatterns?: string[];
}

export interface ProxyStartOptions extends SessionStartOptions {
  persistenceEnabled?: boolean;
}

export interface CapturedExchange {
  id: string;
  timestamp: number;
  request: {
    method: string;
    url: string;
    hostname: string;
    path: string;
    headers: Record<string, string>;
    bodyPreview: string;
    bodySize: number;
  };
  response?: {
    statusCode: number;
    statusMessage: string;
    headers: Record<string, string>;
    bodyPreview: string;
    bodySize: number;
  };
  tls?: {
    client?: TlsClientMetadata;
    server?: TlsServerMetadata;
  };
  duration?: number;
  matchedRuleId?: string;
}

// Map null values to undefined so mockttp deletes those headers.
// JSON can't represent undefined, so the MCP schema uses null for deletion.
function nullsToUndefined(
  headers?: Record<string, string | null>,
): Record<string, string | undefined> | undefined {
  if (!headers) return undefined;
  return Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k, v === null ? undefined : v]),
  );
}

// ── Constants ──

const MAX_TRAFFIC_ENTRIES = 1000;
const MAX_BODY_PREVIEW = 4096;

// ── ProxyManager ──

let nextRuleId = 1;

export class ProxyManager {
  private server: mockttp.Mockttp | null = null;
  private cert: CertificateInfo | null = null;
  private port: number | null = null;
  private _running = false;
  private readonly sessionStore = new SessionStore();

  // Upstream proxy
  private globalUpstream: UpstreamProxyConfig | null = null;
  private hostUpstreams = new Map<string, UpstreamProxyConfig>();

  // Interception rules
  private rules = new Map<string, InterceptionRule>();

  // Traffic capture (ring buffer)
  private traffic: CapturedExchange[] = [];
  private pendingRequests = new Map<string, CapturedExchange>();
  private pendingRawBodies = new Map<string, { requestBody?: Buffer }>();

  // TLS fingerprinting
  private tlsMetadataCache = new Map<string, TlsClientMetadata>();
  private serverTlsCapture: ServerTlsCapture | null = null;
  private _ja3SpoofConfig: Ja3SpoofConfig | null = null;

  // ── Lifecycle ──

  async start(port?: number, options: ProxyStartOptions = {}): Promise<{ port: number; url: string; cert: CertificateInfo }> {
    if (this._running) {
      throw new Error("Proxy is already running. Stop it first.");
    }

    // Generate CA cert (once, reused across rebuilds)
    if (!this.cert) {
      const mockttp = await getMockttp();
      const ca = await mockttp.generateCACertificate({ bits: 2048 });
      const fingerprint = mockttp.generateSPKIFingerprint(ca.cert);
      this.cert = { key: ca.key, cert: ca.cert, fingerprint };
    }

    this.port = port || 0;
    await this.buildAndStart();
    this._running = true;
    this.port = this.server!.port;

    if (options.persistenceEnabled) {
      await this.sessionStore.startSession({
        sessionName: options.sessionName,
        captureProfile: options.captureProfile,
        storageDir: options.storageDir,
        maxDiskMb: options.maxDiskMb,
      });
    }

    return {
      port: this.server!.port,
      url: this.server!.url,
      cert: this.cert,
    };
  }

  async stop(): Promise<void> {
    if (!this._running) {
      throw new Error("Proxy is not running.");
    }
    // Deactivate all interceptors before stopping the proxy
    await interceptorManager.deactivateAll().catch(() => {});
    await cleanupTempCerts().catch(() => {});
    if (this.server) {
      await this.server.stop();
      this.server = null;
    }
    await this.sessionStore.stopSession().catch(() => {});
    this._running = false;
    this.pendingRequests.clear();
    this.pendingRawBodies.clear();
    this.tlsMetadataCache.clear();
    this.disableServerTls();
    if (this._ja3SpoofConfig) {
      await shutdownCycleTLS();
    }
  }

  isRunning(): boolean {
    return this._running;
  }

  getPort(): number | null {
    return this.port;
  }

  getCert(): CertificateInfo | null {
    return this.cert;
  }

  getStatus(): object {
    return {
      running: this.isRunning(),
      port: this.port,
      url: this.server?.url ?? null,
      certFingerprint: this.cert?.fingerprint ?? null,
      globalUpstream: this.globalUpstream,
      hostUpstreams: Object.fromEntries(this.hostUpstreams),
      ruleCount: this.rules.size,
      trafficCount: this.traffic.length,
      persistence: this.sessionStore.getRuntimeStatus(),
    };
  }

  // ── Upstream Proxy ──

  async setGlobalUpstream(config: UpstreamProxyConfig): Promise<void> {
    this.globalUpstream = config;
    if (this._running) await this.rebuildMockttpRules();
  }

  async clearGlobalUpstream(): Promise<void> {
    this.globalUpstream = null;
    if (this._running) await this.rebuildMockttpRules();
  }

  getGlobalUpstream(): UpstreamProxyConfig | null {
    return this.globalUpstream;
  }

  async setHostUpstream(hostname: string, config: UpstreamProxyConfig): Promise<void> {
    this.hostUpstreams.set(hostname, config);
    if (this._running) await this.rebuildMockttpRules();
  }

  async removeHostUpstream(hostname: string): Promise<boolean> {
    const removed = this.hostUpstreams.delete(hostname);
    if (removed && this._running) await this.rebuildMockttpRules();
    return removed;
  }

  getHostUpstreams(): Map<string, UpstreamProxyConfig> {
    return this.hostUpstreams;
  }

  // ── Interception Rules ──

  async addRule(rule: Omit<InterceptionRule, "id" | "hitCount" | "createdAt">): Promise<InterceptionRule> {
    const id = `rule_${nextRuleId++}`;
    const newRule: InterceptionRule = {
      ...rule,
      id,
      hitCount: 0,
      createdAt: Date.now(),
    };
    this.rules.set(id, newRule);
    if (this._running) await this.rebuildMockttpRules();
    return newRule;
  }

  async updateRule(id: string, updates: Partial<Omit<InterceptionRule, "id" | "hitCount" | "createdAt">>): Promise<InterceptionRule> {
    const rule = this.rules.get(id);
    if (!rule) throw new Error(`Rule '${id}' not found`);
    Object.assign(rule, updates);
    if (this._running) await this.rebuildMockttpRules();
    return rule;
  }

  async removeRule(id: string): Promise<boolean> {
    const removed = this.rules.delete(id);
    if (removed && this._running) await this.rebuildMockttpRules();
    return removed;
  }

  getRule(id: string): InterceptionRule | undefined {
    return this.rules.get(id);
  }

  listRules(): InterceptionRule[] {
    return [...this.rules.values()].sort((a, b) => a.priority - b.priority);
  }

  async enableRule(id: string): Promise<void> {
    const rule = this.rules.get(id);
    if (!rule) throw new Error(`Rule '${id}' not found`);
    rule.enabled = true;
    if (this._running) await this.rebuildMockttpRules();
  }

  async disableRule(id: string): Promise<void> {
    const rule = this.rules.get(id);
    if (!rule) throw new Error(`Rule '${id}' not found`);
    rule.enabled = false;
    if (this._running) await this.rebuildMockttpRules();
  }

  // ── Traffic ──

  getTraffic(): CapturedExchange[] {
    return this.traffic;
  }

  getExchange(id: string): CapturedExchange | undefined {
    return this.traffic.find((t) => t.id === id);
  }

  searchTraffic(query: string): CapturedExchange[] {
    const q = query.toLowerCase();
    return this.traffic.filter((t) => {
      if (t.request.url.toLowerCase().includes(q)) return true;
      if (t.request.bodyPreview.toLowerCase().includes(q)) return true;
      if (t.response?.bodyPreview.toLowerCase().includes(q)) return true;
      for (const v of Object.values(t.request.headers)) {
        if (v.toLowerCase().includes(q)) return true;
      }
      if (t.response) {
        for (const v of Object.values(t.response.headers)) {
          if (v.toLowerCase().includes(q)) return true;
        }
      }
      return false;
    });
  }

  clearTraffic(): number {
    const count = this.traffic.length;
    this.traffic.length = 0;
    this.pendingRequests.clear();
    this.pendingRawBodies.clear();
    return count;
  }

  // ── Persistent Sessions ──

  isSessionPersistenceEnabled(): boolean {
    return this.sessionStore.isActive();
  }

  getSessionCaptureProfile(): "preview" | "full" | null {
    return this.sessionStore.getActiveProfile();
  }

  async startSession(options: SessionStartOptions = {}): Promise<SessionManifest> {
    return await this.sessionStore.startSession(options);
  }

  async stopSession(): Promise<SessionManifest | null> {
    return await this.sessionStore.stopSession();
  }

  getSessionStatus(): object {
    return this.sessionStore.getRuntimeStatus();
  }

  async listSessions(): Promise<Array<SessionManifest & { diskUsageMb: number }>> {
    return await this.sessionStore.listSessions();
  }

  async getSession(sessionId: string): Promise<SessionManifest> {
    return await this.sessionStore.getSession(sessionId);
  }

  async querySession(sessionId: string, query: SessionQuery): Promise<SessionQueryResult> {
    return await this.sessionStore.querySession(sessionId, query);
  }

  async getSessionExchange(
    sessionId: string,
    opts: { seq?: number; exchangeId?: string; includeBody?: boolean },
  ): Promise<{ index: SessionIndexEntry; record?: unknown }> {
    return await this.sessionStore.getSessionExchange(sessionId, opts);
  }

  async exportSessionHar(
    sessionId: string,
    opts: { outputFile?: string; query?: SessionQuery; includeBodies?: boolean } = {},
  ): Promise<{ sessionId: string; outputFile: string; entries: number }> {
    return await this.sessionStore.exportHar(sessionId, opts);
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.sessionStore.deleteSession(sessionId);
  }

  async recoverSession(sessionId?: string): Promise<{ recovered: Array<{ sessionId: string; exchanges: number; droppedTailBytes: number }> }> {
    return await this.sessionStore.recoverSession(sessionId);
  }

  async getSessionSummary(sessionId: string): Promise<{
    manifest: SessionManifest;
    totals: {
      exchanges: number;
      avgDurationMs: number | null;
      topHostnames: Array<{ hostname: string; count: number }>;
      statuses: Record<string, number>;
      methods: Record<string, number>;
    };
  }> {
    return await this.sessionStore.getSessionSummary(sessionId);
  }

  async getSessionTimeline(
    sessionId: string,
    bucketMs?: number,
  ): Promise<Array<{ bucketStart: number; count: number; errorCount: number }>> {
    return await this.sessionStore.getSessionTimeline(sessionId, bucketMs);
  }

  async getSessionFindings(sessionId: string): Promise<{
    highErrorEndpoints: Array<{ endpoint: string; errors: number }>;
    slowestExchanges: Array<{ exchangeId: string; duration: number; url: string }>;
    hostErrorRates: Array<{ hostname: string; total: number; errors: number; errorRate: number }>;
  }> {
    return await this.sessionStore.getSessionFindings(sessionId);
  }

  // ── TLS Fingerprinting ──

  getJa3SpoofConfig(): Ja3SpoofConfig | null {
    return this._ja3SpoofConfig;
  }

  async setJa3Spoof(config: Ja3SpoofConfig): Promise<void> {
    this._ja3SpoofConfig = config;
    if (this._running) await this.rebuildMockttpRules();
  }

  async clearJa3Spoof(): Promise<void> {
    this._ja3SpoofConfig = null;
    await shutdownCycleTLS();
    if (this._running) await this.rebuildMockttpRules();
  }

  isServerTlsCaptureEnabled(): boolean {
    return this.serverTlsCapture !== null;
  }

  enableServerTls(): void {
    if (!this.serverTlsCapture) {
      this.serverTlsCapture = enableServerTlsCapture();
    }
  }

  disableServerTls(): void {
    if (this.serverTlsCapture) {
      this.serverTlsCapture.disable();
      this.serverTlsCapture = null;
    }
  }

  getTlsConfig(): object {
    return {
      serverTlsCaptureEnabled: this.isServerTlsCaptureEnabled(),
      ja3SpoofConfig: this._ja3SpoofConfig,
    };
  }

  // ── Internal: Build server with rules, then start ──

  /**
   * Create a fresh mockttp server, apply all rules + event listeners, then start it.
   * Called during initial start() and during rule rebuilds.
   */
  private async buildAndStart(): Promise<void> {
    if (!this.cert) throw new Error("No certificate");

    const mockttp = await getMockttp();
    const server = mockttp.getLocal({
      https: { key: this.cert.key, cert: this.cert.cert },
    });

    // Set up event listeners
    this.setupEventListeners(server);

    // Apply user rules sorted by priority (ascending = most important first).
    // Rules are registered in order — mockttp uses registration order for matching
    // when asPriority() is not used (asPriority has bugs with HTTPS mode).
    const proxyConfig = this.resolveProxyConfig();
    const enabledRules = [...this.rules.values()]
      .filter((r) => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of enabledRules) {
      const builder = this.buildMatcher(server, rule.matcher).always();
      await this.buildHandler(builder, rule, proxyConfig);
    }

    // Default passthrough (registered last = lowest priority)
    if (this._ja3SpoofConfig) {
      const spoofConfig = this._ja3SpoofConfig;
      await server.forAnyRequest().always()
        .thenPassThrough({
          ignoreHostHttpsErrors: true,
          proxyConfig,
          beforeRequest: async (req) => {
            // Only spoof HTTPS requests matching host patterns
            if (!req.url.startsWith("https://")) return {};

            if (spoofConfig.hostPatterns && spoofConfig.hostPatterns.length > 0) {
              const hostname = req.hostname || "";
              const matches = spoofConfig.hostPatterns.some((p) =>
                hostname.includes(p) || hostname.endsWith(p)
              );
              if (!matches) return {};
            }

            try {
              const result = await spoofedRequest(req.url, {
                method: req.method,
                headers: req.headers as Record<string, string>,
                body: req.body.buffer.length > 0 ? req.body.buffer.toString("utf-8") : undefined,
                ja3: spoofConfig.ja3,
                userAgent: spoofConfig.userAgent,
              });

              return {
                response: {
                  statusCode: result.status,
                  headers: result.headers,
                  body: result.body,
                },
              };
            } catch {
              // On failure, let the request pass through normally
              return {};
            }
          },
        });
    } else {
      await server.forAnyRequest().always()
        .thenPassThrough({
          ignoreHostHttpsErrors: true,
          proxyConfig,
        });
    }

    // Start on the stored port
    await server.start(this.port || 0);
    this.server = server;

    // Set up TLS client metadata capture from the underlying server
    this.setupTlsCapture(server);
  }

  /**
   * Stop current server, rebuild with updated rules, restart on same port.
   */
  private async rebuildMockttpRules(): Promise<void> {
    const currentPort = this.port;
    if (this.server) {
      await this.server.stop();
      this.server = null;
    }
    this.port = currentPort;
    await this.buildAndStart();
    this.port = this.server!.port;
  }

  // ── Internal: TLS Capture ──

  /**
   * Hook the underlying net.Server's secureConnection event to capture
   * TLS client metadata (JA3/JA4) that mockttp stores on socket.__tlsMetadata.
   * Cache by remoteAddress:remotePort for later lookup in request handlers.
   */
  private setupTlsCapture(server: mockttp.Mockttp): void {
    // Access the internal https server — mockttp doesn't expose this publicly.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const internalServer = (server as any).server as
      | { on(event: string, cb: (...args: any[]) => void): void }
      | undefined;

    if (!internalServer || typeof internalServer.on !== "function") {
      return; // Graceful degradation
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    internalServer.on("secureConnection", (socket: any) => {
      const meta = socket.__tlsMetadata as
        | { sniHostname?: string; clientAlpn?: string[]; ja3Fingerprint?: string; ja4Fingerprint?: string }
        | undefined;

      const addr = socket.remoteAddress as string | undefined;
      const port = socket.remotePort as number | undefined;

      if (meta && addr && port) {
        const key = `${addr}:${port}`;
        this.tlsMetadataCache.set(key, {
          sniHostname: meta.sniHostname,
          clientAlpn: meta.clientAlpn,
          ja3Fingerprint: meta.ja3Fingerprint,
          ja4Fingerprint: meta.ja4Fingerprint,
        });

        if (typeof socket.once === "function") {
          socket.once("close", () => {
            this.tlsMetadataCache.delete(key);
          });
        }
      }
    });
  }

  // ── Internal: Event Listeners ──

  private setupEventListeners(server: mockttp.Mockttp): void {
    server.on("request", (req: CompletedRequest) => {
      const requestBody = req.body.buffer;
      const shouldCaptureFullBody = this.sessionStore.getActiveProfile() === "full";
      if (shouldCaptureFullBody && requestBody.length > 0) {
        this.pendingRawBodies.set(req.id, { requestBody: Buffer.from(requestBody) });
      }

      // Look up TLS client metadata from cache
      let clientTls: TlsClientMetadata | undefined;
      if (req.remoteIpAddress && req.remotePort) {
        const key = `${req.remoteIpAddress}:${req.remotePort}`;
        clientTls = this.tlsMetadataCache.get(key);
      }

      const exchange: CapturedExchange = {
        id: req.id,
        timestamp: Date.now(),
        request: {
          method: req.method,
          url: req.url,
          hostname: req.hostname || "",
          path: req.path,
          headers: serializeHeaders(req.headers as Record<string, string | string[] | undefined>),
          bodyPreview: capString(requestBody.toString("utf-8"), MAX_BODY_PREVIEW),
          bodySize: requestBody.length,
        },
        tls: clientTls ? { client: clientTls } : undefined,
        matchedRuleId: req.matchedRuleId,
      };
      this.pendingRequests.set(req.id, exchange);
    });

    server.on("response", (res: CompletedResponse) => {
      const exchange = this.pendingRequests.get(res.id);
      if (exchange) {
        const responseBody = res.body.buffer;
        exchange.response = {
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          headers: serializeHeaders(res.headers as Record<string, string | string[] | undefined>),
          bodyPreview: capString(responseBody.toString("utf-8"), MAX_BODY_PREVIEW),
          bodySize: responseBody.length,
        };
        if (res.timingEvents.responseSentTimestamp && res.timingEvents.startTimestamp) {
          exchange.duration = Math.round(res.timingEvents.responseSentTimestamp - res.timingEvents.startTimestamp);
        }
        // Attach server TLS metadata if capture is enabled
        if (this.serverTlsCapture && exchange.request.hostname) {
          const serverTls = this.serverTlsCapture.getServerTlsByHostname(exchange.request.hostname);
          if (serverTls) {
            if (!exchange.tls) exchange.tls = {};
            exchange.tls.server = {
              protocol: serverTls.protocol,
              cipher: serverTls.cipher,
              ja3sFingerprint: serverTls.ja3sFingerprint,
            };
          }
        }
        this.pendingRequests.delete(res.id);
        const pendingBodies = this.pendingRawBodies.get(res.id);
        if (pendingBodies || this.sessionStore.isActive()) {
          this.sessionStore.recordExchange(exchange, {
            requestBody: pendingBodies?.requestBody,
            responseBody: this.sessionStore.getActiveProfile() === "full" ? Buffer.from(responseBody) : undefined,
          });
        }
        this.pendingRawBodies.delete(res.id);
        this.pushTraffic(exchange);
      } else {
        const orphanedExchange: CapturedExchange = {
          id: res.id,
          timestamp: Date.now(),
          request: { method: "?", url: "?", hostname: "", path: "", headers: {}, bodyPreview: "", bodySize: 0 },
          response: {
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: serializeHeaders(res.headers as Record<string, string | string[] | undefined>),
            bodyPreview: capString(res.body.buffer.toString("utf-8"), MAX_BODY_PREVIEW),
            bodySize: res.body.buffer.length,
          },
        };
        if (this.sessionStore.isActive()) {
          this.sessionStore.recordExchange(orphanedExchange, {
            responseBody: this.sessionStore.getActiveProfile() === "full" ? Buffer.from(res.body.buffer) : undefined,
          });
        }
        this.pendingRawBodies.delete(res.id);
        this.pushTraffic(orphanedExchange);
      }
    });

    server.on("abort", (req) => {
      const exchange = this.pendingRequests.get(req.id);
      if (exchange) {
        this.pendingRequests.delete(req.id);
        if (this.sessionStore.isActive()) {
          const pendingBodies = this.pendingRawBodies.get(req.id);
          this.sessionStore.recordExchange(exchange, {
            requestBody: pendingBodies?.requestBody,
          });
        }
        this.pendingRawBodies.delete(req.id);
        this.pushTraffic(exchange);
      }
    });
  }

  private pushTraffic(exchange: CapturedExchange): void {
    this.traffic.push(exchange);
    if (this.traffic.length > MAX_TRAFFIC_ENTRIES) {
      this.traffic.splice(0, this.traffic.length - MAX_TRAFFIC_ENTRIES);
    }
  }

  // ── Internal: Rule Building ──

  private resolveProxyConfig(): ProxyConfig {
    if (!this.globalUpstream && this.hostUpstreams.size === 0) return undefined;

    return ({ hostname }: { hostname: string }) => {
      const hostConfig = this.hostUpstreams.get(hostname);
      if (hostConfig) {
        return { proxyUrl: hostConfig.proxyUrl, noProxy: hostConfig.noProxy };
      }
      if (this.globalUpstream) {
        return { proxyUrl: this.globalUpstream.proxyUrl, noProxy: this.globalUpstream.noProxy };
      }
      return undefined;
    };
  }

  private buildMatcher(server: mockttp.Mockttp, matcher: RuleMatcher): mockttp.RequestRuleBuilder {
    let builder: mockttp.RequestRuleBuilder;

    if (matcher.method) {
      const m = matcher.method.toUpperCase();
      const urlRe = matcher.urlPattern ? new RegExp(matcher.urlPattern) : undefined;
      switch (m) {
        case "GET": builder = server.forGet(urlRe); break;
        case "POST": builder = server.forPost(urlRe); break;
        case "PUT": builder = server.forPut(urlRe); break;
        case "DELETE": builder = server.forDelete(urlRe); break;
        case "PATCH": builder = server.forPatch(urlRe); break;
        case "HEAD": builder = server.forHead(urlRe); break;
        case "OPTIONS": builder = server.forOptions(urlRe); break;
        default: builder = server.forAnyRequest(); break;
      }
    } else if (matcher.urlPattern) {
      builder = server.forAnyRequest().withUrlMatching(new RegExp(matcher.urlPattern));
    } else {
      builder = server.forAnyRequest();
    }

    if (matcher.hostname) {
      builder = builder.forHostname(matcher.hostname);
    }
    if (matcher.headers) {
      builder = builder.withHeaders(matcher.headers);
    }
    if (matcher.bodyIncludes) {
      builder = builder.withBodyIncluding(matcher.bodyIncludes);
    }

    return builder;
  }

  private async buildHandler(
    builder: mockttp.RequestRuleBuilder,
    rule: InterceptionRule,
    proxyConfig: ProxyConfig,
  ): Promise<void> {
    const handler = rule.handler;

    switch (handler.type) {
      case "mock":
        await builder.thenReply(
          handler.status ?? 200,
          handler.body ?? "",
          handler.headers ?? {},
        );
        break;

      case "forward":
        await builder.thenForwardTo(handler.forwardTo!, {
          ignoreHostHttpsErrors: true,
          proxyConfig,
          transformRequest: handler.transformRequest ? {
            updateHeaders: nullsToUndefined(handler.transformRequest.updateHeaders),
            replaceMethod: handler.transformRequest.replaceMethod,
            matchReplaceBody: handler.transformRequest.matchReplaceBody?.map(([m, r]) => [m, r] as [string, string]),
          } : undefined,
          transformResponse: handler.transformResponse ? {
            updateHeaders: nullsToUndefined(handler.transformResponse.updateHeaders),
            replaceStatus: handler.transformResponse.replaceStatus,
            matchReplaceBody: handler.transformResponse.matchReplaceBody?.map(([m, r]) => [m, r] as [string, string]),
          } : undefined,
        });
        break;

      case "drop":
        await builder.thenCloseConnection();
        break;

      case "passthrough":
      default:
        await builder.thenPassThrough({
          ignoreHostHttpsErrors: true,
          proxyConfig,
          transformRequest: handler.transformRequest ? {
            updateHeaders: nullsToUndefined(handler.transformRequest.updateHeaders),
            replaceMethod: handler.transformRequest.replaceMethod,
            matchReplaceBody: handler.transformRequest.matchReplaceBody?.map(([m, r]) => [m, r] as [string, string]),
          } : undefined,
          transformResponse: handler.transformResponse ? {
            updateHeaders: nullsToUndefined(handler.transformResponse.updateHeaders),
            replaceStatus: handler.transformResponse.replaceStatus,
            matchReplaceBody: handler.transformResponse.matchReplaceBody?.map(([m, r]) => [m, r] as [string, string]),
          } : undefined,
        });
        break;
    }
  }
}

// Singleton
export const proxyManager = new ProxyManager();
