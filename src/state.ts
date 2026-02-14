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
import { randomUUID } from "node:crypto";
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
  type HarImportOptions,
  type HarImportSummary,
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

export interface RuleTestRequest {
  method: string;
  url: string;
  hostname: string;
  path: string;
  headers: Record<string, string>;
  body: string;
}

export interface RuleMatchFieldCheck {
  applies: boolean;
  passed: boolean;
  expected?: unknown;
  actual?: unknown;
  reason?: string;
  mismatch?: Array<{ header: string; expected: string; actual: string | null }>;
}

export interface RuleMatchChecks {
  method: RuleMatchFieldCheck;
  urlPattern: RuleMatchFieldCheck;
  hostname: RuleMatchFieldCheck;
  pathPattern: RuleMatchFieldCheck;
  headers: RuleMatchFieldCheck;
  bodyIncludes: RuleMatchFieldCheck;
}

export interface RuleMatchEvaluation {
  ruleId: string;
  enabled: boolean;
  priority: number;
  description: string;
  matched: boolean;
  eligible: boolean;
  checks: RuleMatchChecks;
}

export interface RuleTestOptions {
  includeDisabled?: boolean;
  limitRules?: number;
}

export interface RuleTestResult {
  request: RuleTestRequest;
  includeDisabled: boolean;
  evaluatedCount: number;
  totalRules: number;
  results: RuleMatchEvaluation[];
  matchedCount: number;
  effectiveMatchCount: number;
  effectiveWinner: {
    ruleId: string;
    priority: number;
    description: string;
    handlerType: RuleHandlerType;
  } | null;
}

export interface ReplaySessionOptions {
  mode?: "dry_run" | "execute";
  limit?: number;
  offset?: number;
  sort?: "asc" | "desc";
  method?: string;
  hostnameContains?: string;
  urlContains?: string;
  statusCode?: number;
  fromTs?: number;
  toTs?: number;
  text?: string;
  exchangeIds?: string[];
  targetBaseUrl?: string;
  timeoutMs?: number;
}

export interface ReplaySessionPlanItem {
  seq: number;
  exchangeId: string;
  method: string;
  originalUrl: string;
  targetUrl: string;
  hostname: string;
  hasRequestBody: boolean;
}

export interface ReplaySessionExecutionItem extends ReplaySessionPlanItem {
  status: "success" | "error";
  durationMs?: number;
  responseStatus?: number;
  responseSize?: number;
  replayExchangeId?: string;
  error?: string;
}

export interface ReplaySessionResult {
  mode: "dry_run" | "execute";
  sessionId: string;
  selectedCount: number;
  executedCount: number;
  successCount: number;
  errorCount: number;
  targetBaseUrl: string | null;
  items: Array<ReplaySessionPlanItem | ReplaySessionExecutionItem>;
}

export interface SessionHandshakeItem {
  seq: number;
  exchangeId: string;
  timestamp: number;
  hostname: string;
  url: string;
  ja3: string | null;
  ja4: string | null;
  ja3s: string | null;
  hasTls: boolean;
}

export interface SessionHandshakeReport {
  sessionId: string;
  total: number;
  withTlsMetadata: number;
  withoutTlsMetadata: number;
  unavailableReason: string;
  items: SessionHandshakeItem[];
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

export interface FingerprintSpoofConfig {
  ja3: string;
  userAgent?: string;
  hostPatterns?: string[];
  http2Fingerprint?: string;
  headerOrder?: string[];
  orderAsProvided?: boolean;
  disableGrease?: boolean;
  disableRedirect?: boolean;
  forceHTTP1?: boolean;
  insecureSkipVerify?: boolean;
  preset?: string;
}

/** @deprecated Use FingerprintSpoofConfig */
export type Ja3SpoofConfig = FingerprintSpoofConfig;

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
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "content-length",
  "host",
]);

function sanitizeReplayHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(key)) continue;
    out[key] = v;
  }
  return out;
}

function rewriteReplayUrl(originalUrl: string, targetBaseUrl?: string): string {
  if (!targetBaseUrl) return originalUrl;
  const original = new URL(originalUrl);
  const base = new URL(targetBaseUrl);
  return new URL(`${original.pathname}${original.search}`, base).toString();
}

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
  private _ja3SpoofConfig: FingerprintSpoofConfig | null = null;

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

  testRulesAgainstRequest(
    requestInput: { url: string } & Partial<Omit<RuleTestRequest, "url">>,
    options: RuleTestOptions = {},
  ): RuleTestResult {
    const request = this.normalizeRuleTestRequest(requestInput);
    const includeDisabled = options.includeDisabled ?? true;
    const limitRules = options.limitRules;

    const allRules = this.listRules();
    const candidates = includeDisabled ? allRules : allRules.filter((r) => r.enabled);
    const rules = (typeof limitRules === "number" && limitRules >= 0)
      ? candidates.slice(0, limitRules)
      : candidates;

    const results: RuleMatchEvaluation[] = rules.map((rule) => {
      const { matched, checks } = this.evaluateRuleMatcher(rule.matcher, request);
      const eligible = matched && rule.enabled;
      return {
        ruleId: rule.id,
        enabled: rule.enabled,
        priority: rule.priority,
        description: rule.description,
        matched,
        eligible,
        checks,
      };
    });

    const matchedCount = results.filter((r) => r.matched).length;
    const effectiveMatches = results.filter((r) => r.eligible);
    const winner = effectiveMatches[0] ?? null;
    const winnerRule = winner ? this.getRule(winner.ruleId) ?? null : null;

    return {
      request,
      includeDisabled,
      evaluatedCount: results.length,
      totalRules: allRules.length,
      results,
      matchedCount,
      effectiveMatchCount: effectiveMatches.length,
      effectiveWinner: winner && winnerRule ? {
        ruleId: winner.ruleId,
        priority: winner.priority,
        description: winner.description,
        handlerType: winnerRule.handler.type,
      } : null,
    };
  }

  testRulesAgainstExchange(exchangeId: string, options: RuleTestOptions = {}): RuleTestResult {
    const exchange = this.getExchange(exchangeId);
    if (!exchange) {
      throw new Error(`Exchange '${exchangeId}' not found`);
    }
    return this.testRulesAgainstRequest({
      method: exchange.request.method,
      url: exchange.request.url,
      hostname: exchange.request.hostname,
      path: exchange.request.path,
      headers: exchange.request.headers,
      body: exchange.request.bodyPreview,
    }, options);
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

  async importHarAsSession(opts: HarImportOptions): Promise<{ session: SessionManifest; importSummary: HarImportSummary }> {
    return await this.sessionStore.importHar(opts);
  }

  async getSessionHandshakes(
    sessionId: string,
    opts: {
      limit?: number;
      offset?: number;
      hostnameContains?: string;
      urlContains?: string;
      sort?: "asc" | "desc";
    } = {},
  ): Promise<SessionHandshakeReport> {
    const filterQuery = {
      hostnameContains: opts.hostnameContains,
      urlContains: opts.urlContains,
      sort: opts.sort ?? "desc" as "asc" | "desc",
    };

    const all = await this.sessionStore.querySession(sessionId, {
      ...filterQuery,
      limit: 500000,
      offset: 0,
    });

    const result = await this.sessionStore.querySession(sessionId, {
      ...filterQuery,
      limit: opts.limit ?? 200,
      offset: opts.offset ?? 0,
    });

    const items: SessionHandshakeItem[] = result.items.map((entry) => {
      const ja3 = entry.ja3 ?? null;
      const ja4 = entry.ja4 ?? null;
      const ja3s = entry.ja3s ?? null;
      return {
        seq: entry.seq,
        exchangeId: entry.exchangeId,
        timestamp: entry.timestamp,
        hostname: entry.hostname,
        url: entry.url,
        ja3,
        ja4,
        ja3s,
        hasTls: !!(ja3 || ja4 || ja3s),
      };
    });

    const withTlsMetadata = all.items.filter((entry) => !!(entry.ja3 || entry.ja4 || entry.ja3s)).length;
    return {
      sessionId,
      total: all.total,
      withTlsMetadata,
      withoutTlsMetadata: Math.max(0, all.total - withTlsMetadata),
      unavailableReason:
        "HAR imports and proxy_replay_session entries do not include TLS handshake fingerprints. Use live proxy-captured traffic for JA3/JA4/JA3S.",
      items,
    };
  }

  async replaySession(sessionId: string, opts: ReplaySessionOptions = {}): Promise<ReplaySessionResult> {
    const mode = opts.mode ?? "dry_run";
    const timeoutMs = Math.max(1000, opts.timeoutMs ?? 15000);

    const planned: ReplaySessionPlanItem[] = [];
    const sourceItems: Array<{
      seq: number;
      exchangeId: string;
      method: string;
      originalUrl: string;
      targetUrl: string;
      hostname: string;
      headers: Record<string, string>;
      body: string;
      bodyBuffer: Buffer;
    }> = [];

    if (opts.exchangeIds && opts.exchangeIds.length > 0) {
      for (const exchangeId of opts.exchangeIds) {
        const loaded = await this.sessionStore.getSessionExchange(sessionId, { exchangeId, includeBody: true });
        const exchange = loaded.record?.exchange;
        if (!exchange) {
          throw new Error(`Exchange '${exchangeId}' not found in session '${sessionId}'.`);
        }
        const originalUrl = exchange.request.url;
        const targetUrl = rewriteReplayUrl(originalUrl, opts.targetBaseUrl);
        const headers = sanitizeReplayHeaders(exchange.request.headers);
        const body = loaded.record?.requestBodyText ?? exchange.request.bodyPreview ?? "";
        const bodyBuffer = Buffer.from(body, "utf8");
        sourceItems.push({
          seq: loaded.index.seq,
          exchangeId: loaded.index.exchangeId,
          method: exchange.request.method,
          originalUrl,
          targetUrl,
          hostname: new URL(targetUrl).hostname,
          headers,
          body,
          bodyBuffer,
        });
      }
    } else {
      const result = await this.sessionStore.querySession(sessionId, {
        limit: opts.limit ?? 100,
        offset: opts.offset ?? 0,
        sort: opts.sort ?? "desc",
        method: opts.method,
        hostnameContains: opts.hostnameContains,
        urlContains: opts.urlContains,
        statusCode: opts.statusCode,
        fromTs: opts.fromTs,
        toTs: opts.toTs,
        text: opts.text,
      });

      for (const entry of result.items) {
        const loaded = await this.sessionStore.getSessionExchange(sessionId, { exchangeId: entry.exchangeId, includeBody: true });
        const exchange = loaded.record?.exchange;
        if (!exchange) continue;
        const originalUrl = exchange.request.url;
        const targetUrl = rewriteReplayUrl(originalUrl, opts.targetBaseUrl);
        const headers = sanitizeReplayHeaders(exchange.request.headers);
        const body = loaded.record?.requestBodyText ?? exchange.request.bodyPreview ?? "";
        const bodyBuffer = Buffer.from(body, "utf8");
        sourceItems.push({
          seq: loaded.index.seq,
          exchangeId: loaded.index.exchangeId,
          method: exchange.request.method,
          originalUrl,
          targetUrl,
          hostname: new URL(targetUrl).hostname,
          headers,
          body,
          bodyBuffer,
        });
      }
    }

    for (const item of sourceItems) {
      planned.push({
        seq: item.seq,
        exchangeId: item.exchangeId,
        method: item.method,
        originalUrl: item.originalUrl,
        targetUrl: item.targetUrl,
        hostname: item.hostname,
        hasRequestBody: item.bodyBuffer.length > 0,
      });
    }

    if (mode === "dry_run") {
      return {
        mode,
        sessionId,
        selectedCount: planned.length,
        executedCount: 0,
        successCount: 0,
        errorCount: 0,
        targetBaseUrl: opts.targetBaseUrl ?? null,
        items: planned,
      };
    }

    const execution: ReplaySessionExecutionItem[] = [];
    let successCount = 0;
    let errorCount = 0;

    for (const source of sourceItems) {
      const startedAt = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const method = source.method.toUpperCase();
        const withBody = !["GET", "HEAD"].includes(method) && source.bodyBuffer.length > 0;
        const response = await fetch(source.targetUrl, {
          method,
          headers: source.headers,
          body: withBody ? source.body : undefined,
          redirect: "manual",
          signal: controller.signal,
        });
        clearTimeout(timer);

        const responseBuffer = Buffer.from(await response.arrayBuffer());
        const responseBodyText = responseBuffer.toString("utf8");
        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          responseHeaders[key.toLowerCase()] = value;
        });
        const parsedTarget = new URL(source.targetUrl);
        const durationMs = Date.now() - startedAt;
        const replayExchangeId = `replay_${randomUUID()}`;
        const captured: CapturedExchange = {
          id: replayExchangeId,
          timestamp: startedAt,
          request: {
            method,
            url: source.targetUrl,
            hostname: parsedTarget.hostname,
            path: `${parsedTarget.pathname}${parsedTarget.search}`,
            headers: source.headers,
            bodyPreview: capString(source.body, MAX_BODY_PREVIEW),
            bodySize: source.bodyBuffer.length,
          },
          response: {
            statusCode: response.status,
            statusMessage: response.statusText,
            headers: responseHeaders,
            bodyPreview: capString(responseBodyText, MAX_BODY_PREVIEW),
            bodySize: responseBuffer.length,
          },
          duration: durationMs,
        };
        this.pushTraffic(captured);
        if (this.sessionStore.isActive()) {
          const captureFullBodies = this.sessionStore.getActiveProfile() === "full";
          this.sessionStore.recordExchange(captured, {
            requestBody: captureFullBodies ? source.bodyBuffer : undefined,
            responseBody: captureFullBodies ? responseBuffer : undefined,
          });
        }

        execution.push({
          seq: source.seq,
          exchangeId: source.exchangeId,
          method,
          originalUrl: source.originalUrl,
          targetUrl: source.targetUrl,
          hostname: source.hostname,
          hasRequestBody: source.bodyBuffer.length > 0,
          status: "success",
          durationMs,
          responseStatus: response.status,
          responseSize: responseBuffer.length,
          replayExchangeId,
        });
        successCount++;
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        execution.push({
          seq: source.seq,
          exchangeId: source.exchangeId,
          method: source.method,
          originalUrl: source.originalUrl,
          targetUrl: source.targetUrl,
          hostname: source.hostname,
          hasRequestBody: source.bodyBuffer.length > 0,
          status: "error",
          durationMs: Date.now() - startedAt,
          error: message,
        });
        errorCount++;
      }
    }

    return {
      mode,
      sessionId,
      selectedCount: planned.length,
      executedCount: execution.length,
      successCount,
      errorCount,
      targetBaseUrl: opts.targetBaseUrl ?? null,
      items: execution,
    };
  }

  // ── TLS Fingerprinting ──

  getJa3SpoofConfig(): FingerprintSpoofConfig | null {
    return this._ja3SpoofConfig;
  }

  async setFingerprintSpoof(config: FingerprintSpoofConfig): Promise<void> {
    this._ja3SpoofConfig = config;
    if (this._running) await this.rebuildMockttpRules();
  }

  async setJa3Spoof(config: FingerprintSpoofConfig): Promise<void> {
    return this.setFingerprintSpoof(config);
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
              // req.hostname can be empty in HTTPS proxy mode; fall back to URL parsing
              let hostname = req.hostname || "";
              if (!hostname) {
                try { hostname = new URL(req.url).hostname; } catch { /* ignore */ }
              }
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
                http2Fingerprint: spoofConfig.http2Fingerprint,
                headerOrder: spoofConfig.headerOrder,
                orderAsProvided: spoofConfig.orderAsProvided,
                disableGrease: spoofConfig.disableGrease,
                disableRedirect: spoofConfig.disableRedirect,
                forceHTTP1: spoofConfig.forceHTTP1,
                insecureSkipVerify: spoofConfig.insecureSkipVerify,
              });

              return {
                response: {
                  statusCode: result.status,
                  headers: result.headers,
                  // Use rawBody so mockttp doesn't auto content-encode based on Content-Encoding.
                  // CycleTLS already returns the bytes as received from the origin.
                  rawBody: result.body,
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
    if (matcher.pathPattern) {
      const pathRe = new RegExp(matcher.pathPattern);
      builder = builder.matching((req) => pathRe.test(req.path));
    }
    if (matcher.headers) {
      builder = builder.withHeaders(matcher.headers);
    }
    if (matcher.bodyIncludes) {
      builder = builder.withBodyIncluding(matcher.bodyIncludes);
    }

    return builder;
  }

  private normalizeRuleTestRequest(
    requestInput: { url: string } & Partial<Omit<RuleTestRequest, "url">>,
  ): RuleTestRequest {
    let parsed: URL;
    try {
      parsed = new URL(requestInput.url);
    } catch {
      throw new Error(`Invalid URL '${requestInput.url}'`);
    }

    const method = (requestInput.method ?? "GET").toUpperCase();
    const hostname = (requestInput.hostname ?? parsed.hostname).toLowerCase();
    const path = requestInput.path ?? `${parsed.pathname}${parsed.search}`;
    const body = requestInput.body ?? "";

    const headers: Record<string, string> = {};
    if (requestInput.headers) {
      for (const [k, v] of Object.entries(requestInput.headers)) {
        headers[k.toLowerCase()] = String(v);
      }
    }

    return {
      method,
      url: requestInput.url,
      hostname,
      path,
      headers,
      body,
    };
  }

  private evaluateRuleMatcher(matcher: RuleMatcher, request: RuleTestRequest): {
    matched: boolean;
    checks: RuleMatchChecks;
  } {
    const passByDefault: RuleMatchFieldCheck = { applies: false, passed: true };
    const checks: RuleMatchChecks = {
      method: { ...passByDefault },
      urlPattern: { ...passByDefault },
      hostname: { ...passByDefault },
      pathPattern: { ...passByDefault },
      headers: { ...passByDefault },
      bodyIncludes: { ...passByDefault },
    };

    if (matcher.method) {
      const expected = matcher.method.toUpperCase();
      const actual = request.method.toUpperCase();
      checks.method = {
        applies: true,
        passed: actual === expected,
        expected,
        actual,
        ...(actual === expected ? {} : { reason: "HTTP method mismatch" }),
      };
    }

    if (matcher.urlPattern) {
      try {
        const re = new RegExp(matcher.urlPattern);
        const passed = re.test(request.url);
        checks.urlPattern = {
          applies: true,
          passed,
          expected: matcher.urlPattern,
          actual: request.url,
          ...(passed ? {} : { reason: "URL does not match regex" }),
        };
      } catch (e) {
        checks.urlPattern = {
          applies: true,
          passed: false,
          expected: matcher.urlPattern,
          actual: request.url,
          reason: `Invalid regex: ${e instanceof Error ? e.message : String(e)}`,
        };
      }
    }

    if (matcher.hostname) {
      const expected = matcher.hostname.toLowerCase();
      const actual = request.hostname.toLowerCase();
      const passed = actual === expected;
      checks.hostname = {
        applies: true,
        passed,
        expected,
        actual,
        ...(passed ? {} : { reason: "Hostname mismatch" }),
      };
    }

    if (matcher.pathPattern) {
      try {
        const re = new RegExp(matcher.pathPattern);
        const passed = re.test(request.path);
        checks.pathPattern = {
          applies: true,
          passed,
          expected: matcher.pathPattern,
          actual: request.path,
          ...(passed ? {} : { reason: "Path does not match regex" }),
        };
      } catch (e) {
        checks.pathPattern = {
          applies: true,
          passed: false,
          expected: matcher.pathPattern,
          actual: request.path,
          reason: `Invalid regex: ${e instanceof Error ? e.message : String(e)}`,
        };
      }
    }

    if (matcher.headers) {
      const missingOrMismatched: Array<{ header: string; expected: string; actual: string | null }> = [];
      for (const [key, expectedValue] of Object.entries(matcher.headers)) {
        const actual = request.headers[key.toLowerCase()];
        if (actual === undefined || actual !== expectedValue) {
          missingOrMismatched.push({
            header: key.toLowerCase(),
            expected: expectedValue,
            actual: actual ?? null,
          });
        }
      }
      const passed = missingOrMismatched.length === 0;
      checks.headers = {
        applies: true,
        passed,
        expected: matcher.headers,
        actual: request.headers,
        ...(passed
          ? {}
          : {
              reason: "Required headers missing or mismatched",
              // Provide exact header mismatches for deterministic debugging.
              mismatch: missingOrMismatched,
            }),
      };
    }

    if (matcher.bodyIncludes) {
      const expected = matcher.bodyIncludes;
      const actual = request.body;
      const passed = actual.includes(expected);
      checks.bodyIncludes = {
        applies: true,
        passed,
        expected,
        actual: actual.length > 200 ? `${actual.slice(0, 200)}...` : actual,
        ...(passed ? {} : { reason: "Body does not include required substring" }),
      };
    }

    const matched = checks.method.passed
      && checks.urlPattern.passed
      && checks.hostname.passed
      && checks.pathPattern.passed
      && checks.headers.passed
      && checks.bodyIncludes.passed;

    return { matched, checks };
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
