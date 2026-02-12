/**
 * SessionStore — optional persistent traffic recording, querying, export, and recovery.
 *
 * Stores each captured exchange as NDJSON plus a compact NDJSON index for efficient
 * MCP queries without loading full records/bodies.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import type { CapturedExchange } from "./state.js";
import { capString } from "./utils.js";

export type CaptureProfile = "preview" | "full";
export type SessionRecoveryState = "clean" | "recovered" | "error";

export interface SessionStartOptions {
  sessionName?: string;
  captureProfile?: CaptureProfile;
  storageDir?: string;
  maxDiskMb?: number;
}

export interface SessionManifest {
  schemaVersion: 1;
  id: string;
  name: string | null;
  captureProfile: CaptureProfile;
  storageDir: string;
  maxDiskMb: number;
  createdAt: number;
  startedAt: number;
  endedAt: number | null;
  status: "active" | "stopped";
  recoveryState: SessionRecoveryState;
  exchangeCount: number;
  bytesWritten: number;
  droppedWrites: number;
  lastSequence: number;
  lastFlushAt: number | null;
  lastError: string | null;
  files: {
    records: string;
    index: string;
    harDir: string;
  };
}

export interface SessionIndexEntry {
  seq: number;
  exchangeId: string;
  timestamp: number;
  method: string;
  hostname: string;
  path: string;
  url: string;
  statusCode: number | null;
  duration: number | null;
  requestBodySize: number;
  responseBodySize: number | null;
  hasResponse: boolean;
  hasFullRequestBody: boolean;
  hasFullResponseBody: boolean;
  matchedRuleId: string | null;
  ja3: string | null;
  ja4: string | null;
  ja3s?: string | null;
  recordOffset: number;
  recordLineBytes: number;
}

export interface PersistedExchangeRecord {
  seq: number;
  sessionId: string;
  exchange: CapturedExchange;
  requestBodyBase64?: string;
  responseBodyBase64?: string;
}

export interface SessionQuery {
  limit?: number;
  offset?: number;
  method?: string;
  hostnameContains?: string;
  urlContains?: string;
  statusCode?: number;
  fromTs?: number;
  toTs?: number;
  text?: string;
  sort?: "asc" | "desc";
}

export interface SessionQueryResult {
  total: number;
  limit: number;
  offset: number;
  items: SessionIndexEntry[];
}

export interface HarImportOptions {
  harFile: string;
  sessionName?: string;
  storageDir?: string;
  maxDiskMb?: number;
  strict?: boolean;
}

export interface HarImportSummary {
  sourceFile: string;
  totalEntries: number;
  importedEntries: number;
  skippedEntries: number;
  errorCount: number;
  firstTimestamp: number | null;
  lastTimestamp: number | null;
  warnings: string[];
}

export interface SessionRuntimeStatus {
  enabled: boolean;
  sessionId: string | null;
  captureProfile: CaptureProfile | null;
  storageDir: string;
  bytesWritten: number;
  droppedWrites: number;
  lastFlushAt: number | null;
  maxDiskMb: number | null;
  recoveryState: SessionRecoveryState | null;
  lastError: string | null;
}

interface ActiveSessionRuntime {
  manifest: SessionManifest;
  dir: string;
  recordsPath: string;
  indexPath: string;
  manifestPath: string;
  harDir: string;
  currentRecordOffset: number;
  writeQueue: Promise<void>;
  writesSinceFlush: number;
}

const SESSION_SCHEMA_VERSION = 1 as const;
const MANIFEST_FILENAME = "manifest.json";
const RECORDS_FILENAME = "records.ndjson";
const INDEX_FILENAME = "index.ndjson";
const DEFAULT_MAX_DISK_MB = 1024;
const IMPORT_BODY_PREVIEW_MAX = 4096;
const IMPORT_WARNING_LIMIT = 100;

function randomSuffix(): string {
  return Math.random().toString(36).slice(2, 10);
}

function toSessionId(now = Date.now()): string {
  const iso = new Date(now).toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  return `${iso}_${randomSuffix()}`;
}

async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
}

function toBase64(body?: Buffer): string | undefined {
  if (!body || body.length === 0) return undefined;
  return body.toString("base64");
}

function fromBase64(b64?: string): string | null {
  if (!b64) return null;
  return Buffer.from(b64, "base64").toString("utf8");
}

function headersToHar(headers: Record<string, string> | undefined): Array<{ name: string; value: string }> {
  if (!headers) return [];
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

function queryToHar(url: string): Array<{ name: string; value: string }> {
  try {
    const u = new URL(url);
    const out: Array<{ name: string; value: string }> = [];
    for (const [name, value] of u.searchParams.entries()) {
      out.push({ name, value });
    }
    return out;
  } catch {
    return [];
  }
}

function fileSizeMb(bytes: number): number {
  return Math.round((bytes / (1024 * 1024)) * 100) / 100;
}

function headersArrayToRecord(headers: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!Array.isArray(headers)) return out;
  for (const h of headers) {
    if (!h || typeof h !== "object") continue;
    const obj = h as Record<string, unknown>;
    if (typeof obj.name !== "string") continue;
    if (typeof obj.value !== "string") continue;
    const key = obj.name.toLowerCase();
    if (out[key]) {
      out[key] = `${out[key]}, ${obj.value}`;
    } else {
      out[key] = obj.value;
    }
  }
  return out;
}

function decodeHarText(text: string, encoding?: string): Buffer {
  if ((encoding ?? "").toLowerCase() === "base64") {
    return Buffer.from(text, "base64");
  }
  return Buffer.from(text, "utf8");
}

function pushWarning(target: string[], warning: string): void {
  if (target.length < IMPORT_WARNING_LIMIT) {
    target.push(warning);
  }
}

export class SessionStore {
  private rootDir: string;
  private active: ActiveSessionRuntime | null = null;

  constructor(rootDir = path.resolve(process.cwd(), ".proxy-mcp/sessions")) {
    this.rootDir = path.resolve(rootDir);
  }

  getRootDir(): string {
    return this.rootDir;
  }

  isActive(): boolean {
    return this.active !== null;
  }

  getActiveProfile(): CaptureProfile | null {
    return this.active?.manifest.captureProfile ?? null;
  }

  getRuntimeStatus(): SessionRuntimeStatus {
    const active = this.active;
    return {
      enabled: !!active,
      sessionId: active?.manifest.id ?? null,
      captureProfile: active?.manifest.captureProfile ?? null,
      storageDir: this.rootDir,
      bytesWritten: active?.manifest.bytesWritten ?? 0,
      droppedWrites: active?.manifest.droppedWrites ?? 0,
      lastFlushAt: active?.manifest.lastFlushAt ?? null,
      maxDiskMb: active?.manifest.maxDiskMb ?? null,
      recoveryState: active?.manifest.recoveryState ?? null,
      lastError: active?.manifest.lastError ?? null,
    };
  }

  async startSession(opts: SessionStartOptions = {}): Promise<SessionManifest> {
    if (this.active) {
      throw new Error(`Session '${this.active.manifest.id}' is already active. Stop it first.`);
    }

    if (opts.storageDir) {
      this.rootDir = path.resolve(opts.storageDir);
    }
    await ensureDir(this.rootDir);

    const now = Date.now();
    const id = toSessionId(now);
    const sessionDir = path.join(this.rootDir, id);
    const recordsPath = path.join(sessionDir, RECORDS_FILENAME);
    const indexPath = path.join(sessionDir, INDEX_FILENAME);
    const manifestPath = path.join(sessionDir, MANIFEST_FILENAME);
    const harDir = path.join(sessionDir, "har");

    await ensureDir(sessionDir);
    await ensureDir(harDir);
    await fs.writeFile(recordsPath, "");
    await fs.writeFile(indexPath, "");

    const manifest: SessionManifest = {
      schemaVersion: SESSION_SCHEMA_VERSION,
      id,
      name: opts.sessionName ?? null,
      captureProfile: opts.captureProfile ?? "preview",
      storageDir: this.rootDir,
      maxDiskMb: opts.maxDiskMb ?? DEFAULT_MAX_DISK_MB,
      createdAt: now,
      startedAt: now,
      endedAt: null,
      status: "active",
      recoveryState: "clean",
      exchangeCount: 0,
      bytesWritten: 0,
      droppedWrites: 0,
      lastSequence: 0,
      lastFlushAt: null,
      lastError: null,
      files: {
        records: RECORDS_FILENAME,
        index: INDEX_FILENAME,
        harDir: "har",
      },
    };

    await this.writeManifest(manifestPath, manifest);

    this.active = {
      manifest,
      dir: sessionDir,
      recordsPath,
      indexPath,
      manifestPath,
      harDir,
      currentRecordOffset: 0,
      writeQueue: Promise.resolve(),
      writesSinceFlush: 0,
    };

    return structuredClone(manifest);
  }

  async stopSession(): Promise<SessionManifest | null> {
    const active = this.active;
    if (!active) return null;

    try {
      await active.writeQueue;
    } catch {
      // lastError already tracked
    }

    active.manifest.status = "stopped";
    active.manifest.endedAt = Date.now();
    active.manifest.lastFlushAt = Date.now();
    await this.writeManifest(active.manifestPath, active.manifest);

    this.active = null;
    return structuredClone(active.manifest);
  }

  async listSessions(): Promise<Array<SessionManifest & { diskUsageMb: number }>> {
    await ensureDir(this.rootDir);
    const entries = await fs.readdir(this.rootDir, { withFileTypes: true });
    const sessions: Array<SessionManifest & { diskUsageMb: number }> = [];

    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const dir = path.join(this.rootDir, e.name);
      const manifestPath = path.join(dir, MANIFEST_FILENAME);
      try {
        const manifestRaw = await fs.readFile(manifestPath, "utf8");
        const manifest = JSON.parse(manifestRaw) as SessionManifest;
        sessions.push({
          ...manifest,
          diskUsageMb: fileSizeMb(manifest.bytesWritten),
        });
      } catch {
        // Ignore malformed directories
      }
    }

    sessions.sort((a, b) => b.startedAt - a.startedAt);
    return sessions;
  }

  async getSession(sessionId: string): Promise<SessionManifest> {
    const manifestPath = path.join(this.rootDir, sessionId, MANIFEST_FILENAME);
    const raw = await fs.readFile(manifestPath, "utf8");
    return JSON.parse(raw) as SessionManifest;
  }

  async importHar(opts: HarImportOptions): Promise<{ session: SessionManifest; importSummary: HarImportSummary }> {
    if (this.active) {
      throw new Error(`Session '${this.active.manifest.id}' is already active. Stop it before importing HAR.`);
    }

    const strict = opts.strict ?? false;
    const sourceFile = path.resolve(opts.harFile);
    const raw = await fs.readFile(sourceFile, "utf8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      throw new Error(`Invalid HAR JSON: ${e instanceof Error ? e.message : String(e)}`);
    }

    const log = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>).log : undefined;
    const entriesRaw = log && typeof log === "object" ? (log as Record<string, unknown>).entries : undefined;
    if (!Array.isArray(entriesRaw)) {
      throw new Error("Invalid HAR: missing log.entries array.");
    }

    const importSummary: HarImportSummary = {
      sourceFile,
      totalEntries: entriesRaw.length,
      importedEntries: 0,
      skippedEntries: 0,
      errorCount: 0,
      firstTimestamp: null,
      lastTimestamp: null,
      warnings: [],
    };

    const defaultName = path.basename(sourceFile, path.extname(sourceFile));
    const started = await this.startSession({
      sessionName: opts.sessionName ?? `har-import-${defaultName}`,
      captureProfile: "full",
      storageDir: opts.storageDir,
      maxDiskMb: opts.maxDiskMb,
    });

    let failed = false;
    let failReason = "";

    for (let i = 0; i < entriesRaw.length; i++) {
      const converted = this.convertHarEntry(entriesRaw[i], i + 1, started.id);
      if (!converted.ok) {
        importSummary.errorCount++;
        importSummary.skippedEntries++;
        pushWarning(importSummary.warnings, converted.error);
        if (strict) {
          failed = true;
          failReason = converted.error;
          break;
        }
        continue;
      }

      const { exchange, requestBody, responseBody, warnings } = converted;
      for (const warning of warnings) {
        pushWarning(importSummary.warnings, warning);
      }

      this.recordExchange(exchange, {
        requestBody,
        responseBody,
      });
      importSummary.importedEntries++;
      if (importSummary.firstTimestamp === null || exchange.timestamp < importSummary.firstTimestamp) {
        importSummary.firstTimestamp = exchange.timestamp;
      }
      if (importSummary.lastTimestamp === null || exchange.timestamp > importSummary.lastTimestamp) {
        importSummary.lastTimestamp = exchange.timestamp;
      }
    }

    const stopped = await this.stopSession();
    if (!stopped) {
      throw new Error("Failed to finalize imported HAR session.");
    }

    if (failed) {
      await this.deleteSession(stopped.id).catch(() => {});
      throw new Error(failReason);
    }

    return {
      session: stopped,
      importSummary,
    };
  }

  recordExchange(
    exchange: CapturedExchange,
    fullBodies?: { requestBody?: Buffer; responseBody?: Buffer },
  ): void {
    const active = this.active;
    if (!active) return;

    active.writeQueue = active.writeQueue
      .then(async () => {
        const seq = active.manifest.lastSequence + 1;
        const includeFull = active.manifest.captureProfile === "full";
        const record: PersistedExchangeRecord = {
          seq,
          sessionId: active.manifest.id,
          exchange,
          ...(includeFull ? {
            requestBodyBase64: toBase64(fullBodies?.requestBody),
            responseBodyBase64: toBase64(fullBodies?.responseBody),
          } : {}),
        };

        const recordLine = `${JSON.stringify(record)}\n`;
        const recordLineBytes = Buffer.byteLength(recordLine);
        const indexEntry = this.toIndexEntry(record, {
          recordOffset: active.currentRecordOffset,
          recordLineBytes,
        });
        const indexLine = `${JSON.stringify(indexEntry)}\n`;
        const indexLineBytes = Buffer.byteLength(indexLine);

        const bytesToWrite = recordLineBytes + indexLineBytes;
        const maxBytes = active.manifest.maxDiskMb * 1024 * 1024;
        if (active.manifest.bytesWritten + bytesToWrite > maxBytes) {
          active.manifest.lastError = `Session disk cap reached (${active.manifest.maxDiskMb} MB).`;
          active.manifest.droppedWrites++;
          active.manifest.recoveryState = "error";
          if (active.writesSinceFlush >= 10) {
            await this.writeManifest(active.manifestPath, active.manifest);
            active.writesSinceFlush = 0;
          }
          return;
        }

        await fs.appendFile(active.recordsPath, recordLine);
        await fs.appendFile(active.indexPath, indexLine);

        active.currentRecordOffset += recordLineBytes;
        active.manifest.bytesWritten += bytesToWrite;
        active.manifest.exchangeCount++;
        active.manifest.lastSequence = seq;
        active.manifest.lastError = null;
        active.manifest.recoveryState = "clean";
        active.manifest.lastFlushAt = Date.now();
        active.writesSinceFlush++;

        if (active.writesSinceFlush >= 10) {
          await this.writeManifest(active.manifestPath, active.manifest);
          active.writesSinceFlush = 0;
        }
      })
      .catch(async (err: unknown) => {
        active.manifest.lastError = err instanceof Error ? err.message : String(err);
        active.manifest.recoveryState = "error";
        active.manifest.droppedWrites++;
        try {
          await this.writeManifest(active.manifestPath, active.manifest);
        } catch {
          // Ignore nested write errors
        }
      });
  }

  async querySession(sessionId: string, query: SessionQuery = {}): Promise<SessionQueryResult> {
    const entries = await this.readSessionIndex(sessionId);
    const method = query.method?.toUpperCase();
    const hostnameContains = query.hostnameContains?.toLowerCase();
    const urlContains = query.urlContains?.toLowerCase();
    const text = query.text?.toLowerCase();

    const filtered = entries.filter((e) => {
      if (method && e.method !== method) return false;
      if (hostnameContains && !e.hostname.toLowerCase().includes(hostnameContains)) return false;
      if (urlContains && !e.url.toLowerCase().includes(urlContains)) return false;
      if (query.statusCode !== undefined && e.statusCode !== query.statusCode) return false;
      if (query.fromTs !== undefined && e.timestamp < query.fromTs) return false;
      if (query.toTs !== undefined && e.timestamp > query.toTs) return false;
      if (text) {
        const hay = `${e.url}\n${e.hostname}\n${e.path}\n${e.exchangeId}\n${e.matchedRuleId ?? ""}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });

    const sorted = filtered.sort((a, b) => {
      if (query.sort === "asc") return a.timestamp - b.timestamp;
      return b.timestamp - a.timestamp;
    });

    const offset = Math.max(0, query.offset ?? 0);
    const limit = Math.max(1, Math.min(5000, query.limit ?? 50));
    const items = sorted.slice(offset, offset + limit);

    return {
      total: sorted.length,
      limit,
      offset,
      items,
    };
  }

  async getSessionExchange(
    sessionId: string,
    opts: { seq?: number; exchangeId?: string; includeBody?: boolean },
  ): Promise<{ index: SessionIndexEntry; record?: PersistedExchangeRecord & { requestBodyText?: string | null; responseBodyText?: string | null } }> {
    const entry = await this.findIndexEntry(sessionId, opts);
    if (!entry) {
      throw new Error(`Exchange not found in session '${sessionId}'.`);
    }

    if (!opts.includeBody) {
      return { index: entry };
    }

    const record = await this.readRecordAtOffset(sessionId, entry.recordOffset, entry.recordLineBytes);
    return {
      index: entry,
      record: {
        ...record,
        requestBodyText: fromBase64(record.requestBodyBase64),
        responseBodyText: fromBase64(record.responseBodyBase64),
      },
    };
  }

  async exportHar(
    sessionId: string,
    opts: {
      outputFile?: string;
      query?: SessionQuery;
      includeBodies?: boolean;
    } = {},
  ): Promise<{ sessionId: string; outputFile: string; entries: number }> {
    const sessionDir = path.join(this.rootDir, sessionId);
    const manifest = await this.getSession(sessionId);
    const queryResult = await this.querySession(sessionId, { ...(opts.query ?? {}), limit: 500000, offset: 0 });
    const includeBodies = opts.includeBodies ?? true;

    const harEntries = [];
    for (const idx of queryResult.items) {
      const record = await this.readRecordAtOffset(sessionId, idx.recordOffset, idx.recordLineBytes);
      const req = record.exchange.request;
      const res = record.exchange.response;

      const reqBody = includeBodies ? fromBase64(record.requestBodyBase64) : null;
      const resBody = includeBodies ? fromBase64(record.responseBodyBase64) : null;

      const entry = {
        startedDateTime: new Date(record.exchange.timestamp).toISOString(),
        time: record.exchange.duration ?? 0,
        request: {
          method: req.method,
          url: req.url,
          httpVersion: "HTTP/1.1",
          headers: headersToHar(req.headers),
          queryString: queryToHar(req.url),
          headersSize: -1,
          bodySize: req.bodySize,
          ...(reqBody ? {
            postData: {
              mimeType: req.headers["content-type"] ?? "application/octet-stream",
              text: reqBody,
            },
          } : {}),
        },
        response: {
          status: res?.statusCode ?? 0,
          statusText: res?.statusMessage ?? "",
          httpVersion: "HTTP/1.1",
          headers: headersToHar(res?.headers),
          headersSize: -1,
          bodySize: res?.bodySize ?? 0,
          content: {
            size: res?.bodySize ?? 0,
            mimeType: res?.headers?.["content-type"] ?? "application/octet-stream",
            ...(resBody ? { text: resBody } : {}),
            ...(resBody ? {} : { text: res?.bodyPreview ?? "", comment: "Body preview only." }),
          },
        },
      };
      harEntries.push(entry);
    }

    const outputFile = opts.outputFile
      ? path.resolve(opts.outputFile)
      : path.join(sessionDir, manifest.files.harDir, `export-${Date.now()}.har`);

    await ensureDir(path.dirname(outputFile));

    const har = {
      log: {
        version: "1.2",
        creator: { name: "proxy-mcp", version: "1.0.0" },
        pages: [],
        entries: harEntries,
      },
    };

    await fs.writeFile(outputFile, JSON.stringify(har, null, 2), "utf8");
    return { sessionId, outputFile, entries: harEntries.length };
  }

  async deleteSession(sessionId: string): Promise<void> {
    const activeId = this.active?.manifest.id;
    if (activeId === sessionId) {
      throw new Error("Cannot delete the active session. Stop it first.");
    }
    const sessionDir = path.join(this.rootDir, sessionId);
    await fs.rm(sessionDir, { recursive: true, force: true });
  }

  async recoverSession(sessionId?: string): Promise<{
    recovered: Array<{ sessionId: string; exchanges: number; droppedTailBytes: number }>;
  }> {
    const ids = sessionId
      ? [sessionId]
      : (await this.listSessions()).map((s) => s.id);

    const recovered: Array<{ sessionId: string; exchanges: number; droppedTailBytes: number }> = [];

    for (const id of ids) {
      const sessionDir = path.join(this.rootDir, id);
      const recordsPath = path.join(sessionDir, RECORDS_FILENAME);
      const indexPath = path.join(sessionDir, INDEX_FILENAME);
      const manifestPath = path.join(sessionDir, MANIFEST_FILENAME);

      let manifest: SessionManifest;
      try {
        manifest = await this.getSession(id);
      } catch {
        continue;
      }

      const buffer = await fs.readFile(recordsPath);
      let cursor = 0;
      let seq = 0;
      let validBytes = 0;
      const indexLines: string[] = [];

      while (cursor < buffer.length) {
        const nl = buffer.indexOf(0x0a, cursor);
        const end = nl === -1 ? buffer.length : nl;
        const lineBuf = buffer.subarray(cursor, end);
        const lineBytes = (nl === -1 ? end - cursor : (end - cursor + 1));
        if (lineBuf.length === 0) {
          cursor = nl === -1 ? end : end + 1;
          validBytes += lineBytes;
          continue;
        }

        try {
          const parsed = JSON.parse(lineBuf.toString("utf8")) as PersistedExchangeRecord;
          seq++;
          const record = {
            ...parsed,
            seq,
          };
          const idx = this.toIndexEntry(record, { recordOffset: validBytes, recordLineBytes: lineBytes });
          indexLines.push(JSON.stringify(idx));
          validBytes += lineBytes;
          cursor = nl === -1 ? end : end + 1;
        } catch {
          break;
        }
      }

      if (validBytes < buffer.length) {
        await fs.truncate(recordsPath, validBytes);
      }

      await fs.writeFile(indexPath, `${indexLines.join("\n")}${indexLines.length > 0 ? "\n" : ""}`);

      manifest.exchangeCount = indexLines.length;
      manifest.lastSequence = indexLines.length;
      manifest.bytesWritten = validBytes + Buffer.byteLength(`${indexLines.join("\n")}${indexLines.length > 0 ? "\n" : ""}`);
      manifest.recoveryState = validBytes < buffer.length ? "recovered" : "clean";
      manifest.lastError = validBytes < buffer.length ? "Recovered from truncated tail." : null;
      manifest.lastFlushAt = Date.now();
      if (manifest.status === "active") {
        manifest.status = "stopped";
        manifest.endedAt = Date.now();
      }
      await this.writeManifest(manifestPath, manifest);

      recovered.push({
        sessionId: id,
        exchanges: indexLines.length,
        droppedTailBytes: Math.max(0, buffer.length - validBytes),
      });
    }

    return { recovered };
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
    const manifest = await this.getSession(sessionId);
    const entries = await this.readSessionIndex(sessionId);
    const methods: Record<string, number> = {};
    const statuses: Record<string, number> = {};
    const hosts: Record<string, number> = {};
    let durationSum = 0;
    let durationCount = 0;

    for (const e of entries) {
      methods[e.method] = (methods[e.method] || 0) + 1;
      if (e.statusCode !== null) {
        const k = String(e.statusCode);
        statuses[k] = (statuses[k] || 0) + 1;
      }
      hosts[e.hostname] = (hosts[e.hostname] || 0) + 1;
      if (e.duration !== null) {
        durationSum += e.duration;
        durationCount++;
      }
    }

    const topHostnames = Object.entries(hosts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([hostname, count]) => ({ hostname, count }));

    return {
      manifest,
      totals: {
        exchanges: entries.length,
        avgDurationMs: durationCount > 0 ? Math.round(durationSum / durationCount) : null,
        topHostnames,
        statuses,
        methods,
      },
    };
  }

  async getSessionTimeline(
    sessionId: string,
    bucketMs = 60_000,
  ): Promise<Array<{ bucketStart: number; count: number; errorCount: number }>> {
    const entries = await this.readSessionIndex(sessionId);
    const buckets = new Map<number, { count: number; errorCount: number }>();

    for (const e of entries) {
      const b = Math.floor(e.timestamp / bucketMs) * bucketMs;
      const entry = buckets.get(b) ?? { count: 0, errorCount: 0 };
      entry.count++;
      if (e.statusCode !== null && e.statusCode >= 400) {
        entry.errorCount++;
      }
      buckets.set(b, entry);
    }

    return [...buckets.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([bucketStart, stats]) => ({
        bucketStart,
        count: stats.count,
        errorCount: stats.errorCount,
      }));
  }

  async getSessionFindings(sessionId: string): Promise<{
    highErrorEndpoints: Array<{ endpoint: string; errors: number }>;
    slowestExchanges: Array<{ exchangeId: string; duration: number; url: string }>;
    hostErrorRates: Array<{ hostname: string; total: number; errors: number; errorRate: number }>;
  }> {
    const entries = await this.readSessionIndex(sessionId);
    const endpointErrors = new Map<string, number>();
    const hostStats = new Map<string, { total: number; errors: number }>();

    for (const e of entries) {
      const endpoint = `${e.hostname}${e.path}`;
      const host = e.hostname;
      const hs = hostStats.get(host) ?? { total: 0, errors: 0 };
      hs.total++;
      if (e.statusCode !== null && e.statusCode >= 400) {
        hs.errors++;
        endpointErrors.set(endpoint, (endpointErrors.get(endpoint) ?? 0) + 1);
      }
      hostStats.set(host, hs);
    }

    const highErrorEndpoints = [...endpointErrors.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([endpoint, errors]) => ({ endpoint, errors }));

    const slowestExchanges = entries
      .filter((e) => e.duration !== null)
      .sort((a, b) => (b.duration ?? 0) - (a.duration ?? 0))
      .slice(0, 10)
      .map((e) => ({
        exchangeId: e.exchangeId,
        duration: e.duration ?? 0,
        url: e.url,
      }));

    const hostErrorRates = [...hostStats.entries()]
      .map(([hostname, s]) => ({
        hostname,
        total: s.total,
        errors: s.errors,
        errorRate: s.total > 0 ? s.errors / s.total : 0,
      }))
      .sort((a, b) => b.errorRate - a.errorRate)
      .slice(0, 10);

    return { highErrorEndpoints, slowestExchanges, hostErrorRates };
  }

  private toIndexEntry(
    record: PersistedExchangeRecord,
    location: { recordOffset: number; recordLineBytes: number },
  ): SessionIndexEntry {
    const exchange = record.exchange;
    return {
      seq: record.seq,
      exchangeId: exchange.id,
      timestamp: exchange.timestamp,
      method: exchange.request.method,
      hostname: exchange.request.hostname,
      path: exchange.request.path,
      url: exchange.request.url,
      statusCode: exchange.response?.statusCode ?? null,
      duration: exchange.duration ?? null,
      requestBodySize: exchange.request.bodySize,
      responseBodySize: exchange.response?.bodySize ?? null,
      hasResponse: !!exchange.response,
      hasFullRequestBody: !!record.requestBodyBase64,
      hasFullResponseBody: !!record.responseBodyBase64,
      matchedRuleId: exchange.matchedRuleId ?? null,
      ja3: exchange.tls?.client?.ja3Fingerprint ?? null,
      ja4: exchange.tls?.client?.ja4Fingerprint ?? null,
      ja3s: exchange.tls?.server?.ja3sFingerprint ?? null,
      recordOffset: location.recordOffset,
      recordLineBytes: location.recordLineBytes,
    };
  }

  private convertHarEntry(
    entry: unknown,
    seq: number,
    sessionId: string,
  ):
    | {
      ok: true;
      exchange: CapturedExchange;
      requestBody?: Buffer;
      responseBody?: Buffer;
      warnings: string[];
    }
    | { ok: false; error: string } {
    if (!entry || typeof entry !== "object") {
      return { ok: false, error: `HAR entry #${seq}: entry is not an object.` };
    }
    const e = entry as Record<string, unknown>;

    const requestObj = e.request;
    if (!requestObj || typeof requestObj !== "object") {
      return { ok: false, error: `HAR entry #${seq}: missing request object.` };
    }
    const req = requestObj as Record<string, unknown>;
    if (typeof req.method !== "string" || req.method.length === 0) {
      return { ok: false, error: `HAR entry #${seq}: missing request.method.` };
    }
    if (typeof req.url !== "string" || req.url.length === 0) {
      return { ok: false, error: `HAR entry #${seq}: missing request.url.` };
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(req.url);
    } catch (err) {
      return {
        ok: false,
        error: `HAR entry #${seq}: invalid request.url (${err instanceof Error ? err.message : String(err)}).`,
      };
    }

    const warnings: string[] = [];
    const requestHeaders = headersArrayToRecord(req.headers);
    const requestPostData = req.postData && typeof req.postData === "object"
      ? req.postData as Record<string, unknown>
      : null;
    const requestBody = requestPostData && typeof requestPostData.text === "string"
      ? decodeHarText(requestPostData.text, typeof requestPostData.encoding === "string" ? requestPostData.encoding : undefined)
      : undefined;
    const requestBodyText = requestBody ? requestBody.toString("utf8") : "";
    const requestBodySize = typeof req.bodySize === "number" && Number.isFinite(req.bodySize) && req.bodySize >= 0
      ? req.bodySize
      : requestBody?.length ?? 0;

    let timestamp = Date.now();
    if (typeof e.startedDateTime === "string") {
      const parsed = Date.parse(e.startedDateTime);
      if (Number.isFinite(parsed)) {
        timestamp = parsed;
      } else {
        warnings.push(`HAR entry #${seq}: invalid startedDateTime, using import time.`);
      }
    } else {
      warnings.push(`HAR entry #${seq}: missing startedDateTime, using import time.`);
    }

    const responseObj = e.response && typeof e.response === "object"
      ? e.response as Record<string, unknown>
      : null;

    let response:
      | {
        statusCode: number;
        statusMessage: string;
        headers: Record<string, string>;
        bodyPreview: string;
        bodySize: number;
      }
      | undefined;
    let responseBody: Buffer | undefined;

    if (responseObj) {
      const responseHeaders = headersArrayToRecord(responseObj.headers);
      const contentObj = responseObj.content && typeof responseObj.content === "object"
        ? responseObj.content as Record<string, unknown>
        : null;

      if (contentObj && typeof contentObj.text === "string") {
        responseBody = decodeHarText(
          contentObj.text,
          typeof contentObj.encoding === "string" ? contentObj.encoding : undefined,
        );
      }

      const statusCodeRaw = responseObj.status;
      const statusCode = typeof statusCodeRaw === "number" && Number.isFinite(statusCodeRaw)
        ? Math.max(0, Math.trunc(statusCodeRaw))
        : 0;
      const statusMessage = typeof responseObj.statusText === "string" ? responseObj.statusText : "";
      const responseBodySize = typeof responseObj.bodySize === "number" && Number.isFinite(responseObj.bodySize) && responseObj.bodySize >= 0
        ? responseObj.bodySize
        : responseBody?.length ?? 0;
      const responseBodyText = responseBody ? responseBody.toString("utf8") : "";
      response = {
        statusCode,
        statusMessage,
        headers: responseHeaders,
        bodyPreview: capString(responseBodyText, IMPORT_BODY_PREVIEW_MAX),
        bodySize: responseBodySize,
      };
    } else {
      warnings.push(`HAR entry #${seq}: missing response object.`);
    }

    const duration = typeof e.time === "number" && Number.isFinite(e.time)
      ? Math.max(0, Math.round(e.time))
      : undefined;

    const exchange: CapturedExchange = {
      id: `har_${sessionId}_${seq}`,
      timestamp,
      request: {
        method: req.method.toUpperCase(),
        url: req.url,
        hostname: parsedUrl.hostname,
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        headers: requestHeaders,
        bodyPreview: capString(requestBodyText, IMPORT_BODY_PREVIEW_MAX),
        bodySize: requestBodySize,
      },
      ...(response ? { response } : {}),
      ...(duration !== undefined ? { duration } : {}),
    };

    return { ok: true, exchange, requestBody, responseBody, warnings };
  }

  private async readSessionIndex(sessionId: string): Promise<SessionIndexEntry[]> {
    const indexPath = path.join(this.rootDir, sessionId, INDEX_FILENAME);
    const raw = await fs.readFile(indexPath, "utf8").catch(() => "");
    if (!raw.trim()) return [];
    const lines = raw.split("\n").filter(Boolean);
    const out: SessionIndexEntry[] = [];
    for (const line of lines) {
      try {
        out.push(JSON.parse(line) as SessionIndexEntry);
      } catch {
        // skip malformed lines
      }
    }
    return out;
  }

  private async findIndexEntry(
    sessionId: string,
    opts: { seq?: number; exchangeId?: string },
  ): Promise<SessionIndexEntry | null> {
    if (opts.seq === undefined && !opts.exchangeId) {
      throw new Error("Provide either seq or exchangeId.");
    }
    const entries = await this.readSessionIndex(sessionId);
    const found = entries.find((e) => (opts.seq !== undefined ? e.seq === opts.seq : e.exchangeId === opts.exchangeId));
    return found ?? null;
  }

  private async readRecordAtOffset(
    sessionId: string,
    offset: number,
    lineBytes: number,
  ): Promise<PersistedExchangeRecord> {
    const recordsPath = path.join(this.rootDir, sessionId, RECORDS_FILENAME);
    const fh = await fs.open(recordsPath, "r");
    try {
      const buf = Buffer.alloc(lineBytes);
      const read = await fh.read(buf, 0, lineBytes, offset);
      const line = buf.subarray(0, read.bytesRead).toString("utf8").trimEnd();
      return JSON.parse(line) as PersistedExchangeRecord;
    } finally {
      await fh.close();
    }
  }

  private async writeManifest(manifestPath: string, manifest: SessionManifest): Promise<void> {
    const tmp = `${manifestPath}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(manifest, null, 2), "utf8");
    await fs.rename(tmp, manifestPath);
  }
}
