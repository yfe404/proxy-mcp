/**
 * CDP (Chrome DevTools Protocol) helpers.
 *
 * Used to expose ready-to-use endpoints for attaching Playwright/CDP clients
 * to a Chrome instance launched by proxy-mcp.
 */

export interface FetchJsonOptions {
  timeoutMs?: number;
}

interface CdpCommandErrorPayload {
  code?: number;
  message?: string;
  data?: unknown;
}

interface CdpCommandResponse {
  id?: number;
  result?: Record<string, unknown>;
  error?: CdpCommandErrorPayload;
}

interface MinimalWebSocketEvent {
  data?: unknown;
}

interface MinimalWebSocket {
  addEventListener(type: string, listener: (event: unknown) => void): void;
  removeEventListener(type: string, listener: (event: unknown) => void): void;
  close(code?: number, reason?: string): void;
  send(data: string): void;
}

interface MinimalWebSocketCtor {
  new(url: string): MinimalWebSocket;
}

export interface SendCdpCommandOptions {
  timeoutMs?: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorToString(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

function getWebSocketCtor(): MinimalWebSocketCtor {
  const ctor = (globalThis as unknown as { WebSocket?: unknown }).WebSocket;
  if (typeof ctor !== "function") {
    throw new Error("WebSocket is not available in this Node runtime. Use Node.js 22+.");
  }
  return ctor as MinimalWebSocketCtor;
}

function messageDataToString(event: unknown): string {
  const data = (event as MinimalWebSocketEvent | undefined)?.data ?? event;

  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf-8");
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf-8");
  }
  if (data === null || data === undefined) return "";
  return String(data);
}

export function getCdpBaseUrl(port: number): string {
  return `http://127.0.0.1:${port}`;
}

export function getCdpVersionUrl(port: number): string {
  return `${getCdpBaseUrl(port)}/json/version`;
}

export function getCdpTargetsUrl(port: number): string {
  return `${getCdpBaseUrl(port)}/json/list`;
}

export async function fetchJson<T = unknown>(url: string, opts: FetchJsonOptions = {}): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? 1000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "accept": "application/json" },
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status} from ${url}${text ? `: ${text.slice(0, 200)}` : ""}`);
    }

    return await res.json() as T;
  } finally {
    clearTimeout(timer);
  }
}

export async function getCdpVersion(port: number, opts: FetchJsonOptions = {}): Promise<Record<string, unknown>> {
  return await fetchJson<Record<string, unknown>>(getCdpVersionUrl(port), opts);
}

export async function getCdpTargets(port: number, opts: FetchJsonOptions = {}): Promise<Array<Record<string, unknown>>> {
  return await fetchJson<Array<Record<string, unknown>>>(getCdpTargetsUrl(port), opts);
}

export interface WaitForCdpOptions {
  timeoutMs?: number;
  intervalMs?: number;
  requestTimeoutMs?: number;
}

export async function waitForCdpVersion(port: number, opts: WaitForCdpOptions = {}): Promise<Record<string, unknown>> {
  const timeoutMs = opts.timeoutMs ?? 3000;
  const intervalMs = opts.intervalMs ?? 200;
  const requestTimeoutMs = opts.requestTimeoutMs ?? Math.min(1000, timeoutMs);

  const startedAt = Date.now();
  let lastErr: unknown;

  while (Date.now() - startedAt < timeoutMs) {
    try {
      return await getCdpVersion(port, { timeoutMs: requestTimeoutMs });
    } catch (e) {
      lastErr = e;
      await sleep(intervalMs);
    }
  }

  throw new Error(`CDP not responding at ${getCdpVersionUrl(port)} within ${timeoutMs}ms${lastErr ? `: ${errorToString(lastErr)}` : ""}`);
}

/**
 * Send a single CDP command to a target WebSocket endpoint and wait for its reply.
 * Useful for deterministic one-shot actions (e.g. Page.navigate) from MCP tools.
 */
// ── Persistent CDP session ───────────────────────────────────────────

interface PendingCommand {
  resolve: (result: Record<string, unknown>) => void;
  reject: (err: Error) => void;
  method: string;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Persistent WebSocket connection to a CDP target.
 *
 * Unlike `sendCdpCommand()` (fire-and-forget, one WS per command), CdpSession
 * keeps the socket open so session-scoped CDP domains like `Emulation` remain
 * active for the browser tab's lifetime.
 */
export class CdpSession {
  private _ws: MinimalWebSocket;
  private _closed = false;
  private _nextId = 1;
  private _pending = new Map<number, PendingCommand>();

  private constructor(ws: MinimalWebSocket) {
    this._ws = ws;

    ws.addEventListener("message", this._onMessage);
    ws.addEventListener("close", this._onClose);
    ws.addEventListener("error", this._onError);
  }

  /** Open a persistent CDP session to `wsUrl`. */
  static async open(wsUrl: string, opts?: { timeoutMs?: number }): Promise<CdpSession> {
    const timeoutMs = opts?.timeoutMs ?? 5000;
    const WS = getWebSocketCtor();
    const ws = new WS(wsUrl);

    return new Promise<CdpSession>((resolve, reject) => {
      let done = false;
      const timer = setTimeout(() => {
        if (done) return;
        done = true;
        try { ws.close(); } catch { /* */ }
        reject(new Error(`CdpSession: connection to ${wsUrl} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const onOpen = (): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        ws.removeEventListener("open", onOpen);
        ws.removeEventListener("error", onErr);
        resolve(new CdpSession(ws));
      };

      const onErr = (): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        ws.removeEventListener("open", onOpen);
        ws.removeEventListener("error", onErr);
        reject(new Error(`CdpSession: failed to connect to ${wsUrl}`));
      };

      ws.addEventListener("open", onOpen);
      ws.addEventListener("error", onErr);
    });
  }

  get closed(): boolean {
    return this._closed;
  }

  /** Send a CDP command and wait for its response. */
  async send(
    method: string,
    params?: Record<string, unknown>,
    opts?: { timeoutMs?: number },
  ): Promise<Record<string, unknown>> {
    if (this._closed) throw new Error("CdpSession is closed");

    const timeoutMs = opts?.timeoutMs ?? 5000;
    const id = this._nextId++;

    return new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`CdpSession: timeout waiting for '${method}' (id=${id}) after ${timeoutMs}ms`));
      }, timeoutMs);

      this._pending.set(id, { resolve, reject, method, timer });

      try {
        this._ws.send(JSON.stringify({ id, method, ...(params ? { params } : {}) }));
      } catch (e) {
        this._pending.delete(id);
        clearTimeout(timer);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  /** Cleanly close the session. */
  close(): void {
    if (this._closed) return;
    this._closed = true;

    // Reject all pending commands
    for (const [id, pending] of this._pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`CdpSession closed while '${pending.method}' (id=${id}) was pending`));
    }
    this._pending.clear();

    this._ws.removeEventListener("message", this._onMessage);
    this._ws.removeEventListener("close", this._onClose);
    this._ws.removeEventListener("error", this._onError);

    try { this._ws.close(1000, "CdpSession.close"); } catch { /* */ }
  }

  // ── Internal event handlers (arrow fns for stable `this`) ──

  private _onMessage = (event: unknown): void => {
    let payload: CdpCommandResponse;
    try {
      payload = JSON.parse(messageDataToString(event)) as CdpCommandResponse;
    } catch {
      return; // ignore non-JSON frames (CDP events)
    }

    if (payload.id == null) return; // CDP event, not a command response
    const pending = this._pending.get(payload.id);
    if (!pending) return;

    this._pending.delete(payload.id);
    clearTimeout(pending.timer);

    if (payload.error) {
      const msg = payload.error.message || "Unknown CDP error";
      pending.reject(new Error(`CDP ${pending.method} failed: ${msg}`));
    } else {
      pending.resolve(payload.result ?? {});
    }
  };

  private _onClose = (): void => {
    if (!this._closed) {
      this._closed = true;
      for (const [, pending] of this._pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error(`CdpSession WebSocket closed unexpectedly`));
      }
      this._pending.clear();
    }
  };

  private _onError = (): void => {
    // Error is typically followed by close; just mark closed
    if (!this._closed) {
      this._closed = true;
      for (const [, pending] of this._pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error(`CdpSession WebSocket error`));
      }
      this._pending.clear();
    }
  };
}

/**
 * Send a single CDP command to a target WebSocket endpoint and wait for its reply.
 * Useful for deterministic one-shot actions (e.g. Page.navigate) from MCP tools.
 */
export async function sendCdpCommand(
  wsUrl: string,
  method: string,
  params?: Record<string, unknown>,
  opts: SendCdpCommandOptions = {},
): Promise<Record<string, unknown>> {
  const timeoutMs = opts.timeoutMs ?? 3000;
  const WS = getWebSocketCtor();
  const commandId = Math.floor(Math.random() * 1_000_000_000);

  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    const socket = new WS(wsUrl);
    let done = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const finishOk = (result: Record<string, unknown>): void => {
      if (done) return;
      done = true;
      cleanup();
      try { socket.close(1000, "done"); } catch { /* ignore */ }
      resolve(result);
    };

    const finishErr = (err: unknown): void => {
      if (done) return;
      done = true;
      cleanup();
      try { socket.close(1000, "error"); } catch { /* ignore */ }
      reject(err instanceof Error ? err : new Error(errorToString(err)));
    };

    const onOpen = (): void => {
      try {
        socket.send(JSON.stringify({
          id: commandId,
          method,
          ...(params ? { params } : {}),
        }));
      } catch (e) {
        finishErr(e);
      }
    };

    const onMessage = (event: unknown): void => {
      let payload: CdpCommandResponse;
      try {
        payload = JSON.parse(messageDataToString(event)) as CdpCommandResponse;
      } catch {
        // Ignore unrelated/invalid frames.
        return;
      }
      if (payload.id !== commandId) return;
      if (payload.error) {
        const msg = payload.error.message || "Unknown CDP error";
        finishErr(new Error(`CDP ${method} failed: ${msg}`));
        return;
      }
      finishOk(payload.result ?? {});
    };

    const onError = (): void => {
      finishErr(new Error(`WebSocket error while sending CDP command '${method}' to ${wsUrl}`));
    };

    const onClose = (): void => {
      if (!done) {
        finishErr(new Error(`WebSocket closed before CDP command '${method}' completed`));
      }
    };

    const cleanup = (): void => {
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("error", onError);
      socket.removeEventListener("close", onClose);
      if (timer) clearTimeout(timer);
      timer = null;
    };

    socket.addEventListener("open", onOpen);
    socket.addEventListener("message", onMessage);
    socket.addEventListener("error", onError);
    socket.addEventListener("close", onClose);

    timer = setTimeout(() => {
      finishErr(new Error(`Timeout waiting for CDP '${method}' response after ${timeoutMs}ms`));
    }, timeoutMs);
  });
}
