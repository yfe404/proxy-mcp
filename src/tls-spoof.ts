/**
 * TLS + HTTP/2 fingerprint spoofing via impit (native Rust NAPI module).
 *
 * Replaces the former Docker/curl-impersonate backend with a direct in-process
 * call to impit's fetch(), which handles TLS fingerprinting, HTTP/2 frame
 * ordering, and header normalization natively via rustls.
 */

import { Impit } from "impit";
import { resolveBrowserPreset } from "./browser-presets.js";

// ── Public types ──

export interface SpoofedResponse {
  status: number;
  headers: Record<string, string | string[]>;
  body: Buffer;
}

export interface SpoofOptions {
  method: string;
  headers?: Record<string, string>;
  body?: string;
  userAgent?: string;
  proxy?: string;
  disableRedirect?: boolean;
  insecureSkipVerify?: boolean;
  cookies?: Array<object> | { [key: string]: string };
  preset?: string;           // browser preset name → selects impitBrowser
}

export interface FingerprintRuntimeCheck {
  status: "success";
  ready: boolean;
  backend: string;
}

// ── Utilities (kept from original — still needed) ──

/** @internal */
export function responseDataToBuffer(data: unknown): Buffer {
  if (!data) return Buffer.alloc(0);
  if (typeof data === "string") return Buffer.from(data, "utf-8");
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);

  // Some libraries serialize Buffers as { type: "Buffer", data: number[] }
  if (typeof data === "object") {
    const maybe = data as { type?: unknown; data?: unknown };
    if (maybe.type === "Buffer" && Array.isArray(maybe.data)) {
      return Buffer.from(maybe.data as number[]);
    }
  }

  try {
    return Buffer.from(JSON.stringify(data), "utf-8");
  } catch {
    return Buffer.from(String(data), "utf-8");
  }
}

function getHeader(headers: Record<string, string>, name: string): string | undefined {
  const needle = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === needle) return v;
  }
  return undefined;
}

/** @internal */
export function stripHopByHopHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};

  // RFC 9110: Connection is hop-by-hop and may list additional hop-by-hop headers.
  const connection = getHeader(headers, "connection");
  const connectionTokens = new Set<string>();
  if (connection) {
    for (const token of connection.split(",")) {
      const t = token.trim().toLowerCase();
      if (t) connectionTokens.add(t);
    }
  }

  for (const [k, v] of Object.entries(headers)) {
    const kl = k.toLowerCase();
    if (kl === "connection") continue;
    if (connectionTokens.has(kl)) continue;
    if (kl === "proxy-connection") continue;
    if (kl === "keep-alive") continue;
    if (kl === "transfer-encoding") continue;
    if (kl === "upgrade") continue;
    if (kl === "proxy-authenticate") continue;
    if (kl === "proxy-authorization") continue;
    out[k] = v;
  }

  return out;
}

// ── Main request function ──

/**
 * Make an HTTP request with a spoofed TLS + HTTP/2 fingerprint via impit.
 */
export async function spoofedRequest(url: string, opts: SpoofOptions): Promise<SpoofedResponse> {
  // 1. Resolve preset → impit browser name
  let browser: string = "chrome131";
  if (opts.preset) {
    try {
      const preset = resolveBrowserPreset(opts.preset);
      browser = preset.impitBrowser;
    } catch { /* fall through to default */ }
  }

  // 2. Build Impit instance (per-request — different proxy/preset combos)
  // When chaining through an upstream proxy, the proxy may present its own TLS
  // certificate for CONNECT tunneling. ignoreTlsErrors must be true to allow this.
  const impit = new Impit({
    browser: browser as any,
    proxyUrl: opts.proxy,
    ignoreTlsErrors: opts.insecureSkipVerify ?? !!opts.proxy,
    followRedirects: !opts.disableRedirect,
    maxRedirects: opts.disableRedirect ? 0 : 10,
    timeout: 45_000,
    headers: opts.userAgent ? { "user-agent": opts.userAgent } : undefined,
  });

  // 3. Merge cookies into headers
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.cookies && typeof opts.cookies === "object" && !Array.isArray(opts.cookies)) {
    const cookieStr = Object.entries(opts.cookies as Record<string, string>)
      .map(([k, v]) => `${k}=${v}`).join("; ");
    if (cookieStr) {
      const existing = getHeader(headers, "cookie");
      if (existing) {
        headers["cookie"] = `${existing}; ${cookieStr}`;
      } else {
        headers["cookie"] = cookieStr;
      }
    }
  }

  // 4. Execute fetch
  const method = opts.method.toUpperCase();
  const response = await impit.fetch(url, {
    method: method as any,
    headers,
    body: opts.body,
  });

  // 5. Convert response
  const bodyBytes = await response.bytes();
  const responseHeaders: Record<string, string | string[]> = {};

  // Handle set-cookie as array (getSetCookie API)
  const setCookies = (response.headers as any).getSetCookie?.();
  if (setCookies && setCookies.length > 0) {
    responseHeaders["set-cookie"] = setCookies;
  }
  for (const [key, value] of response.headers.entries()) {
    const lk = key.toLowerCase();
    if (lk === "set-cookie") continue; // already handled above
    responseHeaders[lk] = value;
  }

  // Strip encoding headers (impit already decompresses)
  delete responseHeaders["content-length"];
  delete responseHeaders["transfer-encoding"];
  delete responseHeaders["content-encoding"];

  return { status: response.status, headers: responseHeaders, body: Buffer.from(bodyBytes) };
}

// ── Runtime check ──

/**
 * Check fingerprint spoofing backend readiness.
 */
export async function checkSpoofRuntime(): Promise<FingerprintRuntimeCheck> {
  try {
    new Impit({ browser: "chrome131" as any });
    return { status: "success", ready: true, backend: "impit-node" };
  } catch {
    return { status: "success", ready: false, backend: "impit-node" };
  }
}

// ── Shutdown ──

/**
 * No-op: impit is in-process, no container to shut down.
 */
export async function shutdownSpoofContainer(): Promise<void> {
  // No-op: impit is in-process, no container to shut down.
}

/**
 * @deprecated Use shutdownSpoofContainer(). Kept for backward compat during transition.
 */
export const shutdownCycleTLS = shutdownSpoofContainer;
