/**
 * CycleTLS wrapper for JA3 fingerprint spoofing.
 *
 * Spawns a Go subprocess (CycleTLS) that handles TLS with custom JA3 strings.
 * Lazy singleton: process starts on first spoofed request, reused across calls.
 */

import type { CycleTLSClient, CycleTLSRequestOptions } from "cycletls";

let instance: CycleTLSClient | null = null;
let initPromise: Promise<CycleTLSClient> | null = null;

/**
 * Get or create the CycleTLS singleton.
 */
async function getCycleTLS(): Promise<CycleTLSClient> {
  if (instance) return instance;

  if (!initPromise) {
    initPromise = (async () => {
      // Dynamic import to handle CJS → ESM interop
      const mod = await import("cycletls");
      const init = mod.default ?? mod;
      const client: CycleTLSClient = await (init as unknown as (opts?: Record<string, unknown>) => Promise<CycleTLSClient>)();
      instance = client;
      return client;
    })();
  }

  return initPromise;
}

export interface SpoofedResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

export interface SpoofOptions {
  method: string;
  headers?: Record<string, string>;
  body?: string;
  ja3: string;
  userAgent?: string;
  proxy?: string;
  http2Fingerprint?: string;
  headerOrder?: string[];
  orderAsProvided?: boolean;
  disableGrease?: boolean;
  disableRedirect?: boolean;
  forceHTTP1?: boolean;
  insecureSkipVerify?: boolean;
  cookies?: Array<object> | { [key: string]: string };
}

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

/**
 * Re-sort headers according to the provided headerOrder.
 * Headers listed in the order come first (in that order);
 * unlisted headers are appended at the end in their original order.
 */
export function reorderHeaders(
  headers: Record<string, string>,
  headerOrder: string[],
): Record<string, string> {
  const orderLower = headerOrder.map((h) => h.toLowerCase());
  const orderSet = new Set(orderLower);
  const result: Record<string, string> = {};

  // Add headers in the specified order
  for (const key of orderLower) {
    // Find the matching header (case-insensitive)
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === key) {
        result[k] = v;
        break;
      }
    }
  }

  // Append any remaining headers not in the order
  for (const [k, v] of Object.entries(headers)) {
    if (!orderSet.has(k.toLowerCase())) {
      result[k] = v;
    }
  }

  return result;
}

/**
 * Make an HTTP request with a spoofed JA3 fingerprint via CycleTLS.
 */
export async function spoofedRequest(url: string, opts: SpoofOptions): Promise<SpoofedResponse> {
  const cycle = await getCycleTLS();

  // Compatibility-first: send headers exactly as received from mockttp and let
  // CycleTLS apply headerOrder/orderAsProvided if configured.
  const headers = opts.headers || {};

  const requestOpts: CycleTLSRequestOptions = {
    ja3: opts.ja3,
    userAgent: opts.userAgent || getHeader(headers, "user-agent") || "",
    headers,
    body: opts.body || "",
    proxy: opts.proxy || "",
  };

  // Conditionally include new CycleTLS fields (only when defined)
  if (opts.http2Fingerprint !== undefined) requestOpts.http2Fingerprint = opts.http2Fingerprint;
  if (opts.headerOrder !== undefined) requestOpts.headerOrder = opts.headerOrder;
  if (opts.orderAsProvided !== undefined) requestOpts.orderAsProvided = opts.orderAsProvided;
  if (opts.disableGrease !== undefined) requestOpts.disableGrease = opts.disableGrease;
  if (opts.disableRedirect !== undefined) requestOpts.disableRedirect = opts.disableRedirect;
  if (opts.forceHTTP1 !== undefined) requestOpts.forceHTTP1 = opts.forceHTTP1;
  if (opts.insecureSkipVerify !== undefined) requestOpts.insecureSkipVerify = opts.insecureSkipVerify;
  if (opts.cookies !== undefined) requestOpts.cookies = opts.cookies;

  const response = await cycle(url, requestOpts, opts.method.toLowerCase() as "get" | "post" | "put" | "delete" | "patch" | "head" | "options");

  // CycleTLS returns headers as Record<string, any>
  const responseHeaders: Record<string, string> = {};
  if (response.headers) {
    for (const [k, v] of Object.entries(response.headers)) {
      responseHeaders[k.toLowerCase()] = String(v);
    }
  }

  const body = Buffer.from(await response.arrayBuffer());

  // Let mockttp compute length/transfer encoding after any automatic
  // Content-Encoding transformation.
  delete responseHeaders["content-length"];
  delete responseHeaders["transfer-encoding"];

  return {
    status: response.status,
    headers: responseHeaders,
    body,
  };
}

/**
 * Shut down the CycleTLS subprocess. Called when spoofing is disabled or proxy stops.
 */
export async function shutdownCycleTLS(): Promise<void> {
  if (instance) {
    try {
      await instance.exit();
    } catch {
      // Ignore shutdown errors
    }
    instance = null;
    initPromise = null;
  }
}
