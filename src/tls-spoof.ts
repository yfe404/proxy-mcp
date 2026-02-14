/**
 * CycleTLS wrapper for JA3 fingerprint spoofing.
 *
 * Spawns a Go subprocess (CycleTLS) that handles TLS with custom JA3 strings.
 * Lazy singleton: process starts on first spoofed request, reused across calls.
 */

import type { CycleTLSClient, CycleTLSRequestOptions } from "cycletls";
import { gunzipSync, brotliDecompressSync, inflateSync } from "node:zlib";

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
  body: string;
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

  const headers = opts.headerOrder && opts.headers
    ? reorderHeaders(opts.headers, opts.headerOrder)
    : (opts.headers || {});

  const requestOpts: CycleTLSRequestOptions = {
    ja3: opts.ja3,
    userAgent: opts.userAgent || headers["user-agent"] || "",
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

  // CycleTLS may return compressed data as a Buffer-like object.
  // Decompress it and strip the content-encoding header so the
  // downstream proxy can serve it as plain text to the browser.
  let body: string;
  const encoding = responseHeaders["content-encoding"];

  if (typeof response.data !== "string" && response.data && typeof response.data === "object") {
    // Buffer-like: { type: "Buffer", data: number[] }
    const buf = Buffer.from(
      (response.data as { type?: string; data?: number[] }).data ?? response.data as unknown as number[],
    );
    try {
      if (encoding === "gzip" || encoding === "x-gzip") {
        body = gunzipSync(buf).toString("utf-8");
        delete responseHeaders["content-encoding"];
      } else if (encoding === "br") {
        body = brotliDecompressSync(buf).toString("utf-8");
        delete responseHeaders["content-encoding"];
      } else if (encoding === "deflate") {
        body = inflateSync(buf).toString("utf-8");
        delete responseHeaders["content-encoding"];
      } else {
        body = buf.toString("utf-8");
      }
    } catch {
      // If decompression fails, pass raw bytes as utf-8
      body = buf.toString("utf-8");
    }
  } else {
    body = typeof response.data === "string" ? response.data : JSON.stringify(response.data);
  }

  // Remove content-length since decompression changes the size
  delete responseHeaders["content-length"];
  // Remove transfer-encoding since we're returning a complete body
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
