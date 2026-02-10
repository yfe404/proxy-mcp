/**
 * CycleTLS wrapper for JA3 fingerprint spoofing.
 *
 * Spawns a Go subprocess (CycleTLS) that handles TLS with custom JA3 strings.
 * Lazy singleton: process starts on first spoofed request, reused across calls.
 */

import type { CycleTLSClient } from "cycletls";

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
}

/**
 * Make an HTTP request with a spoofed JA3 fingerprint via CycleTLS.
 */
export async function spoofedRequest(url: string, opts: SpoofOptions): Promise<SpoofedResponse> {
  const cycle = await getCycleTLS();

  const response = await cycle(url, {
    ja3: opts.ja3,
    userAgent: opts.userAgent || opts.headers?.["user-agent"] || "",
    headers: opts.headers || {},
    body: opts.body || "",
    proxy: opts.proxy || "",
  }, opts.method.toLowerCase() as "get" | "post" | "put" | "delete" | "patch" | "head" | "options");

  // CycleTLS returns headers as Record<string, any>
  const responseHeaders: Record<string, string> = {};
  if (response.headers) {
    for (const [k, v] of Object.entries(response.headers)) {
      responseHeaders[k.toLowerCase()] = String(v);
    }
  }

  return {
    status: response.status,
    headers: responseHeaders,
    body: typeof response.data === "string" ? response.data : JSON.stringify(response.data),
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
