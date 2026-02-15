/**
 * curl-impersonate wrapper for TLS + HTTP/2 fingerprint spoofing.
 *
 * Runs curl-impersonate inside a Docker container (debian:bookworm-slim based
 * image with pre-installed binaries from the lexiforest/curl-impersonate fork).
 * The container uses host networking and stays alive via `sleep infinity` so
 * requests are issued via `docker exec`.
 *
 * Replaces the former CycleTLS backend — curl-impersonate uses BoringSSL +
 * nghttp2 (same libs as Chrome), so TLS 1.3 and HTTP/2 fingerprints match
 * real browsers by construction.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Docker from "dockerode";
import { resolveBrowserPreset } from "./browser-presets.js";

const execFileAsync = promisify(execFile);

// Detect container runtime: prefer docker, fall back to podman.
let _containerCli: string | null = null;
async function containerCli(): Promise<string> {
  if (_containerCli) return _containerCli;
  for (const bin of ["docker", "podman"]) {
    try {
      await execFileAsync(bin, ["--version"], { timeout: 5_000 });
      _containerCli = bin;
      return bin;
    } catch { /* not found or not working — try next */ }
  }
  throw new Error("Neither docker nor podman found on PATH");
}

/**
 * Create a dockerode instance, auto-detecting the container socket.
 * Checks DOCKER_HOST first, then the default docker socket, then
 * the podman user socket.
 */
function createDockerClient(): InstanceType<typeof Docker> {
  if (process.env.DOCKER_HOST) return new Docker();

  const defaultSocket = "/var/run/docker.sock";
  if (fs.existsSync(defaultSocket)) return new Docker({ socketPath: defaultSocket });

  const uid = process.getuid?.();
  if (uid !== undefined) {
    const podmanSocket = `/run/user/${uid}/podman/podman.sock`;
    if (fs.existsSync(podmanSocket)) return new Docker({ socketPath: podmanSocket });
  }

  // Last resort — let dockerode try its default
  return new Docker();
}

const IMAGE_NAME = "proxy-mcp-curl-impersonate";
const CONTAINER_NAME = "proxy-mcp-curl-impersonate";
const DEFAULT_CURL_BINARY = "chrome131";

let containerId: string | null = null;
let initPromise: Promise<string> | null = null;

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
  ja3: string;              // kept for backward compat (ignored by curl-impersonate)
  userAgent?: string;
  proxy?: string;
  http2Fingerprint?: string; // kept for backward compat (ignored by curl-impersonate)
  headerOrder?: string[];
  orderAsProvided?: boolean;
  disableGrease?: boolean;
  disableRedirect?: boolean;
  forceHTTP1?: boolean;
  insecureSkipVerify?: boolean;
  cookies?: Array<object> | { [key: string]: string };
  preset?: string;          // browser preset name → selects curlBinary
}

// ── Container lifecycle ──

function getProjectRoot(): string {
  const thisFile = fileURLToPath(import.meta.url);
  // Works from both src/ (dev) and dist/ (built)
  return path.resolve(path.dirname(thisFile), "..");
}

/**
 * Build the curl-impersonate Docker image if not present,
 * start the container if not running. Returns the container ID.
 */
async function ensureSpoofContainer(): Promise<string> {
  if (containerId) return containerId;

  if (!initPromise) {
    initPromise = (async () => {
      const docker = createDockerClient();

      // Check if container already exists and is running
      try {
        const existing = docker.getContainer(CONTAINER_NAME);
        const info = await existing.inspect();
        if (info.State.Running) {
          containerId = info.Id;
          return containerId;
        }
        // Exists but not running — start it
        await existing.start();
        containerId = info.Id;
        return containerId;
      } catch {
        // Container doesn't exist — continue to build + create
      }

      // Build image if not present
      try {
        await docker.getImage(IMAGE_NAME).inspect();
      } catch {
        const projectRoot = getProjectRoot();
        const dockerfilePath = path.join(projectRoot, "Dockerfile.curl-impersonate");

        // Use execFile to build (simpler than dockerode tar stream)
        const cli = await containerCli();
        await execFileAsync(cli, [
          "build",
          "-f", dockerfilePath,
          "-t", IMAGE_NAME,
          projectRoot,
        ], { timeout: 300_000 });
      }

      // Create and start container
      const container = await docker.createContainer({
        Image: IMAGE_NAME,
        name: CONTAINER_NAME,
        Cmd: ["sleep", "infinity"],
        HostConfig: { NetworkMode: "host" },
      });
      await container.start();
      const info = await container.inspect();
      containerId = info.Id;
      return containerId;
    })();
  }

  return initPromise;
}

// ── Response parsing ──

/**
 * Parse HTTP response headers from curl's `-D /dev/stderr` output.
 * Handles multiple response blocks (redirects, 1xx informational) by
 * using the LAST block.
 */
function parseResponseHeaders(headerBuf: Buffer): { status: number; headers: Record<string, string | string[]> } {
  const text = headerBuf.toString("utf-8");
  // Split into response blocks (each starts with HTTP/...)
  const blocks = text.split(/(?=^HTTP\/)/m).filter((b) => b.trim().length > 0);
  const lastBlock = blocks[blocks.length - 1] || "";
  const lines = lastBlock.split(/\r?\n/);

  let status = 200;
  const headers: Record<string, string | string[]> = {};

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (i === 0) {
      // Status line: "HTTP/2 200" or "HTTP/1.1 200 OK"
      const match = line.match(/^HTTP\/[\d.]+\s+(\d+)/);
      if (match) status = parseInt(match[1], 10);
      continue;
    }
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();
      // Set-Cookie must be kept as an array — combining with commas
      // breaks cookie parsing (commas appear in Expires values).
      if (key === "set-cookie") {
        const existing = headers[key];
        if (Array.isArray(existing)) {
          existing.push(value);
        } else if (typeof existing === "string") {
          headers[key] = [existing, value];
        } else {
          headers[key] = [value];
        }
      } else {
        headers[key] = value;
      }
    }
  }

  return { status, headers };
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

// ── Main request function ──

/**
 * Make an HTTP request with a spoofed TLS + HTTP/2 fingerprint via
 * curl-impersonate running in a Docker container.
 */
export async function spoofedRequest(url: string, opts: SpoofOptions): Promise<SpoofedResponse> {
  const cid = await ensureSpoofContainer();

  // Determine which curl-impersonate target to use
  let curlTarget = DEFAULT_CURL_BINARY;
  if (opts.preset) {
    try {
      const preset = resolveBrowserPreset(opts.preset);
      curlTarget = preset.curlBinary;
    } catch {
      // Fall through to default
    }
  }

  // Build the container exec command
  const cli = await containerCli();
  const args: string[] = [
    "exec", cid,
    "curl-impersonate",
    "--impersonate", curlTarget,
    "-s",                    // silent (no progress)
    "-D", "/dev/stderr",     // response headers → stderr
    "--compressed",          // handle content-encoding
  ];

  // Timeouts — fail fast on unreachable hosts instead of blocking
  // for the full docker exec timeout. These don't alter the TLS fingerprint.
  args.push("--connect-timeout", "15");
  args.push("--max-time", "45");

  // Cookies — forward via -b for explicit cookie jar behavior.
  // Cookies also flow via -H "cookie: ..." from opts.headers; when -b is used
  // the cookie header is stripped from -H to avoid duplication.
  const hasCookies =
    opts.cookies && typeof opts.cookies === "object" && !Array.isArray(opts.cookies);
  if (hasCookies) {
    const cookieStr = Object.entries(opts.cookies as Record<string, string>)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
    if (cookieStr) {
      args.push("-b", cookieStr);
    }
  }

  // Headers
  const headers = opts.headers || {};
  for (const [k, v] of Object.entries(headers)) {
    // Skip cookie header when using -b flag (avoid duplication)
    if (k.toLowerCase() === "cookie" && hasCookies) continue;
    args.push("-H", `${k}: ${v}`);
  }

  // User-Agent override (if set, override the impersonation default)
  if (opts.userAgent) {
    args.push("-H", `user-agent: ${opts.userAgent}`);
  }

  // Method
  const method = opts.method.toUpperCase();
  if (method !== "GET") {
    args.push("-X", method);
  }

  // Body
  if (opts.body) {
    args.push("--data-raw", opts.body);
  }

  // Proxy
  if (opts.proxy) {
    args.push("--proxy", opts.proxy);
  }

  // Redirects
  if (!opts.disableRedirect) {
    args.push("-L");           // follow redirects
    args.push("--max-redirs", "10");
  }

  // TLS verification
  if (opts.insecureSkipVerify) {
    args.push("-k");
  }

  // Force HTTP/1.1
  if (opts.forceHTTP1) {
    args.push("--http1.1");
  }

  // URL must be last
  args.push(url);

  const { stdout, stderr } = await execFileAsync(cli, args, {
    maxBuffer: 50 * 1024 * 1024,
    encoding: "buffer",
    timeout: 60_000,  // curl's own --max-time handles the actual limit
  });

  // Parse response headers from stderr
  const { status, headers: responseHeaders } = parseResponseHeaders(stderr);

  // curl-impersonate with --compressed decompresses the body but keeps the
  // original content-encoding/content-length headers. Strip them so the
  // client doesn't try to decompress already-decompressed data.
  delete responseHeaders["content-length"];
  delete responseHeaders["transfer-encoding"];
  delete responseHeaders["content-encoding"];

  return {
    status,
    headers: responseHeaders,
    body: stdout,
  };
}

// ── Shutdown ──

/**
 * Stop and remove the curl-impersonate Docker container.
 * Called when spoofing is disabled or proxy stops.
 */
export async function shutdownSpoofContainer(): Promise<void> {
  if (containerId) {
    try {
      const docker = createDockerClient();
      const container = docker.getContainer(containerId);
      try { await container.stop({ t: 2 }); } catch { /* may already be stopped */ }
      try { await container.remove({ force: true }); } catch { /* may already be removed */ }
    } catch {
      // Ignore shutdown errors
    }
    containerId = null;
    initPromise = null;
  }
}

/**
 * @deprecated Use shutdownSpoofContainer(). Kept for backward compat during transition.
 */
export const shutdownCycleTLS = shutdownSpoofContainer;
