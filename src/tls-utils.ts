/**
 * TLS utility functions — JA3S computation, cipher/version maps, and server TLS capture.
 *
 * JA3S formula: md5(TLSVersionInt + "," + CipherSuiteInt)
 * Server TLS capture: monkey-patches tls.connect to intercept outgoing TLS parameters.
 */

import * as crypto from "node:crypto";
import * as tls from "node:tls";
import { createRequire } from "node:module";

// Use createRequire to get a mutable CJS reference to the tls module.
// ESM namespace objects are frozen, so direct assignment to `tls.connect` fails.
const require_ = createRequire(import.meta.url);
const tlsMutable = require_("tls") as typeof tls & Record<string, unknown>;

// ── TLS version map: protocol string → IANA greeting version number ──

const TLS_VERSION_MAP: Record<string, number> = {
  "TLSv1": 769,
  "TLSv1.1": 770,
  "TLSv1.2": 771,
  "TLSv1.3": 772,
  "SSLv3": 768,
};

// ── Cipher suite map: OpenSSL name → IANA number (common suites) ──

const CIPHER_MAP: Record<string, number> = {
  // TLS 1.3
  "TLS_AES_128_GCM_SHA256": 0x1301,
  "TLS_AES_256_GCM_SHA384": 0x1302,
  "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
  // TLS 1.2 ECDHE
  "ECDHE-ECDSA-AES128-GCM-SHA256": 0xC02B,
  "ECDHE-RSA-AES128-GCM-SHA256": 0xC02F,
  "ECDHE-ECDSA-AES256-GCM-SHA384": 0xC02C,
  "ECDHE-RSA-AES256-GCM-SHA384": 0xC030,
  "ECDHE-ECDSA-CHACHA20-POLY1305": 0xCCA9,
  "ECDHE-RSA-CHACHA20-POLY1305": 0xCCA8,
  "ECDHE-ECDSA-AES128-SHA256": 0xC023,
  "ECDHE-RSA-AES128-SHA256": 0xC027,
  "ECDHE-ECDSA-AES256-SHA384": 0xC024,
  "ECDHE-RSA-AES256-SHA384": 0xC028,
  "ECDHE-ECDSA-AES128-SHA": 0xC009,
  "ECDHE-RSA-AES128-SHA": 0xC013,
  "ECDHE-ECDSA-AES256-SHA": 0xC00A,
  "ECDHE-RSA-AES256-SHA": 0xC014,
  // DHE
  "DHE-RSA-AES128-GCM-SHA256": 0x009E,
  "DHE-RSA-AES256-GCM-SHA384": 0x009F,
  "DHE-RSA-AES128-SHA256": 0x0067,
  "DHE-RSA-AES256-SHA256": 0x006B,
  "DHE-RSA-AES128-SHA": 0x0033,
  "DHE-RSA-AES256-SHA": 0x0039,
  // RSA
  "AES128-GCM-SHA256": 0x009C,
  "AES256-GCM-SHA384": 0x009D,
  "AES128-SHA256": 0x003C,
  "AES256-SHA256": 0x003D,
  "AES128-SHA": 0x002F,
  "AES256-SHA": 0x0035,
};

/**
 * Resolve a cipher name to its IANA number.
 * Tries standardName first, then OpenSSL name, returns undefined if unknown.
 */
export function cipherToIana(cipherInfo: { name: string; standardName?: string }): number | undefined {
  if (cipherInfo.standardName && CIPHER_MAP[cipherInfo.standardName] !== undefined) {
    return CIPHER_MAP[cipherInfo.standardName];
  }
  return CIPHER_MAP[cipherInfo.name];
}

/**
 * Resolve a TLS protocol string to its IANA version number.
 */
export function tlsVersionToIana(protocol: string): number | undefined {
  return TLS_VERSION_MAP[protocol];
}

/**
 * Compute JA3S fingerprint from server hello parameters.
 * JA3S = md5(TLSVersion + "," + CipherSuite)
 */
export function computeJa3s(protocol: string, cipherInfo: { name: string; standardName?: string }): string | undefined {
  const version = tlsVersionToIana(protocol);
  const cipher = cipherToIana(cipherInfo);
  if (version === undefined || cipher === undefined) return undefined;

  const raw = `${version},${cipher}`;
  return crypto.createHash("md5").update(raw).digest("hex");
}

// ── Server TLS metadata ──

export interface ServerTlsInfo {
  protocol: string;
  cipher: string;
  ja3sFingerprint?: string;
}

// ── Server TLS capture toggle (tls.connect monkey-patch) ──

export interface ServerTlsCapture {
  getServerTls(addr: string, port: number): ServerTlsInfo | undefined;
  getServerTlsByHostname(hostname: string): ServerTlsInfo | undefined;
  disable(): void;
}

/**
 * Enable server TLS capture by monkey-patching tls.connect.
 * Intercepts all outgoing TLS connections, extracts negotiated parameters on
 * `secureConnect`, computes JA3S, and caches by both IP:port and hostname.
 *
 * Returns a handle with lookup methods and disable() for cleanup.
 */
export function enableServerTlsCapture(): ServerTlsCapture {
  const cacheByAddr = new Map<string, ServerTlsInfo>();
  const cacheByHost = new Map<string, ServerTlsInfo>();
  const originalConnect = tlsMutable.connect;

  function patchedConnect(this: unknown, ...args: Parameters<typeof tls.connect>): tls.TLSSocket {
    const socket = (originalConnect as Function).apply(this, args) as tls.TLSSocket;

    // Extract the servername (SNI hostname) from connect options
    const opts = typeof args[0] === "object" ? args[0] as Record<string, unknown> : undefined;
    const servername = (opts?.servername ?? opts?.host) as string | undefined;

    socket.once("secureConnect", () => {
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      if (protocol && cipher) {
        const ja3s = computeJa3s(protocol, cipher);
        const info: ServerTlsInfo = {
          protocol,
          cipher: cipher.standardName || cipher.name,
          ja3sFingerprint: ja3s,
        };

        const addr = socket.remoteAddress;
        const port = socket.remotePort;
        const addrKey = addr && port ? `${addr}:${port}` : undefined;
        if (addrKey) cacheByAddr.set(addrKey, info);
        if (servername) cacheByHost.set(servername, info);

        socket.once("close", () => {
          if (addrKey) cacheByAddr.delete(addrKey);
          // Don't delete hostname cache on close — keep last-seen for lookup
        });
      }
    });

    return socket;
  }

  // Replace tls.connect on the mutable CJS module object
  (tlsMutable as Record<string, unknown>)["connect"] = patchedConnect;

  return {
    getServerTls(addr: string, port: number): ServerTlsInfo | undefined {
      return cacheByAddr.get(`${addr}:${port}`);
    },
    getServerTlsByHostname(hostname: string): ServerTlsInfo | undefined {
      return cacheByHost.get(hostname);
    },
    disable() {
      (tlsMutable as Record<string, unknown>)["connect"] = originalConnect;
      cacheByAddr.clear();
      cacheByHost.clear();
    },
  };
}
