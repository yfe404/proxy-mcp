/**
 * Utility functions for the proxy MCP server.
 */

import { networkInterfaces } from "node:os";

/**
 * Maximum characters for tool output to stay within MCP token limits.
 */
const MAX_RESULT_CHARS = 24000;

/**
 * Serialize data to JSON, truncating if it exceeds MCP limits.
 * For arrays: binary-search for max items that fit, append truncation notice.
 * For other values: slice the JSON string and append a notice.
 */
export function truncateResult(data: unknown, indent?: number): string {
  const full = JSON.stringify(data, null, indent);
  if (full.length <= MAX_RESULT_CHARS) return full;

  if (Array.isArray(data)) {
    let lo = 0;
    let hi = data.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (JSON.stringify(data.slice(0, mid), null, indent).length <= MAX_RESULT_CHARS - 200) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    const truncated = data.slice(0, lo);
    return JSON.stringify({
      items: truncated,
      truncated: true,
      showing: lo,
      total: data.length,
      message: `Showing ${lo} of ${data.length} items. Use filter/limit params to narrow results.`,
    }, null, indent);
  }

  return full.slice(0, MAX_RESULT_CHARS - 100) + "\n... [truncated, total " + full.length + " chars]";
}

/**
 * Get the first non-loopback IPv4 address for LAN proxy instructions.
 */
export function getLocalIP(): string {
  let interfaces: ReturnType<typeof networkInterfaces>;
  try {
    interfaces = networkInterfaces();
  } catch {
    return "127.0.0.1";
  }
  for (const iface of Object.values(interfaces)) {
    if (!iface) continue;
    for (const addr of iface) {
      if (addr.family === "IPv4" && !addr.internal) {
        return addr.address;
      }
    }
  }
  return "127.0.0.1";
}

/**
 * Serialize headers object to a clean record, lowercasing keys.
 */
export function serializeHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined) {
      result[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
    }
  }
  return result;
}

/**
 * Cap a string to maxLen characters, appending "..." if truncated.
 */
export function capString(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen) + "...";
}

/** Upstream proxy password, and the one hostname it may be sent to. */
export const UPSTREAM_PASSWORD_ENV = "PROXY_MCP_UPSTREAM_PASSWORD";

/**
 * Build the environment for a process this server spawns.
 *
 * The upstream password is for this server to merge into a proxy URL, not for a
 * spawned command to read back out of its own environment. Both spawn sites go
 * through here so neither can drift.
 *
 * PROXY_MCP_UPSTREAM_HOST is kept: it is configuration rather than a secret, and
 * a spawned tool may legitimately need to know where its traffic goes.
 */
export function spawnEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...extra };
  delete env[UPSTREAM_PASSWORD_ENV];
  return env;
}
const UPSTREAM_HOST_ENV = "PROXY_MCP_UPSTREAM_HOST";

/**
 * Replace credentials in a proxy URL with "***" for safe logging.
 *
 * The username is preserved on purpose: for some providers it is configuration
 * rather than a secret (Apify Proxy encodes proxy group, country and
 * sticky-session id there), and it is what makes a confirmation message worth
 * printing. Everything else that can carry a token is removed — the query and
 * fragment are dropped and path segments masked — because a pac+http:// URL
 * carries its token in one of those and no agent in this stack needs any of
 * them echoed back. A URL with no authority is reduced to its scheme, since an
 * opaque path cannot be rewritten at all.
 */
export function redactProxyUrl(proxyUrl: string): string {
  let url: URL;
  try {
    url = new URL(proxyUrl);
  } catch {
    return "<unparseable url>";
  }
  // An opaque path ("pac+http:host/TOKEN.pac", no "//") cannot be rewritten —
  // assigning pathname is a silent no-op — so nothing structural can be
  // preserved safely. Such a URL has no authority and is not a usable upstream
  // anyway; show only the scheme.
  if (!url.host) return `${url.protocol}***`;

  if (url.password) url.password = "***";
  // Drop the query rather than masking values: "?TOKEN" with no "=" parses as a
  // key with an empty value, so masking would return "?TOKEN=***" — the token
  // echoed in full, and looking redacted, so nobody would spot it.
  url.search = "";
  url.hash = "";
  url.pathname = url.pathname.replace(/[^/]+/g, "***");
  return url.toString();
}

function stripBrackets(host: string): string {
  return host.replace(/^\[|\]$/g, "").toLowerCase();
}

/**
 * Fill in the upstream password from the environment when the caller supplied
 * a username but no password, so a credential need not appear in the tool call.
 *
 * Two conditions, both required. The value only ever lands in the password
 * slot, so it cannot be echoed back through the username, host, path or query;
 * and it is only ever sent to PROXY_MCP_UPSTREAM_HOST, so a caller who cannot
 * read the value cannot have it delivered to a host of their choosing either.
 * Without the host variable nothing is merged — a half-configuration must not
 * degrade into an unbound credential.
 *
 * A URL with no username, or one that already carries a password, is returned
 * untouched; so is any URL when either variable is unset.
 */
export function mergeUpstreamPassword(
  proxyUrl: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const password = env[UPSTREAM_PASSWORD_ENV];
  const host = env[UPSTREAM_HOST_ENV]?.trim();
  if (!password || !host) return proxyUrl;

  let url: URL;
  try {
    url = new URL(proxyUrl);
  } catch {
    return proxyUrl; // the tool boundary rejects it
  }
  if (!url.username || url.password) return proxyUrl;
  // url.hostname keeps the brackets on an IPv6 literal ("[::1]"), so strip them
  // from both sides: the variable is documented as a bare hostname.
  if (stripBrackets(url.hostname) !== stripBrackets(host)) return proxyUrl;

  // A ":" in the username is unrepresentable in every credential format here:
  // Basic auth splits the decoded pair at the first colon (RFC 7617) and
  // socks-proxy-agent does the same, so "gro:ups" + "s3cret" arrives as user
  // "gro" and the merged password is silently discarded. A literal ":" cannot
  // survive WHATWG parsing of userinfo, so it is always "%3A" here.
  if (/%3a/i.test(url.username)) {
    throw new Error(
      `proxy_url's username contains ":", which every proxy credential format in this stack reads as the user/password separator — the merged password would be dropped. Put the credential in proxy_url instead.`,
    );
  }

  // socks-proxy-agent splits the credential on the first ":" and keeps only
  // what follows, so half the password would authenticate — silently. Refusing
  // beats delivering a credential we know is wrong. http/https send the whole
  // password, so this one is socks-only.
  if (url.protocol.startsWith("socks") && password.includes(":")) {
    throw new Error(
      `${UPSTREAM_PASSWORD_ENV} contains ":", which a ${url.protocol} upstream truncates. Use a password without ":" or put the credential in proxy_url.`,
    );
  }

  // encodeURIComponent, not the raw value: the password setter escapes "@" and
  // "/" but leaves "%" alone, and mockttp reads the credential back through
  // url.parse().auth, which decodeURIComponent()s it. A raw "%" therefore makes
  // that decode throw, and a raw "%20" silently decodes to a space. Encoding
  // first is lossless — the setter escapes nothing encodeURIComponent leaves.
  url.password = encodeURIComponent(password);
  return url.toString();
}

/**
 * Which credential a resolved upstream URL ended up using, or null when the URL
 * carries no username and the question does not arise.
 *
 * "none" means no password was applied to a URL that names a user — either the
 * credential is username-only, or the server does not have both
 * PROXY_MCP_UPSTREAM_PASSWORD and PROXY_MCP_UPSTREAM_HOST set for this host.
 * Without it, that misconfiguration reads as plain success and surfaces later
 * as unexplained 407s.
 */
export function upstreamPasswordSource(
  original: string,
  resolved: string,
): "env" | "url" | "none" | null {
  if (resolved !== original) return "env";
  let url: URL;
  try {
    url = new URL(original);
  } catch {
    return null;
  }
  if (!url.username) return null;
  return url.password ? "url" : "none";
}
