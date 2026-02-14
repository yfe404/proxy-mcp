/**
 * Header normalization for fingerprint spoofing.
 *
 * When we re-issue a request with a spoofed TLS/HTTP2 fingerprint (CycleTLS),
 * it's easy to accidentally forward browser-provided headers (User-Agent +
 * UA Client Hints) that contradict the chosen TLS preset.
 *
 * Some bot mitigations treat this mismatch as an immediate signal.
 */

export interface FingerprintHeaderOverrideOptions {
  /**
   * When set, overrides the outgoing User-Agent header and normalizes
   * Chromium UA Client Hints (`sec-ch-ua*`) to match.
   */
  userAgent?: string;
}

function findHeaderKey(headers: Record<string, string>, name: string): string | undefined {
  const needle = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === needle) return key;
  }
  return undefined;
}

function getHeader(headers: Record<string, string>, name: string): string | undefined {
  const key = findHeaderKey(headers, name);
  return key ? headers[key] : undefined;
}

function deleteHeader(headers: Record<string, string>, name: string): void {
  const key = findHeaderKey(headers, name);
  if (key) delete headers[key];
}

function setHeader(headers: Record<string, string>, name: string, value: string): void {
  deleteHeader(headers, name);
  headers[name] = value;
}

function isChromiumLikeUserAgent(userAgent: string): boolean {
  // Chrome UA contains "Safari/..." too; explicitly exclude Firefox.
  if (/Firefox\/\d+/i.test(userAgent)) return false;
  return /\b(?:Chrome|Chromium|CriOS)\/\d+/i.test(userAgent);
}

function parseChromiumMajor(userAgent: string): string | null {
  const m = userAgent.match(/\b(?:Chrome|Chromium|CriOS)\/(\d+)/i);
  return m ? m[1] : null;
}

function derivePlatform(userAgent: string): string | null {
  if (/Windows NT/i.test(userAgent)) return "Windows";
  if (/Android/i.test(userAgent)) return "Android";
  if (/(iPhone|iPad|iPod)/i.test(userAgent)) return "iOS";
  if (/Mac OS X/i.test(userAgent)) return "macOS";
  if (/Linux/i.test(userAgent)) return "Linux";
  return null;
}

function isMobileUserAgent(userAgent: string): boolean {
  return /\bMobile\b/i.test(userAgent) || /\bAndroid\b/i.test(userAgent);
}

function rewriteSecChUaMajor(value: string, major: string): string {
  // Preserve GREASE/Not-A-Brand slots as-is; only rewrite the real Chromium brands.
  return value
    .replace(/("Chromium";v=")\d+(")/gi, `$1${major}$2`)
    .replace(/("Google Chrome";v=")\d+(")/gi, `$1${major}$2`)
    .replace(/("Microsoft Edge";v=")\d+(")/gi, `$1${major}$2`);
}

/**
 * Apply outgoing header overrides that keep User-Agent and UA Client Hints
 * consistent with a spoof preset.
 */
export function applyFingerprintHeaderOverrides(
  headers: Record<string, string>,
  opts: FingerprintHeaderOverrideOptions,
): Record<string, string> {
  const out: Record<string, string> = { ...headers };
  const ua = opts.userAgent;
  if (!ua) return out;

  // Always force the UA header to match the spoof preset.
  setHeader(out, "user-agent", ua);

  // Remove any UA client hints; we will re-add the appropriate subset below.
  const originalSecChUa = getHeader(out, "sec-ch-ua");
  for (const key of Object.keys(out)) {
    if (key.toLowerCase().startsWith("sec-ch-ua")) delete out[key];
  }

  // Only Chromium sends `sec-ch-ua*`. For Firefox/Safari presets, keep them absent.
  if (!isChromiumLikeUserAgent(ua)) return out;

  const major = parseChromiumMajor(ua);
  const platform = derivePlatform(ua);
  const mobile = isMobileUserAgent(ua);

  // If we had a real Chrome value from the client, keep its formatting/GREASE and
  // only rewrite the actual Chromium/Chrome brand major versions.
  if (major) {
    const secChUa = originalSecChUa
      ? rewriteSecChUaMajor(originalSecChUa, major)
      : `"Chromium";v="${major}", "Google Chrome";v="${major}"`;
    setHeader(out, "sec-ch-ua", secChUa);
  }

  if (platform) setHeader(out, "sec-ch-ua-platform", `"${platform}"`);
  setHeader(out, "sec-ch-ua-mobile", mobile ? "?1" : "?0");

  return out;
}

