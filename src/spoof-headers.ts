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
// ── CDP identity derivation ──────────────────────────────────────────

export interface UserAgentMetadata {
  brands: Array<{ brand: string; version: string }>;
  fullVersionList: Array<{ brand: string; version: string }>;
  platform: string;
  platformVersion: string;
  architecture: string;
  model: string;
  mobile: boolean;
  bitness: string;
  wow64: boolean;
}

/**
 * Derive `navigator.platform` from the UA string.
 *
 * Maps to values real browsers return:
 * - Windows → "Win32"
 * - macOS   → "MacIntel"
 * - Linux   → "Linux x86_64"
 * - Android → "Linux armv81" (or similar)
 * - iOS     → "iPhone" / "iPad"
 */
export function deriveNavigatorPlatformFromUA(userAgent: string): string {
  if (/Windows NT/i.test(userAgent)) return "Win32";
  if (/(iPhone|iPod)/i.test(userAgent)) return "iPhone";
  if (/iPad/i.test(userAgent)) return "iPad";
  if (/Mac OS X/i.test(userAgent)) return "MacIntel";
  if (/Android/i.test(userAgent)) return "Linux armv8l";
  if (/Linux/i.test(userAgent)) return "Linux x86_64";
  return "";
}

function derivePlatformArch(userAgent: string): { architecture: string; bitness: string; wow64: boolean } {
  if (/Win64|WOW64|x64/i.test(userAgent)) return { architecture: "x86", bitness: "64", wow64: false };
  if (/Windows NT/i.test(userAgent)) return { architecture: "x86", bitness: "64", wow64: false };
  if (/Mac OS X/i.test(userAgent)) return { architecture: "arm", bitness: "64", wow64: false };
  if (/Android/i.test(userAgent)) return { architecture: "", bitness: "", wow64: false };
  if (/Linux/i.test(userAgent)) return { architecture: "x86", bitness: "64", wow64: false };
  return { architecture: "", bitness: "", wow64: false };
}

function derivePlatformVersion(userAgent: string): string {
  // Windows NT 10.0 → report "15.0.0" (Win11 style) or "10.0.0"
  const winMatch = userAgent.match(/Windows NT (\d+)\.(\d+)/i);
  if (winMatch) return "15.0.0";

  // Mac OS X 10_15_7 or Mac OS X 14_0
  const macMatch = userAgent.match(/Mac OS X (\d+)[_.](\d+)(?:[_.](\d+))?/i);
  if (macMatch) return `${macMatch[1]}.${macMatch[2]}.${macMatch[3] || "0"}`;

  // Android 14
  const androidMatch = userAgent.match(/Android (\d+)(?:\.(\d+))?/i);
  if (androidMatch) return `${androidMatch[1]}.${androidMatch[2] || "0"}.0`;

  return "0.0.0";
}

function buildBrandsList(major: string): Array<{ brand: string; version: string }> {
  // Chrome uses GREASE-like "Not/A)Brand" entries that vary per version.
  // These are representative patterns; the exact GREASE rotates but
  // bot-detection checks that brand list structure looks plausible.
  const majorNum = parseInt(major, 10);
  const greaseSlot = majorNum % 4;
  const greasBrands = [
    "Not)A;Brand",
    "Not A(Brand",
    "Not/A)Brand",
    "Not:A-Brand",
  ];
  const grease = greasBrands[greaseSlot] || "Not;A=Brand";

  return [
    { brand: "Chromium", version: major },
    { brand: "Google Chrome", version: major },
    { brand: grease, version: "99" },
  ];
}

/**
 * Build `Emulation.setUserAgentOverride` `userAgentMetadata` from a UA string.
 * Returns `null` for non-Chromium UAs (Firefox/Safari don't have Client Hints).
 */
export function buildUserAgentMetadata(userAgent: string): UserAgentMetadata | null {
  if (!isChromiumLikeUserAgent(userAgent)) return null;
  const major = parseChromiumMajor(userAgent);
  if (!major) return null;

  const platform = derivePlatform(userAgent) ?? "Windows";
  const mobile = isMobileUserAgent(userAgent);
  const { architecture, bitness, wow64 } = derivePlatformArch(userAgent);
  const platformVersion = derivePlatformVersion(userAgent);

  // Extract full Chrome version (e.g. "136.0.0.0")
  const fullVersionMatch = userAgent.match(/\bChrome\/(\d+\.\d+\.\d+\.\d+)/i);
  const fullVersion = fullVersionMatch ? fullVersionMatch[1] : `${major}.0.0.0`;

  const brands = buildBrandsList(major);
  const fullVersionList = brands.map(b => ({
    brand: b.brand,
    version: b.brand.includes("Brand") ? `99.0.0.0` : fullVersion,
  }));

  // Model is typically empty for desktop; Android may have it but we
  // don't embed device model in the UA, so leave empty.
  return {
    brands,
    fullVersionList,
    platform,
    platformVersion,
    architecture,
    model: "",
    mobile,
    bitness,
    wow64,
  };
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

