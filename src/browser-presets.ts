/**
 * Browser fingerprint presets for impit.
 *
 * Each preset bundles a User-Agent and an impitBrowser name that selects the
 * impit impersonation target. impit handles TLS fingerprinting, HTTP/2 frame
 * ordering, and header normalization natively.
 */

export interface BrowserPreset {
  name: string;
  description: string;
  userAgent: string;
  impitBrowser: string;     // impit Browser enum value, e.g. "chrome131"
}

const PRESETS: Record<string, BrowserPreset> = {
  chrome_131: {
    name: "chrome_131",
    description: "Chrome 131 on Windows 10/11 (approx.)",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    impitBrowser: "chrome131",
  },

  chrome_136: {
    name: "chrome_136",
    description: "Chrome 136 on Windows 10/11 (approx.)",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    impitBrowser: "chrome136",
  },

  chrome_136_linux: {
    name: "chrome_136_linux",
    description: "Chrome 136 on Linux x86_64 (approx.)",
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    impitBrowser: "chrome136",
  },

  firefox_133: {
    name: "firefox_133",
    description: "Firefox 133 on Windows 10/11 (approx.)",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    impitBrowser: "firefox133",
  },
};

/**
 * Resolve a browser preset by name. Throws if unknown.
 */
export function resolveBrowserPreset(name: string): BrowserPreset {
  const preset = PRESETS[name];
  if (!preset) {
    const available = Object.keys(PRESETS).join(", ");
    throw new Error(`Unknown browser preset '${name}'. Available: ${available}`);
  }
  return preset;
}

/**
 * List all available browser presets (summary for MCP tool output).
 */
export function listBrowserPresets(): Array<{ name: string; description: string }> {
  return Object.values(PRESETS).map(({ name, description }) => ({ name, description }));
}
