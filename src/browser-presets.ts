/**
 * Browser fingerprint presets for CycleTLS.
 *
 * Each preset bundles a JA3, HTTP/2 fingerprint, User-Agent, and header order
 * that approximate a specific browser version. These are point-in-time snapshots
 * and should be updated periodically — Chrome fingerprints vary by version,
 * platform, and field trials.
 */

export interface BrowserPreset {
  name: string;
  description: string;
  ja3: string;
  userAgent: string;
  http2Fingerprint: string;
  headerOrder: string[];
  orderAsProvided: boolean;
}

// HTTP/2 fingerprint format for CycleTLS (4 pipe-separated parts):
//   SETTINGS | WINDOW_UPDATE | PRIORITY | PSEUDO_HEADER_ORDER
// Pseudo-header order: m = :method, a = :authority, s = :scheme, p = :path
// Example: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0:1:256:0,...|m,a,s,p"

const PRESETS: Record<string, BrowserPreset> = {
  chrome_131: {
    name: "chrome_131",
    description: "Chrome 131 on Windows 10/11 (approx.)",
    ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    http2Fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0:1:256:0,3:0:0:200,5:0:0:168,7:0:0:168,9:0:0:168,11:0:0:168,13:0:0:240|m,a,s,p",
    headerOrder: [
      "host",
      "connection",
      "content-length",
      "sec-ch-ua",
      "sec-ch-ua-mobile",
      "sec-ch-ua-platform",
      "upgrade-insecure-requests",
      "user-agent",
      "accept",
      "sec-fetch-site",
      "sec-fetch-mode",
      "sec-fetch-user",
      "sec-fetch-dest",
      "referer",
      "accept-encoding",
      "accept-language",
      "cookie",
    ],
    orderAsProvided: true,
  },

  chrome_136: {
    name: "chrome_136",
    description: "Chrome 136 on Windows 10/11 (approx.)",
    ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    http2Fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0:1:256:0,3:0:0:200,5:0:0:168,7:0:0:168,9:0:0:168,11:0:0:168,13:0:0:240|m,a,s,p",
    headerOrder: [
      "host",
      "connection",
      "content-length",
      "sec-ch-ua",
      "sec-ch-ua-mobile",
      "sec-ch-ua-platform",
      "upgrade-insecure-requests",
      "user-agent",
      "accept",
      "sec-fetch-site",
      "sec-fetch-mode",
      "sec-fetch-user",
      "sec-fetch-dest",
      "referer",
      "accept-encoding",
      "accept-language",
      "cookie",
    ],
    orderAsProvided: true,
  },

  chrome_136_linux: {
    name: "chrome_136_linux",
    description: "Chrome 136 on Linux x86_64 (approx.)",
    ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    http2Fingerprint: "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0:1:256:0,3:0:0:200,5:0:0:168,7:0:0:168,9:0:0:168,11:0:0:168,13:0:0:240|m,a,s,p",
    headerOrder: [
      "host",
      "connection",
      "content-length",
      "sec-ch-ua",
      "sec-ch-ua-mobile",
      "sec-ch-ua-platform",
      "upgrade-insecure-requests",
      "user-agent",
      "accept",
      "sec-fetch-site",
      "sec-fetch-mode",
      "sec-fetch-user",
      "sec-fetch-dest",
      "referer",
      "accept-encoding",
      "accept-language",
      "cookie",
    ],
    orderAsProvided: true,
  },

  firefox_133: {
    name: "firefox_133",
    description: "Firefox 133 on Windows 10/11 (approx.)",
    ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-45-43-13-21,29-23-24-25-256-257,0",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    http2Fingerprint: "1:65536;4:131072;5:16384|12517377|0|m,s,a,p",
    headerOrder: [
      "host",
      "user-agent",
      "accept",
      "accept-language",
      "accept-encoding",
      "referer",
      "connection",
      "cookie",
      "upgrade-insecure-requests",
      "sec-fetch-dest",
      "sec-fetch-mode",
      "sec-fetch-site",
      "sec-fetch-user",
      "te",
    ],
    orderAsProvided: true,
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
