/**
 * Chrome interceptor — launch Chrome/Chromium with proxy flags.
 *
 * Uses chrome-launcher (dynamic import) to find and launch Chrome with:
 * - --proxy-server pointing at our MITM proxy
 * - --ignore-certificate-errors-spki-list with our CA fingerprint
 * - --remote-debugging-address=127.0.0.1 (avoid exposing CDP on LAN)
 * - Isolated temp profile (auto-cleaned on close)
 *
 * Supports Chrome, Chromium, Brave, and Edge.
 */

import type { Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult, ActiveTarget } from "./types.js";
import {
  getCdpTargetsUrl, getCdpTargets, getCdpVersion, getCdpVersionUrl, getCdpBaseUrl,
  waitForCdpVersion, CdpSession,
} from "../cdp-utils.js";
import { buildUserAgentMetadata, deriveNavigatorPlatformFromUA } from "../spoof-headers.js";

interface LaunchedBrowser {
  target: ActiveTarget;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  chrome: any; // ChromeLauncher instance
  pid: number;
  cdpSession: CdpSession | null;
}

/**
 * Stealth script injected via Page.addScriptToEvaluateOnNewDocument when
 * fingerprint spoofing is active. Runs before ANY page JavaScript (including
 * bot-detection sensors like Akamai).
 */
const STEALTH_SCRIPT = `
// 1. Ensure chrome.runtime exists with expected shape.
//    Without --disable-extensions this should already be present, but
//    belt-and-suspenders in case the extension system is slow to init.
if (window.chrome && !window.chrome.runtime) {
  window.chrome.runtime = { id: undefined };
}

// 2. Patch Permissions.query for 'notifications' check.
//    CDP automation can cause this to reject abnormally.
(function() {
  const origQuery = Permissions.prototype.query;
  Permissions.prototype.query = function(params) {
    if (params && params.name === 'notifications') {
      return Promise.resolve({ state: Notification.permission });
    }
    return origQuery.call(this, params);
  };
})();

// 3. Harden navigator.webdriver as non-configurable false.
Object.defineProperty(navigator, 'webdriver', {
  get: () => false,
  configurable: false,
});

// 4. Clean CDP-injected artifacts from Error stacks.
(function() {
  const origGetStack = Object.getOwnPropertyDescriptor(Error.prototype, 'stack');
  if (origGetStack && origGetStack.get) {
    Object.defineProperty(Error.prototype, 'stack', {
      get: function() {
        const stack = origGetStack.get.call(this);
        if (typeof stack === 'string') {
          return stack.replace(/\\n\\s+at\\s+Object\\.InjectedScript\\..+/g, '');
        }
        return stack;
      },
      configurable: true,
    });
  }
})();
`;

/**
 * Minimal, stealth-safe Chrome flags used when fingerprint spoofing is active.
 * Deliberately omits chrome-launcher defaults that create detectable artifacts:
 *   --disable-extensions  → removes chrome.runtime (primary Akamai check)
 *   --disable-sync        → detectable via sync API
 *   --disable-default-apps → removes default extension pages
 *   --mute-audio          → detectable via AudioContext state
 *   --metrics-recording-only → subtly detectable
 */
const STEALTH_BASE_FLAGS = [
  "--no-first-run",
  "--no-default-browser-check",
  "--password-store=basic",
  "--disable-background-timer-throttling",
  "--disable-backgrounding-occluded-windows",
  "--disable-renderer-backgrounding",
  "--disable-hang-monitor",
  "--disable-ipc-flooding-protection",
  "--disable-prompt-on-repost",
  "--disable-client-side-phishing-detection",
  "--disable-component-update",
];

export class ChromeInterceptor implements Interceptor {
  readonly id = "chrome";
  readonly name = "Chrome / Chromium Browser";

  private launched = new Map<string, LaunchedBrowser>();
  private _activable: boolean | null = null;

  async isActivable(): Promise<boolean> {
    if (this._activable !== null) return this._activable;
    try {
      await import("chrome-launcher");
      this._activable = true;
    } catch {
      this._activable = false;
    }
    return this._activable;
  }

  async activate(options: ActivateOptions): Promise<ActivateResult> {
    const { proxyPort, certFingerprint } = options;
    const url = options.url as string | undefined;
    const browser = options.browser as string | undefined;
    const incognito = options.incognito as boolean | undefined;

    const chromeLauncher = await import("chrome-launcher");

    // Override User-Agent if fingerprint spoofing provides one. This sets both
    // the HTTP User-Agent header and navigator.userAgent so in-page bot sensors
    // see an identity consistent with the spoofed TLS fingerprint.
    const spoofUserAgent = options.spoofUserAgent as string | undefined;
    const stealthMode = !!spoofUserAgent;

    // In stealth mode, start from a curated minimal flag set to avoid
    // detectable artifacts (e.g. --disable-extensions removes chrome.runtime).
    // Otherwise, chrome-launcher's defaults are used.
    const flags = stealthMode
      ? [
          ...STEALTH_BASE_FLAGS,
          `--proxy-server=http://127.0.0.1:${proxyPort}`,
          `--ignore-certificate-errors-spki-list=${certFingerprint}`,
          "--proxy-bypass-list=<-loopback>",
          "--remote-debugging-address=127.0.0.1",
        ]
      : [
          `--proxy-server=http://127.0.0.1:${proxyPort}`,
          `--ignore-certificate-errors-spki-list=${certFingerprint}`,
          "--proxy-bypass-list=<-loopback>",
          "--remote-debugging-address=127.0.0.1",
        ];

    if (incognito) {
      flags.push("--incognito");
    }

    if (spoofUserAgent) {
      flags.push(`--user-agent=${spoofUserAgent}`);
    }

    // Resolve browser path for non-standard Chrome variants
    let chromePath: string | undefined;
    if (browser) {
      const b = browser.toLowerCase();
      const candidates: Record<string, string[]> = {
        chromium: ["/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"],
        brave: ["/usr/bin/brave-browser", "/usr/bin/brave", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"],
        edge: ["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"],
      };
      const paths = candidates[b];
      if (paths) {
        const { accessSync } = await import("node:fs");
        for (const p of paths) {
          try { accessSync(p); chromePath = p; break; } catch { /* try next */ }
        }
      }
      // "chrome" or unknown — let chrome-launcher find it
    }

    // When spoofing, launch to about:blank first so the CDP identity override
    // is in place before the real page loads any scripts.
    const needsCdpOverride = !!spoofUserAgent;
    const launchUrl = needsCdpOverride ? "about:blank" : (url ?? "about:blank");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const launchOptions: any = {
      chromeFlags: flags,
      startingUrl: launchUrl,
      ...(stealthMode ? { ignoreDefaultFlags: true } : {}),
    };

    if (chromePath) {
      launchOptions.chromePath = chromePath;
    }

    const chrome = await chromeLauncher.launch(launchOptions);

    const targetId = `chrome_${chrome.pid}`;
    const cdpHttpUrl = getCdpBaseUrl(chrome.port);
    const cdpVersionUrl = getCdpVersionUrl(chrome.port);
    const cdpTargetsUrl = getCdpTargetsUrl(chrome.port);

    // Best-effort: CDP is usually ready when chrome-launcher returns, but don't block launch on it.
    let browserWebSocketDebuggerUrl: string | null = null;
    try {
      const version = await getCdpVersion(chrome.port, { timeoutMs: 500 });
      const ws = version.webSocketDebuggerUrl;
      if (typeof ws === "string" && ws.length > 0) {
        browserWebSocketDebuggerUrl = ws;
      }
    } catch {
      // Ignore and let users call interceptor_chrome_cdp_info for retries
    }

    // ── Persistent CDP identity override ──
    let cdpSession: CdpSession | null = null;
    let identityOverrideActive = false;

    if (needsCdpOverride) {
      try {
        // Wait for CDP to be fully ready
        await waitForCdpVersion(chrome.port, { timeoutMs: 5000 });

        // Find the first page target's WebSocket URL
        const targets = await getCdpTargets(chrome.port, { timeoutMs: 2000 });
        const pageTarget = targets.find(
          (t) => t.type === "page" && typeof t.webSocketDebuggerUrl === "string",
        );

        if (pageTarget) {
          const pageWsUrl = pageTarget.webSocketDebuggerUrl as string;
          cdpSession = await CdpSession.open(pageWsUrl, { timeoutMs: 3000 });

          // Build override params from the spoof UA
          const uaMetadata = buildUserAgentMetadata(spoofUserAgent!);
          const navigatorPlatform = deriveNavigatorPlatformFromUA(spoofUserAgent!);

          const overrideParams: Record<string, unknown> = {
            userAgent: spoofUserAgent,
            platform: navigatorPlatform,
          };
          if (uaMetadata) {
            overrideParams.userAgentMetadata = uaMetadata;
          }

          await cdpSession.send("Emulation.setUserAgentOverride", overrideParams);
          identityOverrideActive = true;

          // Inject stealth patches before any page script runs
          if (stealthMode) {
            await cdpSession.send("Page.addScriptToEvaluateOnNewDocument", {
              source: STEALTH_SCRIPT,
            });
          }

          // Navigate via the same persistent session so the emulation
          // override isn't disrupted by a second DevTools connection.
          if (url) {
            await cdpSession.send("Page.navigate", { url }, { timeoutMs: 5000 });
          }
        }
      } catch {
        // CDP override failed — Chrome still launched with --user-agent flag
        // providing partial coverage. Log the failure in details below.
        if (cdpSession && !cdpSession.closed) {
          cdpSession.close();
          cdpSession = null;
        }
      }
    }

    const target: ActiveTarget = {
      id: targetId,
      description: `${browser ?? "chrome"} (PID ${chrome.pid})`,
      activatedAt: Date.now(),
      details: {
        pid: chrome.pid,
        port: chrome.port,
        browser: browser ?? "chrome",
        proxyPort,
        url: url ?? "about:blank",
        incognito: incognito ?? false,
        cdpHttpUrl,
        cdpVersionUrl,
        cdpTargetsUrl,
        browserWebSocketDebuggerUrl,
        ...(spoofUserAgent ? { identityOverrideActive } : {}),
      },
    };

    this.launched.set(targetId, { target, chrome, pid: chrome.pid, cdpSession });

    return {
      targetId,
      details: target.details,
    };
  }

  async deactivate(targetId: string): Promise<void> {
    const entry = this.launched.get(targetId);
    if (!entry) {
      throw new Error(`No Chrome instance with target ID '${targetId}'`);
    }

    // Close the persistent CDP session before killing Chrome
    if (entry.cdpSession && !entry.cdpSession.closed) {
      try { entry.cdpSession.close(); } catch { /* best effort */ }
    }

    try {
      await entry.chrome.kill();
    } catch {
      // Force kill via process signal
      try {
        process.kill(entry.pid, "SIGKILL");
      } catch {
        // Already dead
      }
    }

    this.launched.delete(targetId);
  }

  async deactivateAll(): Promise<void> {
    const ids = [...this.launched.keys()];
    for (const id of ids) {
      try {
        await this.deactivate(id);
      } catch {
        // Best effort
      }
    }
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description: "Launch Chrome/Chromium/Brave/Edge with proxy flags and SPKI certificate trust. Isolated temp profile, auto-cleaned on close.",
      isActivable: await this.isActivable(),
      activeTargets: [...this.launched.values()].map((l) => l.target),
    };
  }
}
