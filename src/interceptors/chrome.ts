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
import { getCdpTargetsUrl, getCdpVersion, getCdpVersionUrl, getCdpBaseUrl } from "../cdp-utils.js";

interface LaunchedBrowser {
  target: ActiveTarget;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  chrome: any; // ChromeLauncher instance
  pid: number;
}

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

    // Proxy-specific flags added on top of chrome-launcher's defaults
    const flags = [
      `--proxy-server=http://127.0.0.1:${proxyPort}`,
      `--ignore-certificate-errors-spki-list=${certFingerprint}`,
      "--proxy-bypass-list=<-loopback>",
      "--remote-debugging-address=127.0.0.1",
    ];

    if (incognito) {
      flags.push("--incognito");
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

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const launchOptions: any = {
      chromeFlags: flags,
      startingUrl: url ?? "about:blank",
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
      },
    };

    this.launched.set(targetId, { target, chrome, pid: chrome.pid });

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
