/**
 * Browser interceptor — launch cloakbrowser (stealth Chromium) via Playwright.
 *
 * Replaces the former chrome-launcher + CDP stack. cloakbrowser ships
 * source-level C++ fingerprint patches, so no JS stealth injection is needed.
 * Humanize mode (humanize: true) handles realistic mouse/keyboard at the
 * browser level — our humanizer tools still run per-call timing profiles on top.
 */

import type {
  Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult, ActiveTarget,
} from "./types.js";
import type { Browser, BrowserContext, Page, ConsoleMessage } from "playwright-core";

export interface ConsoleEntry {
  type: string;
  text: string;
  location: string;
  timestamp: number;
}

export interface BrowserTargetEntry {
  target: ActiveTarget;
  browser: Browser;
  context: BrowserContext;
  page: Page;
  consoleBuffer: ConsoleEntry[];
}

const CONSOLE_BUFFER_MAX = 500;

export class BrowserInterceptor implements Interceptor {
  readonly id = "browser";
  readonly name = "Browser (cloakbrowser stealth Chromium)";

  private launched = new Map<string, BrowserTargetEntry>();
  private _activable: boolean | null = null;

  async isActivable(): Promise<boolean> {
    if (this._activable !== null) return this._activable;
    try {
      await import("cloakbrowser");
      await import("playwright-core");
      this._activable = true;
    } catch {
      this._activable = false;
    }
    return this._activable;
  }

  getEntry(targetId: string): BrowserTargetEntry | undefined {
    return this.launched.get(targetId);
  }

  listEntries(): BrowserTargetEntry[] {
    return [...this.launched.values()];
  }

  async activate(options: ActivateOptions): Promise<ActivateResult> {
    const { proxyPort, certFingerprint } = options;
    const url = typeof options.url === "string" ? options.url : undefined;
    const headless = typeof options.headless === "boolean" ? options.headless : false;
    const humanize = options.humanize !== false;
    const humanPreset = options.humanPreset === "careful" ? "careful" : "default";
    const timezone = typeof options.timezone === "string" ? options.timezone : undefined;
    const locale = typeof options.locale === "string" ? options.locale : undefined;
    const viewport = options.viewport as { width: number; height: number } | undefined;

    const { launchContext } = await import("cloakbrowser");

    const args = [
      `--ignore-certificate-errors-spki-list=${certFingerprint}`,
      "--proxy-bypass-list=<-loopback>",
      "--disable-quic",
    ];

    const context = await launchContext({
      headless,
      proxy: { server: `http://127.0.0.1:${proxyPort}` },
      args,
      humanize,
      humanPreset,
      ...(timezone ? { timezone } : {}),
      ...(locale ? { locale } : {}),
      ...(viewport ? { viewport } : {}),
    });

    const browser = context.browser();
    if (!browser) {
      await context.close().catch(() => {});
      throw new Error("cloakbrowser launchContext returned a context without a browser handle.");
    }

    const page = await context.newPage();

    const consoleBuffer: ConsoleEntry[] = [];
    page.on("console", (msg: ConsoleMessage) => {
      const loc = msg.location();
      consoleBuffer.push({
        type: msg.type(),
        text: msg.text(),
        location: loc.url ? `${loc.url}:${loc.lineNumber ?? 0}:${loc.columnNumber ?? 0}` : "",
        timestamp: Date.now(),
      });
      if (consoleBuffer.length > CONSOLE_BUFFER_MAX) {
        consoleBuffer.splice(0, consoleBuffer.length - CONSOLE_BUFFER_MAX);
      }
    });

    if (url) {
      try {
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
      } catch {
        // Non-fatal: caller can retry via interceptor_browser_navigate.
      }
    }

    const pid = typeof process.pid === "number" ? process.pid : 0;
    const targetId = `browser_${pid}_${Date.now()}`;

    const target: ActiveTarget = {
      id: targetId,
      description: `cloakbrowser (headless=${headless})`,
      activatedAt: Date.now(),
      details: {
        proxyPort,
        url: url ?? "about:blank",
        headless,
        humanize,
        humanPreset,
        ...(timezone ? { timezone } : {}),
        ...(locale ? { locale } : {}),
      },
    };

    this.launched.set(targetId, { target, browser, context, page, consoleBuffer });

    return { targetId, details: target.details };
  }

  async deactivate(targetId: string): Promise<void> {
    const entry = this.launched.get(targetId);
    if (!entry) {
      throw new Error(`No browser instance with target ID '${targetId}'`);
    }

    try { await entry.context.close(); } catch { /* best effort */ }
    try { await entry.browser.close(); } catch { /* already gone */ }

    this.launched.delete(targetId);
  }

  async deactivateAll(): Promise<void> {
    const ids = [...this.launched.keys()];
    for (const id of ids) {
      try { await this.deactivate(id); } catch { /* best effort */ }
    }
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description: "Launch cloakbrowser (stealth Chromium) with proxy + SPKI certificate trust. Humanize mode on by default. Driven via Playwright.",
      isActivable: await this.isActivable(),
      activeTargets: [...this.launched.values()].map((l) => l.target),
    };
  }
}
