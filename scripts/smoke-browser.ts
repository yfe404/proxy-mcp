/**
 * Smoke test for the cloakbrowser + Playwright swap.
 *
 * Starts the mockttp proxy, launches cloakbrowser via the BrowserInterceptor,
 * navigates to stealth-check sites, verifies traffic capture and
 * navigator.webdriver == false. First run downloads the ~200 MB cloakbrowser
 * binary (cached afterwards).
 *
 * Run with: node --import tsx/esm scripts/smoke-browser.ts
 */

import { proxyManager } from "../src/state.js";
import { interceptorManager } from "../src/interceptors/manager.js";
import { initInterceptors } from "../src/interceptors/init.js";
import { getPageForTarget } from "../src/browser/session.js";

function line(label = ""): void {
  console.log(`\n── ${label} ${"─".repeat(Math.max(0, 60 - label.length))}`);
}

async function main() {
  initInterceptors();

  line("1) start proxy");
  const start = await proxyManager.start(0, {});
  console.log(`   port=${start.port} fp=${start.cert.fingerprint.slice(0, 32)}…`);

  line("2) launch cloakbrowser (first run downloads ~200 MB binary)");
  const launchResult = await interceptorManager.activate("browser", {
    proxyPort: start.port,
    certPem: start.cert.cert,
    certFingerprint: start.cert.fingerprint,
    url: "about:blank",
    headless: false,
    humanize: true,
  });
  const targetId = launchResult.targetId;
  console.log(`   target_id=${targetId}`);
  console.log(`   details=`, launchResult.details);

  const page = getPageForTarget(targetId);

  line("3) navigate to bot.sannysoft.com");
  try {
    const resp = await page.goto("https://bot.sannysoft.com/", {
      waitUntil: "domcontentloaded",
      timeout: 45_000,
    });
    console.log(`   http_status=${resp?.status() ?? "?"}`);
    console.log(`   url=${page.url()}`);
    console.log(`   title=${await page.title().catch(() => "?")}`);
  } catch (e) {
    console.log(`   goto failed: ${(e as Error).message}`);
  }

  // Give stealth panels time to run
  await new Promise((r) => setTimeout(r, 3000));

  line("4) check stealth properties");
  const stealth = await page.evaluate(() => ({
    webdriver: navigator.webdriver,
    userAgent: navigator.userAgent,
    chromeRuntime: typeof (window as unknown as { chrome?: { runtime?: unknown } }).chrome?.runtime,
    platform: navigator.platform,
    hardwareConcurrency: navigator.hardwareConcurrency,
    languages: navigator.languages,
  })).catch((e) => ({ error: (e as Error).message }));
  console.log("  ", JSON.stringify(stealth, null, 2));

  line("5) proxy capture");
  const traffic = proxyManager.getTraffic();
  console.log(`   total_exchanges=${traffic.length}`);
  const hosts = new Map<string, number>();
  for (const t of traffic) {
    hosts.set(t.request.hostname, (hosts.get(t.request.hostname) ?? 0) + 1);
  }
  const top = [...hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  for (const [h, n] of top) console.log(`   ${n.toString().padStart(4)} ${h}`);

  line("6) TLS fingerprints captured");
  const withTls = traffic.filter((t) => t.tls?.client?.ja3Fingerprint).slice(0, 3);
  for (const t of withTls) {
    console.log(`   ${t.request.hostname}`);
    console.log(`      ja3=${t.tls?.client?.ja3Fingerprint?.slice(0, 40)}…`);
    console.log(`      ja4=${t.tls?.client?.ja4Fingerprint ?? "?"}`);
  }

  line("7) locator-based click test (duckduckgo search box)");
  try {
    await page.goto("https://duckduckgo.com/", { waitUntil: "domcontentloaded", timeout: 30_000 });
    await page.locator('input[name="q"]').waitFor({ state: "visible", timeout: 10_000 });
    console.log(`   search box located + waited for visible ✓`);
  } catch (e) {
    console.log(`   locator test failed: ${(e as Error).message}`);
  }

  line("8) shutdown");
  await interceptorManager.deactivate("browser", targetId);
  await proxyManager.stop();
  console.log("   done");

  setTimeout(() => process.exit(0), 500);
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
