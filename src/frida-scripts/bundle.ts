/**
 * Frida script bundler — concatenates vendored scripts with config substitution.
 *
 * Reads scripts from vendor/ directory, replaces config tokens, and returns
 * a single combined script string ready for Frida injection.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VENDOR_DIR = join(__dirname, "vendor");

/** Script load order — config must be first. */
const SCRIPT_FILES = [
  "config-template.js",
  "native-connect-hook.js",
  "native-tls-hook.js",
  "android-proxy-override.js",
  "android-system-certificate-injection.js",
  "android-certificate-unpinning.js",
];

export interface BundleConfig {
  proxyHost: string;
  proxyPort: number;
  certPem: string;
}

/**
 * Build a combined Frida script with config values substituted.
 *
 * @param config - Proxy host, port, and cert PEM to inject into the config template.
 * @param extraScripts - Additional script content to append (e.g., custom hooks).
 */
export function buildFridaBundle(config: BundleConfig, extraScripts?: string[]): string {
  const parts: string[] = [];

  for (const file of SCRIPT_FILES) {
    let content: string;
    try {
      content = readFileSync(join(VENDOR_DIR, file), "utf-8");
    } catch {
      // Skip missing scripts (e.g., optional hooks)
      continue;
    }

    // Substitute config tokens in the template
    if (file === "config-template.js") {
      content = content
        .replace("{{PROXY_HOST}}", config.proxyHost)
        .replace("{{PROXY_PORT}}", String(config.proxyPort))
        .replace("{{CERT_PEM}}", config.certPem.replace(/`/g, "\\`"));
    }

    parts.push(`// === ${file} ===`);
    parts.push(content);
    parts.push("");
  }

  if (extraScripts) {
    for (const script of extraScripts) {
      parts.push("// === custom ===");
      parts.push(script);
      parts.push("");
    }
  }

  return parts.join("\n");
}
