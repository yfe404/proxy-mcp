/**
 * Environment shim for Node.js environments where os.networkInterfaces() throws.
 *
 * In this workspace (Node v25.3.0), os.networkInterfaces() can throw:
 *   uv_interface_addresses returned Unknown system error 1
 *
 * Some dependencies (e.g. mockttp) call os.networkInterfaces() at import time,
 * which would crash the entire process. We patch the CJS 'os' export early and
 * wrap networkInterfaces() to return an empty object on failure.
 *
 * This is intentionally best-effort: returning {} is better than crashing, and
 * callers should gracefully fall back to 127.0.0.1 behavior.
 */

import { createRequire } from "node:module";

let patched = false;

export function ensureSafeNetworkInterfaces(): void {
  if (patched) return;
  patched = true;

  const require_ = createRequire(import.meta.url);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const os = require_("os") as typeof import("node:os");

  const original = os.networkInterfaces;
  if (typeof original !== "function") return;

  // Patch the CJS export so downstream CJS deps (e.g. mockttp) don't crash on import.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (os as any).networkInterfaces = () => {
    try {
      return original.call(os);
    } catch {
      return {} as ReturnType<typeof original>;
    }
  };
}
