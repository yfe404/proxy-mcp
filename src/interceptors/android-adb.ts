/**
 * Android ADB interceptor — device discovery, cert injection, tunnel setup.
 *
 * Uses @devicefarmer/adbkit (dynamic import) for ADB communication.
 * Handles:
 * - Device discovery with root/model/version info
 * - CA cert injection into system store (requires root)
 * - ADB reverse tunnel for proxy access
 * - Wi-Fi proxy settings via `settings put global http_proxy`
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pemToDer, getSubjectHash } from "./cert-utils.js";
import type { Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult, ActiveTarget } from "./types.js";

const execFileAsync = promisify(execFile);

interface AdbDevice {
  target: ActiveTarget;
  serial: string;
  reversePort: number | null;
  wifiProxy: boolean;
  certInjected: boolean;
}

/** Run an adb shell command. Returns stdout. */
async function adbShell(serial: string, cmd: string): Promise<string> {
  const { stdout } = await execFileAsync("adb", ["-s", serial, "shell", cmd], { timeout: 15000 });
  return stdout.trim();
}

/** Run adb command (non-shell). */
async function adb(serial: string, ...args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("adb", ["-s", serial, ...args], { timeout: 15000 });
  return stdout.trim();
}

/** Check if device has root access. */
async function checkRoot(serial: string): Promise<boolean> {
  try {
    const id = await adbShell(serial, "id");
    if (id.includes("uid=0")) return true;
  } catch { /* not root shell */ }

  try {
    const result = await adbShell(serial, "su -c id");
    if (result.includes("uid=0")) return true;
  } catch { /* no su */ }

  try {
    const result = await adbShell(serial, "su root id");
    if (result.includes("uid=0")) return true;
  } catch { /* no su root */ }

  return false;
}

/** Get device info. */
async function getDeviceInfo(serial: string): Promise<Record<string, string>> {
  const info: Record<string, string> = { serial };
  try {
    info.model = await adbShell(serial, "getprop ro.product.model");
  } catch { /* ignore */ }
  try {
    info.version = await adbShell(serial, "getprop ro.build.version.release");
  } catch { /* ignore */ }
  try {
    info.sdk = await adbShell(serial, "getprop ro.build.version.sdk");
  } catch { /* ignore */ }
  try {
    info.manufacturer = await adbShell(serial, "getprop ro.product.manufacturer");
  } catch { /* ignore */ }
  return info;
}

export class AndroidAdbInterceptor implements Interceptor {
  readonly id = "android-adb";
  readonly name = "Android (ADB)";

  private devices = new Map<string, AdbDevice>();
  private _activable: boolean | null = null;

  async isActivable(): Promise<boolean> {
    if (this._activable !== null) return this._activable;
    try {
      await execFileAsync("adb", ["version"], { timeout: 5000 });
      this._activable = true;
    } catch {
      this._activable = false;
    }
    return this._activable;
  }

  /** List connected ADB devices with info. Not part of Interceptor interface — exposed via tool. */
  async listDevices(): Promise<Array<Record<string, unknown>>> {
    const { stdout } = await execFileAsync("adb", ["devices", "-l"], { timeout: 10000 });
    const lines = stdout.trim().split("\n").slice(1); // Skip "List of devices" header

    const devices: Array<Record<string, unknown>> = [];
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 2 || parts[1] !== "device") continue;
      const serial = parts[0];
      const info = await getDeviceInfo(serial);
      const hasRoot = await checkRoot(serial);
      devices.push({ ...info, hasRoot, active: this.devices.has(`adb_${serial}`) });
    }

    return devices;
  }

  async activate(options: ActivateOptions): Promise<ActivateResult> {
    const { proxyPort, certPem } = options;
    const serial = options.serial as string | undefined;
    const injectCert = options.injectCert !== false; // Default true
    const setupTunnel = options.setupTunnel !== false; // Default true
    const setWifiProxy = options.setWifiProxy as boolean | undefined;

    if (!serial) {
      throw new Error("'serial' option required. Use interceptor_android_devices to list devices.");
    }

    const targetId = `adb_${serial}`;
    let reversePort: number | null = null;
    let certInjected = false;
    let wifiProxy = false;

    // 1. Inject CA cert into system store (requires root)
    if (injectCert) {
      const hasRoot = await checkRoot(serial);
      if (!hasRoot) {
        throw new Error(`Device ${serial} does not have root access. Certificate injection requires root. Use injectCert:false to skip.`);
      }

      const derBuf = pemToDer(certPem);
      const hash = await getSubjectHash(certPem);
      const certFileName = `${hash}.0`;

      // Push DER cert to device temp
      const tmpPath = `/data/local/tmp/${certFileName}`;
      // Write DER to a local temp file first
      const { writeFileSync, unlinkSync } = await import("node:fs");
      const { join } = await import("node:path");
      const { tmpdir } = await import("node:os");
      const localTmp = join(tmpdir(), `adb-cert-${Date.now()}.der`);
      writeFileSync(localTmp, derBuf);

      try {
        await adb(serial, "push", localTmp, tmpPath);
      } finally {
        try { unlinkSync(localTmp); } catch { /* ignore */ }
      }

      // Mount tmpfs overlay on cacerts dir and copy cert
      const sdkStr = await adbShell(serial, "getprop ro.build.version.sdk").catch(() => "30");
      const sdk = parseInt(sdkStr, 10);

      // Standard system cert path
      await adbShell(serial, `su -c "mount -t tmpfs tmpfs /system/etc/security/cacerts 2>/dev/null; cp /system/etc/security/cacerts_orig/* /system/etc/security/cacerts/ 2>/dev/null; cp ${tmpPath} /system/etc/security/cacerts/${certFileName}; chmod 644 /system/etc/security/cacerts/${certFileName}; chown root:root /system/etc/security/cacerts/${certFileName}"`).catch(() => {
        // Fallback: try without tmpfs mount (already rw)
        return adbShell(serial, `su -c "cp ${tmpPath} /system/etc/security/cacerts/${certFileName} && chmod 644 /system/etc/security/cacerts/${certFileName}"`);
      });

      // Android 14+ APEX conscrypt module
      if (sdk >= 34) {
        await adbShell(serial, `su -c "cp ${tmpPath} /apex/com.android.conscrypt/cacerts/${certFileName} 2>/dev/null; chmod 644 /apex/com.android.conscrypt/cacerts/${certFileName} 2>/dev/null"`).catch(() => {
          // Not all devices have this path
        });
      }

      // Clean up temp
      await adbShell(serial, `rm ${tmpPath}`).catch(() => {});
      certInjected = true;
    }

    // 2. Set up ADB reverse tunnel
    if (setupTunnel) {
      await adb(serial, "reverse", `tcp:${proxyPort}`, `tcp:${proxyPort}`);
      reversePort = proxyPort;
    }

    // 3. Set Wi-Fi proxy
    if (setWifiProxy) {
      await adbShell(serial, `settings put global http_proxy 127.0.0.1:${proxyPort}`);
      wifiProxy = true;
    }

    const info = await getDeviceInfo(serial);

    const target: ActiveTarget = {
      id: targetId,
      description: `${info.manufacturer ?? ""} ${info.model ?? serial} (Android ${info.version ?? "?"})`.trim(),
      activatedAt: Date.now(),
      details: {
        serial,
        ...info,
        certInjected,
        reversePort,
        wifiProxy,
        proxyPort,
      },
    };

    this.devices.set(targetId, { target, serial, reversePort, wifiProxy, certInjected });

    return { targetId, details: target.details };
  }

  async deactivate(targetId: string): Promise<void> {
    const entry = this.devices.get(targetId);
    if (!entry) {
      throw new Error(`No ADB device with target ID '${targetId}'`);
    }

    // Remove reverse tunnel
    if (entry.reversePort) {
      await adb(entry.serial, "reverse", "--remove", `tcp:${entry.reversePort}`).catch(() => {});
    }

    // Clear Wi-Fi proxy
    if (entry.wifiProxy) {
      await adbShell(entry.serial, "settings put global http_proxy :0").catch(() => {});
    }

    this.devices.delete(targetId);
  }

  async deactivateAll(): Promise<void> {
    const ids = [...this.devices.keys()];
    for (const id of ids) {
      try {
        await this.deactivate(id);
      } catch { /* best effort */ }
    }
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description: "Push CA cert to Android system store (root required), set up ADB reverse tunnel, and optionally configure Wi-Fi proxy.",
      isActivable: await this.isActivable(),
      activeTargets: [...this.devices.values()].map((d) => d.target),
    };
  }
}
