/**
 * Certificate utility functions for interceptors.
 *
 * Writes the CA cert to a temp file the terminal interceptor can point
 * SSL_CERT_FILE and friends at, and cleans those files up on proxy stop.
 */

import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Track temp cert files for cleanup
const tempCertFiles: string[] = [];

/**
 * Write CA cert PEM to a temp file. Returns the path.
 * Reuses existing file if already written (same PEM = same file).
 */
let _cachedCertPath: string | null = null;
let _cachedCertPem: string | null = null;

export async function writeCertTempFile(pem: string): Promise<string> {
  if (_cachedCertPath && _cachedCertPem === pem) {
    return _cachedCertPath;
  }

  const path = join(tmpdir(), `proxy-mcp-ca-${Date.now()}.pem`);
  await writeFile(path, pem, "utf-8");
  tempCertFiles.push(path);
  _cachedCertPath = path;
  _cachedCertPem = pem;
  return path;
}

/** Clean up all temp cert files. */
export async function cleanupTempCerts(): Promise<void> {
  for (const path of tempCertFiles) {
    try {
      await unlink(path);
    } catch {
      // Ignore — file may already be deleted
    }
  }
  tempCertFiles.length = 0;
  _cachedCertPath = null;
  _cachedCertPem = null;
}
