/**
 * Certificate utility functions for interceptors.
 *
 * Handles PEM→DER conversion, OpenSSL subject hash computation (for Android
 * system cert naming), and temp file management.
 */

import { createHash } from "node:crypto";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Strip PEM headers/footers and decode base64 → Buffer (DER format). */
export function pemToDer(pem: string): Buffer {
  const lines = pem.split("\n").filter(
    (l) => !l.startsWith("-----") && l.trim().length > 0,
  );
  return Buffer.from(lines.join(""), "base64");
}

/**
 * Compute the OpenSSL-compatible subject hash for naming certs on Android.
 *
 * Android's system cert store expects files named `{hash}.0` where hash is the
 * OpenSSL subject_hash (MD5 of the DER-encoded subject, first 4 bytes LE, hex).
 *
 * Parses the DER-encoded certificate's ASN.1 structure to extract the subject
 * field, then computes MD5 of that, reading the first 4 bytes as LE uint32.
 */
export function getSubjectHash(pem: string): string {
  const derCert = pemToDer(pem);

  // Parse ASN.1 DER to find the subject field (6th element in TBSCertificate)
  // TBSCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... }
  const subjectDer = extractSubjectDer(derCert);

  const md5 = createHash("md5").update(subjectDer).digest();
  const hashValue = md5.readUInt32LE(0);
  return hashValue.toString(16).padStart(8, "0");
}

/** Extract the DER-encoded subject from a DER certificate. */
function extractSubjectDer(der: Buffer): Buffer {
  // Parse outer SEQUENCE
  let offset = 0;
  if (der[offset] !== 0x30) throw new Error("Not a DER SEQUENCE");
  offset++;
  const { length: outerLen, bytesRead } = readAsn1Length(der, offset);
  offset += bytesRead;
  void outerLen;

  // TBSCertificate is a SEQUENCE
  if (der[offset] !== 0x30) throw new Error("TBSCertificate not a SEQUENCE");
  offset++;
  const { bytesRead: tbsLenBytes } = readAsn1Length(der, offset);
  offset += tbsLenBytes;

  // version (context-specific [0], optional)
  if (der[offset] === 0xa0) {
    offset++;
    const { length: vLen, bytesRead: vBytes } = readAsn1Length(der, offset);
    offset += vBytes + vLen;
  }

  // serialNumber (INTEGER)
  offset = skipAsn1Element(der, offset);

  // signature (SEQUENCE)
  offset = skipAsn1Element(der, offset);

  // issuer (SEQUENCE)
  offset = skipAsn1Element(der, offset);

  // validity (SEQUENCE)
  offset = skipAsn1Element(der, offset);

  // subject (SEQUENCE) — this is what we want
  const subjectStart = offset;
  offset = skipAsn1Element(der, offset);
  return der.subarray(subjectStart, offset);
}

function readAsn1Length(buf: Buffer, offset: number): { length: number; bytesRead: number } {
  const first = buf[offset];
  if (first < 0x80) {
    return { length: first, bytesRead: 1 };
  }
  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return { length, bytesRead: 1 + numBytes };
}

function skipAsn1Element(buf: Buffer, offset: number): number {
  offset++; // skip tag
  const { length, bytesRead } = readAsn1Length(buf, offset);
  return offset + bytesRead + length;
}

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
