import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { computeJa3s, cipherToIana, tlsVersionToIana } from "../../src/tls-utils.js";

describe("tlsVersionToIana", () => {
  it("maps common TLS versions", () => {
    assert.equal(tlsVersionToIana("TLSv1.3"), 772);
    assert.equal(tlsVersionToIana("TLSv1.2"), 771);
    assert.equal(tlsVersionToIana("TLSv1.1"), 770);
    assert.equal(tlsVersionToIana("TLSv1"), 769);
    assert.equal(tlsVersionToIana("SSLv3"), 768);
  });

  it("returns undefined for unknown versions", () => {
    assert.equal(tlsVersionToIana("TLSv2.0"), undefined);
  });
});

describe("cipherToIana", () => {
  it("maps TLS 1.3 standard cipher names", () => {
    assert.equal(cipherToIana({ name: "TLS_AES_128_GCM_SHA256", standardName: "TLS_AES_128_GCM_SHA256" }), 0x1301);
    assert.equal(cipherToIana({ name: "TLS_AES_256_GCM_SHA384", standardName: "TLS_AES_256_GCM_SHA384" }), 0x1302);
    assert.equal(cipherToIana({ name: "TLS_CHACHA20_POLY1305_SHA256", standardName: "TLS_CHACHA20_POLY1305_SHA256" }), 0x1303);
  });

  it("maps OpenSSL cipher names (TLS 1.2)", () => {
    assert.equal(cipherToIana({ name: "ECDHE-RSA-AES128-GCM-SHA256" }), 0xC02F);
    assert.equal(cipherToIana({ name: "ECDHE-RSA-AES256-GCM-SHA384" }), 0xC030);
    assert.equal(cipherToIana({ name: "AES128-GCM-SHA256" }), 0x009C);
  });

  it("prefers standardName over name", () => {
    assert.equal(
      cipherToIana({ name: "ECDHE-RSA-AES128-GCM-SHA256", standardName: "TLS_AES_128_GCM_SHA256" }),
      0x1301 // standardName wins
    );
  });

  it("returns undefined for unknown ciphers", () => {
    assert.equal(cipherToIana({ name: "UNKNOWN_CIPHER" }), undefined);
  });
});

describe("computeJa3s", () => {
  it("computes correct JA3S for TLS 1.3 + AES-128-GCM", () => {
    // JA3S = md5("772,4865")
    const expected = crypto.createHash("md5").update("772,4865").digest("hex");
    const result = computeJa3s("TLSv1.3", { name: "TLS_AES_128_GCM_SHA256", standardName: "TLS_AES_128_GCM_SHA256" });
    assert.equal(result, expected);
  });

  it("computes correct JA3S for TLS 1.2 + ECDHE-RSA-AES128-GCM-SHA256", () => {
    // JA3S = md5("771,49199")
    const expected = crypto.createHash("md5").update("771,49199").digest("hex");
    const result = computeJa3s("TLSv1.2", { name: "ECDHE-RSA-AES128-GCM-SHA256" });
    assert.equal(result, expected);
  });

  it("returns undefined for unknown protocol", () => {
    assert.equal(
      computeJa3s("TLSv2.0", { name: "TLS_AES_128_GCM_SHA256", standardName: "TLS_AES_128_GCM_SHA256" }),
      undefined
    );
  });

  it("returns undefined for unknown cipher", () => {
    assert.equal(
      computeJa3s("TLSv1.3", { name: "UNKNOWN_CIPHER" }),
      undefined
    );
  });
});
