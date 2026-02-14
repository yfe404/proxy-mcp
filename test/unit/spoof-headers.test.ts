import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { applyFingerprintHeaderOverrides } from "../../src/spoof-headers.js";

describe("applyFingerprintHeaderOverrides", () => {
  it("returns headers unchanged when no userAgent override is provided", () => {
    const input = { "user-agent": "ua", "x-test": "1" };
    const out = applyFingerprintHeaderOverrides(input, {});
    assert.deepEqual(out, input);
  });

  it("overrides user-agent and normalizes Chromium UA client hints", () => {
    const input = {
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
      "sec-ch-ua": "\"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\", \"Not.A/Brand\";v=\"99\"",
      "sec-ch-ua-platform": "\"Linux\"",
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-full-version": "\"144.0.0.0\"",
      "x-other": "1",
    };

    const targetUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
    const out = applyFingerprintHeaderOverrides(input, { userAgent: targetUa });

    assert.equal(out["user-agent"], targetUa);
    assert.ok(out["sec-ch-ua"]?.includes("Chromium\";v=\"136\""));
    assert.ok(out["sec-ch-ua"]?.includes("Google Chrome\";v=\"136\""));
    assert.ok(out["sec-ch-ua"]?.includes("Not.A/Brand\";v=\"99\""));
    assert.equal(out["sec-ch-ua-platform"], "\"Windows\"");
    assert.equal(out["sec-ch-ua-mobile"], "?0");
    assert.equal(out["sec-ch-ua-full-version"], undefined);
    assert.equal(out["x-other"], "1");
  });

  it("strips Chromium UA client hints for non-Chromium user agents", () => {
    const input = {
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
      "sec-ch-ua": "\"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"",
      "sec-ch-ua-platform": "\"Linux\"",
      "sec-ch-ua-mobile": "?0",
      "x-other": "1",
    };

    const targetUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0";
    const out = applyFingerprintHeaderOverrides(input, { userAgent: targetUa });

    assert.equal(out["user-agent"], targetUa);
    for (const key of Object.keys(out)) {
      assert.ok(!key.toLowerCase().startsWith("sec-ch-ua"));
    }
    assert.equal(out["x-other"], "1");
  });
});

