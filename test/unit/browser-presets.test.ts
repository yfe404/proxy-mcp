import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { listBrowserPresets, resolveBrowserPreset } from "../../src/browser-presets.js";

describe("browser presets", () => {
  it("lists available presets", () => {
    const presets = listBrowserPresets().map((p) => p.name);
    assert.ok(presets.includes("chrome_131"));
    assert.ok(presets.includes("chrome_136"));
    assert.ok(presets.includes("firefox_133"));
  });

  it("resolves a preset with required fields", () => {
    const preset = resolveBrowserPreset("chrome_136");
    assert.equal(preset.name, "chrome_136");
    assert.ok(preset.ja3.length > 0);
    assert.ok(preset.userAgent.includes("Chrome/"));
    assert.ok(preset.http2Fingerprint.includes("|"));
    assert.ok(preset.headerOrder.length > 0);
  });

  it("throws for unknown presets", () => {
    assert.throws(
      () => resolveBrowserPreset("does_not_exist"),
      /unknown browser preset/i,
    );
  });
});
