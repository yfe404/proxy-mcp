import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveToolMap } from "../../src/devtools/tool-map.js";

describe("devtools tool map", () => {
  it("resolves canonical chrome-devtools-mcp names", () => {
    const map = resolveToolMap([
      "navigate_page",
      "take_snapshot",
      "list_network_requests",
      "list_console_messages",
      "take_screenshot",
    ]);

    assert.equal(map.navigate, "navigate_page");
    assert.equal(map.snapshot, "take_snapshot");
    assert.equal(map.listNetwork, "list_network_requests");
    assert.equal(map.listConsole, "list_console_messages");
    assert.equal(map.screenshot, "take_screenshot");
  });

  it("resolves browser_* fallback names", () => {
    const map = resolveToolMap([
      "browser_navigate",
      "browser_snapshot",
      "browser_network_requests",
      "browser_console_messages",
      "browser_take_screenshot",
    ]);

    assert.equal(map.navigate, "browser_navigate");
    assert.equal(map.snapshot, "browser_snapshot");
    assert.equal(map.listNetwork, "browser_network_requests");
    assert.equal(map.listConsole, "browser_console_messages");
    assert.equal(map.screenshot, "browser_take_screenshot");
  });

  it("throws when required tools are missing", () => {
    assert.throws(
      () => resolveToolMap(["navigate_page"]),
      /missing required tools/i,
    );
  });
});
