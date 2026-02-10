import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { truncateResult, getLocalIP, serializeHeaders, capString } from "../../src/utils.js";

describe("truncateResult", () => {
  it("returns short data unchanged", () => {
    const data = { foo: "bar" };
    const result = truncateResult(data);
    assert.equal(result, JSON.stringify(data));
  });

  it("truncates large arrays with binary search", () => {
    const data = Array.from({ length: 5000 }, (_, i) => ({ id: i, value: "x".repeat(100) }));
    const result = truncateResult(data);
    const parsed = JSON.parse(result);
    assert.equal(parsed.truncated, true);
    assert.ok(parsed.showing < 5000);
    assert.equal(parsed.total, 5000);
    assert.ok(result.length <= 24000);
  });

  it("truncates large strings", () => {
    const data = "x".repeat(30000);
    const result = truncateResult(data);
    assert.ok(result.length <= 24000);
    assert.ok(result.includes("[truncated"));
  });
});

describe("getLocalIP", () => {
  it("returns a valid IP string", () => {
    const ip = getLocalIP();
    assert.ok(typeof ip === "string");
    assert.ok(ip.length > 0);
  });
});

describe("serializeHeaders", () => {
  it("lowercases keys and joins arrays", () => {
    const headers = {
      "Content-Type": "application/json",
      "X-Custom": ["a", "b"],
      "X-Undefined": undefined,
    };
    const result = serializeHeaders(headers);
    assert.equal(result["content-type"], "application/json");
    assert.equal(result["x-custom"], "a, b");
    assert.ok(!("x-undefined" in result));
  });
});

describe("capString", () => {
  it("returns short strings unchanged", () => {
    assert.equal(capString("hello", 10), "hello");
  });

  it("truncates long strings with ellipsis", () => {
    assert.equal(capString("hello world", 5), "hello...");
  });
});
