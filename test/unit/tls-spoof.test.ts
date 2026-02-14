import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { reorderHeaders, responseDataToBuffer, stripHopByHopHeaders } from "../../src/tls-spoof.js";

describe("reorderHeaders", () => {
  it("orders specified headers first (case-insensitive) and preserves remaining order", () => {
    const headers = {
      "User-Agent": "ua",
      "Accept": "*/*",
      "X-Z": "1",
      "Host": "example.com",
      "X-A": "2",
    };

    const ordered = reorderHeaders(headers, ["host", "accept", "user-agent"]);
    assert.deepEqual(Object.keys(ordered), ["Host", "Accept", "User-Agent", "X-Z", "X-A"]);
  });
});

describe("stripHopByHopHeaders", () => {
  it("removes hop-by-hop headers and headers listed in Connection", () => {
    const headers = {
      "Connection": "keep-alive, Upgrade, X-Foo",
      "Keep-Alive": "timeout=5",
      "Upgrade": "websocket",
      "X-Foo": "bar",
      "Transfer-Encoding": "chunked",
      "Content-Type": "text/plain",
      "Proxy-Authorization": "Basic abc",
      "Proxy-Authenticate": "Basic realm=\"x\"",
      "X-Bar": "baz",
    };

    const out = stripHopByHopHeaders(headers);
    const keys = new Set(Object.keys(out).map((k) => k.toLowerCase()));

    assert.ok(!keys.has("connection"));
    assert.ok(!keys.has("keep-alive"));
    assert.ok(!keys.has("upgrade"));
    assert.ok(!keys.has("transfer-encoding"));
    assert.ok(!keys.has("proxy-authorization"));
    assert.ok(!keys.has("proxy-authenticate"));
    assert.ok(!keys.has("x-foo"));

    assert.ok(keys.has("content-type"));
    assert.ok(keys.has("x-bar"));
  });
});

describe("responseDataToBuffer", () => {
  it("handles strings", () => {
    assert.equal(responseDataToBuffer("hello").toString("utf-8"), "hello");
  });

  it("handles ArrayBuffer and TypedArray views", () => {
    const ab = Uint8Array.from([1, 2, 3]).buffer;
    assert.deepEqual([...responseDataToBuffer(ab)], [1, 2, 3]);

    const view = Uint8Array.from([4, 5, 6]);
    assert.deepEqual([...responseDataToBuffer(view)], [4, 5, 6]);
  });

  it("handles Buffer-like objects", () => {
    const data = { type: "Buffer", data: [7, 8, 9] };
    assert.deepEqual([...responseDataToBuffer(data)], [7, 8, 9]);
  });

  it("handles plain objects without throwing", () => {
    const obj = { a: 1 };
    assert.equal(responseDataToBuffer(obj).toString("utf-8"), JSON.stringify(obj));
  });

  it("falls back for circular objects", () => {
    const obj: any = {};
    obj.self = obj;
    assert.equal(responseDataToBuffer(obj).toString("utf-8"), "[object Object]");
  });
});

