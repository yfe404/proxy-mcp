import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  formatClientAbortLine,
  installMockttpAbortFilter,
  isClientAbortError,
  isDebugLoggingEnabled,
  isMockttpRequestAbortLog,
} from "../../src/request-log.js";

/**
 * Regression for #29.
 *
 * A browser that navigates away, or a page torn down by
 * interceptor_browser_close, leaves in-flight requests half-read. mockttp's
 * streamToBuffer then rejects with `new Error('Aborted')` and mockttp's own
 * request handler prints `Failed to handle request: Aborted` for every one of
 * them (node_modules/mockttp/dist/server/mockttp-server.js). A normal discover
 * walk produced a dozen such lines, burying real upstream errors.
 */
describe("client-abort detection", () => {
  it("recognises the Error('Aborted') that streamToBuffer rejects with", () => {
    assert.equal(isClientAbortError(new Error("Aborted")), true);
  });

  it("recognises mockttp's serialised abort error object", () => {
    // mockttp's 'abort' event carries a plain { name, code, message, stack }.
    assert.equal(isClientAbortError({ name: "Error", message: "Aborted" }), true);
  });

  it("recognises a request whose readable side was aborted, whatever the error", () => {
    assert.equal(
      isClientAbortError(new Error("socket hang up"), { readableAborted: true }),
      true,
    );
  });

  it("leaves every other failure alone", () => {
    assert.equal(isClientAbortError(new Error("ECONNREFUSED")), false);
    assert.equal(isClientAbortError(new Error("Aborted upstream")), false);
    assert.equal(isClientAbortError(undefined), false);
    assert.equal(isClientAbortError(new Error("boom"), { readableAborted: false }), false);
  });

  it("formats one line naming the method and the URL, with no stack", () => {
    const line = formatClientAbortLine({ method: "GET", url: "https://example.com/a?b=1" });
    assert.equal(line, "request aborted by client: GET https://example.com/a?b=1");
    assert.equal(line.includes("\n"), false);
  });
});

describe("mockttp abort-log filter", () => {
  it("matches exactly mockttp's per-request abort line", () => {
    assert.equal(isMockttpRequestAbortLog(["Failed to handle request:", "Aborted"]), true);
    assert.equal(
      isMockttpRequestAbortLog(["Failed to handle request:", new Error("Aborted")]),
      true,
    );
  });

  it("does not match a real upstream failure on the same prefix", () => {
    assert.equal(
      isMockttpRequestAbortLog(["Failed to handle request:", "getaddrinfo ENOTFOUND"]),
      false,
    );
    assert.equal(isMockttpRequestAbortLog(["HTTP handler error:", new Error("Aborted")]), false);
    assert.equal(isMockttpRequestAbortLog(["Failed to handle request:"]), false);
  });

  it("drops the abort line and forwards everything else", () => {
    const seen: unknown[][] = [];
    const fakeConsole = { error: (...args: unknown[]) => { seen.push(args); } } as unknown as Console;

    const uninstall = installMockttpAbortFilter(fakeConsole);
    fakeConsole.error("Failed to handle request:", new Error("Aborted"));
    fakeConsole.error("Failed to handle request:", "getaddrinfo ENOTFOUND nope.invalid");
    fakeConsole.error("Shutting down…");
    uninstall();
    fakeConsole.error("Failed to handle request:", new Error("Aborted"));

    assert.deepEqual(
      seen.map((args) => args.map(String)),
      [
        ["Failed to handle request:", "getaddrinfo ENOTFOUND nope.invalid"],
        ["Shutting down…"],
        // After uninstall the original console.error is back, abort line included.
        ["Failed to handle request:", "Error: Aborted"],
      ],
    );
  });

  it("installs at most once, so a proxy restart does not stack wrappers", () => {
    const seen: unknown[][] = [];
    const fakeConsole = { error: (...args: unknown[]) => { seen.push(args); } } as unknown as Console;
    const original = fakeConsole.error;

    const uninstall1 = installMockttpAbortFilter(fakeConsole);
    const wrapped = fakeConsole.error;
    const uninstall2 = installMockttpAbortFilter(fakeConsole);
    assert.equal(fakeConsole.error, wrapped, "second install must not wrap the wrapper");

    uninstall2();
    uninstall1();
    assert.equal(fakeConsole.error, original, "uninstall must restore the original");
    assert.equal(seen.length, 0);
  });
});

describe("debug gating", () => {
  it("is off unless PROXY_MCP_DEBUG is set to a truthy value", () => {
    assert.equal(isDebugLoggingEnabled({}), false);
    assert.equal(isDebugLoggingEnabled({ PROXY_MCP_DEBUG: "" }), false);
    assert.equal(isDebugLoggingEnabled({ PROXY_MCP_DEBUG: "0" }), false);
    assert.equal(isDebugLoggingEnabled({ PROXY_MCP_DEBUG: "false" }), false);
    assert.equal(isDebugLoggingEnabled({ PROXY_MCP_DEBUG: "1" }), true);
    assert.equal(isDebugLoggingEnabled({ PROXY_MCP_DEBUG: "true" }), true);
  });
});
