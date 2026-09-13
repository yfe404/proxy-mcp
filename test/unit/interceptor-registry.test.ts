import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { initInterceptors } from "../../src/interceptors/init.js";
import { interceptorManager } from "../../src/interceptors/manager.js";
import type { ActivateResult, Interceptor, InterceptorMetadata } from "../../src/interceptors/types.js";

/**
 * Regression for #25.
 *
 * The HTTP transport builds a fresh McpServer per MCP session. Registration of
 * tools per session is fine, but the interceptor registry is a process
 * singleton holding live browser handles: re-running initInterceptors() on the
 * second session replaced the BrowserInterceptor with an empty one and the
 * browsers launched by the first session became unreachable.
 *
 * No real browser is launched here — a fake carries the state a launched
 * target would.
 */

/**
 * Stands in for the BrowserInterceptor holding a live target across sessions.
 *
 * It takes the real `browser` id deliberately: a second initInterceptors()
 * that re-registered would overwrite this instance and lose `launched` — the
 * reported failure. Registering under a private id instead would prove
 * nothing, since initInterceptors never touches such an id either way.
 */
class FakeBrowserInterceptor implements Interceptor {
  readonly id = "browser";
  readonly name = "Fake browser";
  readonly launched: string[] = [];

  async isActivable(): Promise<boolean> {
    return true;
  }

  async activate(): Promise<ActivateResult> {
    const targetId = `browser_${this.launched.length}`;
    this.launched.push(targetId);
    return { targetId, details: {} };
  }

  async deactivate(targetId: string): Promise<void> {
    const i = this.launched.indexOf(targetId);
    if (i !== -1) this.launched.splice(i, 1);
  }

  async deactivateAll(): Promise<void> {
    this.launched.length = 0;
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description: "fake",
      isActivable: true,
      activeTargets: [],
    };
  }
}

/** Mirrors the registrations in src/interceptors/init.ts. */
const REGISTERED_IDS = [
  "terminal",
  "browser",
  "docker",
];

describe("interceptor registry across MCP sessions", () => {
  it("keeps the same interceptor instances when a second session initialises", async () => {
    // Session A starts: index.ts createMcpServer() calls initInterceptors().
    initInterceptors();
    for (const id of REGISTERED_IDS) {
      assert.ok(interceptorManager.get(id), `${id} should be registered after the first init`);
    }

    // Swap the browser interceptor for a fake so a launched target can be
    // asserted without starting Chromium, and snapshot every instance.
    const fake = new FakeBrowserInterceptor();
    interceptorManager.register(fake);
    const sessionA = new Map(REGISTERED_IDS.map((id) => [id, interceptorManager.get(id)]));

    // Session A launches a target; the handle lives on the registered instance.
    const { targetId } = await interceptorManager.activate("browser", {
      proxyPort: 1,
      certPem: "",
      certFingerprint: "",
    });

    // Session B starts in the same process.
    initInterceptors();

    // Every interceptor is the very same object — initInterceptors did not
    // re-register, so no live handle was dropped.
    for (const [id, interceptor] of sessionA) {
      assert.equal(interceptorManager.get(id), interceptor, `${id} was replaced by the second init`);
    }

    // Session B can still reach the target session A launched.
    const seen = interceptorManager.get("browser") as FakeBrowserInterceptor;
    assert.deepEqual(seen.launched, [targetId]);
  });
});
