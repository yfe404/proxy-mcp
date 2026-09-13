/**
 * InterceptorManager — singleton registry for all interceptors.
 *
 * Provides unified list/activate/deactivate across all interceptor types.
 * Called from ProxyManager.stop() for cleanup.
 *
 * The registry is a process singleton while the HTTP transport builds one
 * McpServer per MCP session, so it also records which session activated each
 * target. That lets `proxy_stop` tear down only its own caller's targets
 * instead of every session's browsers (#26).
 */

import type { Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult } from "./types.js";

/** Owner map key. JSON keeps the two ids unambiguous whatever characters they hold. */
function ownerKey(interceptorId: string, targetId: string): string {
  return JSON.stringify([interceptorId, targetId]);
}

function parseOwnerKey(key: string): [interceptorId: string, targetId: string] {
  return JSON.parse(key) as [string, string];
}

export class InterceptorManager {
  private interceptors = new Map<string, Interceptor>();
  /** interceptorId + targetId → the MCP session that activated it. */
  private owners = new Map<string, string>();

  /**
   * Register an interceptor. Called at startup.
   *
   * Throws on a duplicate id. The registry holds live handles (browsers,
   * containers), so replacing an entry would orphan them (#25). Registration
   * happens exactly once per process, from initInterceptors().
   */
  register(interceptor: Interceptor): void {
    if (this.interceptors.has(interceptor.id)) {
      throw new Error(
        `Interceptor '${interceptor.id}' is already registered. Registration happens once per ` +
        `process; replacing an entry would orphan the targets the existing one holds.`,
      );
    }
    this.interceptors.set(interceptor.id, interceptor);
  }

  /** Get an interceptor by ID. */
  get(id: string): Interceptor | undefined {
    return this.interceptors.get(id);
  }

  /** List all registered interceptors with metadata. */
  async list(): Promise<InterceptorMetadata[]> {
    const results: InterceptorMetadata[] = [];
    for (const interceptor of this.interceptors.values()) {
      results.push(await interceptor.getMetadata());
    }
    return results;
  }

  /**
   * Activate a specific interceptor.
   *
   * `ownerSessionId` is the MCP session that asked for it, when the transport
   * has one (HTTP). stdio has no session id, so such targets stay unowned and
   * are only torn down by deactivateAll().
   */
  async activate(
    interceptorId: string,
    options: ActivateOptions,
    ownerSessionId?: string,
  ): Promise<ActivateResult> {
    const interceptor = this.interceptors.get(interceptorId);
    if (!interceptor) {
      throw new Error(`Interceptor '${interceptorId}' not found. Available: ${[...this.interceptors.keys()].join(", ")}`);
    }
    const activable = await interceptor.isActivable();
    if (!activable) {
      throw new Error(`Interceptor '${interceptorId}' is not activable. Required tooling may be missing.`);
    }
    const result = await interceptor.activate(options);
    if (ownerSessionId) {
      this.owners.set(ownerKey(interceptorId, result.targetId), ownerSessionId);
    }
    return result;
  }

  /** Deactivate a specific target on a specific interceptor. */
  async deactivate(interceptorId: string, targetId: string): Promise<void> {
    const interceptor = this.interceptors.get(interceptorId);
    if (!interceptor) {
      throw new Error(`Interceptor '${interceptorId}' not found.`);
    }
    await interceptor.deactivate(targetId);
    this.owners.delete(ownerKey(interceptorId, targetId));
  }

  /** The MCP session that activated a target, when it was activated with one. */
  ownerOf(interceptorId: string, targetId: string): string | undefined {
    return this.owners.get(ownerKey(interceptorId, targetId));
  }

  /**
   * Deactivate only the targets activated through one MCP session.
   *
   * Targets activated without a session id (stdio) are left running:
   * deactivateAll() is the only thing that takes those down. Returns the
   * number of targets deactivated.
   */
  async deactivateOwnedBy(sessionId: string): Promise<number> {
    const errors: string[] = [];
    let deactivated = 0;
    for (const [key, owner] of [...this.owners]) {
      if (owner !== sessionId) continue;
      const [interceptorId, targetId] = parseOwnerKey(key);
      this.owners.delete(key);
      const interceptor = this.interceptors.get(interceptorId);
      if (!interceptor) continue;
      try {
        await interceptor.deactivate(targetId);
        deactivated++;
      } catch (e) {
        errors.push(`${interceptorId}/${targetId}: ${e}`);
      }
    }
    if (errors.length > 0) {
      throw new Error(`Errors during deactivateOwnedBy: ${errors.join("; ")}`);
    }
    return deactivated;
  }

  /** Deactivate ALL targets on ALL interceptors, whichever session activated them. */
  async deactivateAll(): Promise<void> {
    const errors: string[] = [];
    for (const interceptor of this.interceptors.values()) {
      try {
        await interceptor.deactivateAll();
      } catch (e) {
        errors.push(`${interceptor.id}: ${e}`);
      }
    }
    this.owners.clear();
    if (errors.length > 0) {
      throw new Error(`Errors during deactivateAll: ${errors.join("; ")}`);
    }
  }
}

/** Singleton instance. */
export const interceptorManager = new InterceptorManager();
