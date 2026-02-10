/**
 * InterceptorManager — singleton registry for all interceptors.
 *
 * Provides unified list/activate/deactivate across all interceptor types.
 * Called from ProxyManager.stop() for cleanup.
 */

import type { Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult } from "./types.js";

class InterceptorManager {
  private interceptors = new Map<string, Interceptor>();

  /** Register an interceptor. Called at startup. */
  register(interceptor: Interceptor): void {
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

  /** Activate a specific interceptor. */
  async activate(interceptorId: string, options: ActivateOptions): Promise<ActivateResult> {
    const interceptor = this.interceptors.get(interceptorId);
    if (!interceptor) {
      throw new Error(`Interceptor '${interceptorId}' not found. Available: ${[...this.interceptors.keys()].join(", ")}`);
    }
    const activable = await interceptor.isActivable();
    if (!activable) {
      throw new Error(`Interceptor '${interceptorId}' is not activable. Required tooling may be missing.`);
    }
    return interceptor.activate(options);
  }

  /** Deactivate a specific target on a specific interceptor. */
  async deactivate(interceptorId: string, targetId: string): Promise<void> {
    const interceptor = this.interceptors.get(interceptorId);
    if (!interceptor) {
      throw new Error(`Interceptor '${interceptorId}' not found.`);
    }
    await interceptor.deactivate(targetId);
  }

  /** Deactivate ALL targets on ALL interceptors. Called during proxy shutdown. */
  async deactivateAll(): Promise<void> {
    const errors: string[] = [];
    for (const interceptor of this.interceptors.values()) {
      try {
        await interceptor.deactivateAll();
      } catch (e) {
        errors.push(`${interceptor.id}: ${e}`);
      }
    }
    if (errors.length > 0) {
      throw new Error(`Errors during deactivateAll: ${errors.join("; ")}`);
    }
  }
}

/** Singleton instance. */
export const interceptorManager = new InterceptorManager();
