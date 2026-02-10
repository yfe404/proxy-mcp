/**
 * Interceptor interface and shared types.
 *
 * Each interceptor manages a specific target type (Chrome, Android, Docker, etc.)
 * and handles proxy configuration + certificate trust automatically.
 */

/** Metadata returned by getMetadata() for display/discovery. */
export interface InterceptorMetadata {
  id: string;
  name: string;
  description: string;
  /** Whether the required tooling (adb, docker, chrome, etc.) is available. */
  isActivable: boolean;
  /** Currently active targets managed by this interceptor. */
  activeTargets: ActiveTarget[];
}

/** A single active interception target (a Chrome instance, an Android device, etc.). */
export interface ActiveTarget {
  id: string;
  description: string;
  activatedAt: number;
  details: Record<string, unknown>;
}

/** Options passed to activate(). */
export interface ActivateOptions {
  /** Proxy port on the host machine. */
  proxyPort: number;
  /** CA certificate PEM string. */
  certPem: string;
  /** SPKI fingerprint of the CA certificate. */
  certFingerprint: string;
  /** Additional interceptor-specific options. */
  [key: string]: unknown;
}

/** Result of a successful activation. */
export interface ActivateResult {
  targetId: string;
  details: Record<string, unknown>;
}

/** The interceptor contract. All interceptors implement this. */
export interface Interceptor {
  readonly id: string;
  readonly name: string;

  /**
   * Check if this interceptor can be activated (required tooling exists).
   * Uses dynamic imports — returns false if dependencies are missing.
   */
  isActivable(): Promise<boolean>;

  /**
   * Activate interception for a target.
   * Handles proxy config, certificate trust, tunnel setup, etc.
   */
  activate(options: ActivateOptions): Promise<ActivateResult>;

  /**
   * Deactivate a specific target by ID.
   */
  deactivate(targetId: string): Promise<void>;

  /**
   * Deactivate all active targets. Called during proxy shutdown.
   */
  deactivateAll(): Promise<void>;

  /**
   * Get metadata for display: availability, active targets.
   */
  getMetadata(): Promise<InterceptorMetadata>;
}
