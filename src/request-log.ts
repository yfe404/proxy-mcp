/**
 * Logging helpers for proxied requests.
 *
 * A client that cancels an in-flight request (navigation away, page teardown,
 * `interceptor_browser_close`) leaves mockttp's `streamToBuffer` rejecting with
 * `new Error('Aborted')`. mockttp catches that in its own request handler and
 * prints `Failed to handle request: Aborted` for every cancelled request
 * (node_modules/mockttp/dist/server/mockttp-server.js), which buries real
 * upstream errors in the server log (#29).
 *
 * mockttp exposes no logger to inject, so the noise is removed at the only
 * seam there is: `console.error` is wrapped while the proxy runs, and exactly
 * that one line is dropped. The cancellation itself is reported once, at debug
 * level, from the proxy's `abort` event, which carries the method and URL that
 * mockttp's line does not.
 */

/** The first argument of mockttp's per-request error log. */
const MOCKTTP_REQUEST_ERROR_PREFIX = "Failed to handle request:";

/** The message `streamToBuffer` rejects with when the client goes away. */
const ABORT_MESSAGE = "Aborted";

/** The part of a Node request this module needs. */
export interface AbortedRequestLike {
  method?: string;
  url?: string;
  /** Node sets this on the incoming message when the client cut the body short. */
  readableAborted?: boolean;
}

function messageOf(err: unknown): string | undefined {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  if (err && typeof err === "object" && typeof (err as { message?: unknown }).message === "string") {
    return (err as { message: string }).message;
  }
  return undefined;
}

/**
 * True when a request failure is the client cancelling, not an upstream error.
 *
 * Either side is enough: the error mockttp rejects with, or a request whose
 * readable side Node already marked as aborted.
 */
export function isClientAbortError(err: unknown, req?: AbortedRequestLike | null): boolean {
  if (req?.readableAborted === true) return true;
  return messageOf(err) === ABORT_MESSAGE;
}

/** The single debug line reported for a cancelled request. No stack. */
export function formatClientAbortLine(req: AbortedRequestLike): string {
  return `request aborted by client: ${req.method ?? "?"} ${req.url ?? "?"}`;
}

/** True when these console.error arguments are mockttp's abort noise. */
export function isMockttpRequestAbortLog(args: unknown[]): boolean {
  return args.length >= 2
    && args[0] === MOCKTTP_REQUEST_ERROR_PREFIX
    && isClientAbortError(args[1]);
}

/** Debug logging is opt-in through PROXY_MCP_DEBUG. */
export function isDebugLoggingEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env.PROXY_MCP_DEBUG;
  if (value === undefined) return false;
  const normalized = value.trim().toLowerCase();
  return normalized !== "" && normalized !== "0" && normalized !== "false";
}

/** Write one line to stderr when debug logging is on. */
export function debugLog(line: string, env: NodeJS.ProcessEnv = process.env): void {
  if (isDebugLoggingEnabled(env)) console.error(line);
}

/** Report a cancelled request once, at debug level. */
export function logClientAbort(req: AbortedRequestLike, env: NodeJS.ProcessEnv = process.env): void {
  debugLog(formatClientAbortLine(req), env);
}

const installed = new WeakMap<Console, { original: Console["error"]; wrapper: Console["error"] }>();

/**
 * Drop mockttp's per-request abort line from `console.error`.
 *
 * Idempotent: a second install on the same console is a no-op, so restarting
 * the proxy does not stack wrappers. Returns the uninstaller.
 */
export function installMockttpAbortFilter(target: Console = console): () => void {
  const existing = installed.get(target);
  if (existing) return () => uninstall(target);

  const original = target.error;
  const wrapper = (...args: unknown[]): void => {
    if (isMockttpRequestAbortLog(args)) return;
    original.apply(target, args);
  };
  target.error = wrapper as Console["error"];
  installed.set(target, { original, wrapper });
  return () => uninstall(target);
}

function uninstall(target: Console): void {
  const entry = installed.get(target);
  if (!entry) return;
  // Only restore if nothing else replaced console.error in the meantime.
  if (target.error === entry.wrapper) target.error = entry.original;
  installed.delete(target);
}
