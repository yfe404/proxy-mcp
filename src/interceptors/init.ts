/**
 * Initialize and register all interceptors with the manager.
 *
 * Runs exactly once per process. The HTTP transport builds a fresh McpServer
 * per MCP session, but the interceptor registry is a process singleton holding
 * live handles (browsers, adb tunnels, containers). Re-registering on a second
 * session would swap in empty instances and orphan those handles (#25).
 */

import { interceptorManager } from "./manager.js";
import { TerminalInterceptor } from "./terminal.js";
import { BrowserInterceptor } from "./browser.js";
import { AndroidAdbInterceptor } from "./android-adb.js";
import { AndroidFridaInterceptor } from "./android-frida.js";
import { DockerInterceptor } from "./docker.js";
import { CamoufoxInterceptor } from "./camoufox.js";

let initialized = false;

export function initInterceptors(): void {
  if (initialized) return;
  initialized = true;

  interceptorManager.register(new TerminalInterceptor());
  interceptorManager.register(new BrowserInterceptor());
  interceptorManager.register(new AndroidAdbInterceptor());
  interceptorManager.register(new AndroidFridaInterceptor());
  interceptorManager.register(new DockerInterceptor());
  interceptorManager.register(new CamoufoxInterceptor());
}
