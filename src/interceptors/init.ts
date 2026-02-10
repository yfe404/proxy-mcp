/**
 * Initialize and register all interceptors with the manager.
 * Called once at startup from index.ts.
 */

import { interceptorManager } from "./manager.js";
import { TerminalInterceptor } from "./terminal.js";
import { ChromeInterceptor } from "./chrome.js";
import { AndroidAdbInterceptor } from "./android-adb.js";
import { AndroidFridaInterceptor } from "./android-frida.js";
import { DockerInterceptor } from "./docker.js";

export function initInterceptors(): void {
  interceptorManager.register(new TerminalInterceptor());
  interceptorManager.register(new ChromeInterceptor());
  interceptorManager.register(new AndroidAdbInterceptor());
  interceptorManager.register(new AndroidFridaInterceptor());
  interceptorManager.register(new DockerInterceptor());
}
