/**
 * Docker interceptor — inject proxy config + CA cert into containers.
 *
 * Uses dockerode (dynamic import) to communicate with the Docker daemon.
 * Two modes:
 * - exec: Run commands inside the container to set env vars and write cert
 * - restart: Recreate container with proxy env vars + cert volume mount
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Interceptor, InterceptorMetadata, ActivateOptions, ActivateResult, ActiveTarget } from "./types.js";

interface DockerTarget {
  target: ActiveTarget;
  containerId: string;
  mode: "exec" | "restart";
  originalEnv?: string[];
}

export class DockerInterceptor implements Interceptor {
  readonly id = "docker";
  readonly name = "Docker Container";

  private targets = new Map<string, DockerTarget>();
  private _activable: boolean | null = null;

  async isActivable(): Promise<boolean> {
    if (this._activable !== null) return this._activable;
    try {
      const Docker = (await import("dockerode")).default;
      const docker = new Docker();
      await docker.ping();
      this._activable = true;
    } catch {
      this._activable = false;
    }
    return this._activable;
  }

  async activate(options: ActivateOptions): Promise<ActivateResult> {
    const { proxyPort, certPem } = options;
    const containerId = options.containerId as string | undefined;
    const mode = (options.mode as string) ?? "exec";

    if (!containerId) {
      throw new Error("'containerId' option is required for Docker interceptor.");
    }

    const Docker = (await import("dockerode")).default;
    const docker = new Docker();

    const container = docker.getContainer(containerId);
    const info = await container.inspect();
    const containerName = info.Name.replace(/^\//, "");

    const proxyUrl = `http://host.docker.internal:${proxyPort}`;
    const targetId = `docker_${containerId.slice(0, 12)}`;

    if (mode === "exec") {
      // Write cert to a temp dir that we'll copy into the container
      const certDir = join(tmpdir(), `proxy-mcp-docker-${Date.now()}`);
      mkdirSync(certDir, { recursive: true });
      const certPath = join(certDir, "proxy-mcp-ca.pem");
      writeFileSync(certPath, certPem, "utf-8");

      // Copy cert into container
      const { execSync } = await import("node:child_process");
      execSync(`docker cp "${certPath}" ${containerId}:/tmp/proxy-mcp-ca.pem`, { timeout: 10000 });

      // Set env vars inside container using exec
      const envCommands = [
        `export HTTP_PROXY=${proxyUrl}`,
        `export HTTPS_PROXY=${proxyUrl}`,
        `export http_proxy=${proxyUrl}`,
        `export https_proxy=${proxyUrl}`,
        `export SSL_CERT_FILE=/tmp/proxy-mcp-ca.pem`,
        `export NODE_EXTRA_CA_CERTS=/tmp/proxy-mcp-ca.pem`,
        `export REQUESTS_CA_BUNDLE=/tmp/proxy-mcp-ca.pem`,
        `export CURL_CA_BUNDLE=/tmp/proxy-mcp-ca.pem`,
      ];

      // Write a profile script that sets these on each new shell
      const profileScript = envCommands.join("\n") + "\n";
      const profileExec = await container.exec({
        Cmd: ["sh", "-c", `echo '${profileScript.replace(/'/g, "'\\''")}' > /etc/profile.d/proxy-mcp.sh 2>/dev/null || echo '${profileScript.replace(/'/g, "'\\''")}' >> /etc/profile 2>/dev/null`],
        AttachStdout: true,
        AttachStderr: true,
      });
      await profileExec.start({});

      // Also try updating /etc/environment for some distros
      const envExec = await container.exec({
        Cmd: ["sh", "-c", [
          `echo "HTTP_PROXY=${proxyUrl}" >> /etc/environment`,
          `echo "HTTPS_PROXY=${proxyUrl}" >> /etc/environment`,
          `echo "SSL_CERT_FILE=/tmp/proxy-mcp-ca.pem" >> /etc/environment`,
          `echo "NODE_EXTRA_CA_CERTS=/tmp/proxy-mcp-ca.pem" >> /etc/environment`,
        ].join(" && ")],
        AttachStdout: true,
        AttachStderr: true,
      });
      await envExec.start({});

      const target: ActiveTarget = {
        id: targetId,
        description: `${containerName} (${containerId.slice(0, 12)}) [exec mode]`,
        activatedAt: Date.now(),
        details: {
          containerId,
          containerName,
          mode: "exec",
          proxyUrl,
          certInjected: true,
          note: "Proxy env vars set. New processes in this container will use the proxy. Existing processes may need restart.",
        },
      };

      this.targets.set(targetId, { target, containerId, mode: "exec" });
      return { targetId, details: target.details };

    } else {
      // Restart mode — stop, recreate with proxy env, start
      // This is more invasive but ensures ALL processes in the container use the proxy

      // Save original env for restore
      const originalEnv = info.Config.Env || [];

      const proxyEnvVars = [
        `HTTP_PROXY=${proxyUrl}`,
        `HTTPS_PROXY=${proxyUrl}`,
        `http_proxy=${proxyUrl}`,
        `https_proxy=${proxyUrl}`,
        `SSL_CERT_FILE=/tmp/proxy-mcp-ca.pem`,
        `NODE_EXTRA_CA_CERTS=/tmp/proxy-mcp-ca.pem`,
        `REQUESTS_CA_BUNDLE=/tmp/proxy-mcp-ca.pem`,
        `CURL_CA_BUNDLE=/tmp/proxy-mcp-ca.pem`,
      ];

      // For restart mode, we just inject env vars via exec and restart the main process
      // Full container recreation is too invasive for an MCP tool
      await container.stop().catch(() => {});

      // Note: true container recreation would require Docker compose or similar
      // For now, we add env via exec after restart
      await container.start();

      // Copy cert and set env after restart
      const { execSync } = await import("node:child_process");
      const certDir = join(tmpdir(), `proxy-mcp-docker-${Date.now()}`);
      mkdirSync(certDir, { recursive: true });
      writeFileSync(join(certDir, "proxy-mcp-ca.pem"), certPem, "utf-8");
      execSync(`docker cp "${join(certDir, "proxy-mcp-ca.pem")}" ${containerId}:/tmp/proxy-mcp-ca.pem`, { timeout: 10000 });

      const envScript = proxyEnvVars.map((e) => `export ${e}`).join("\n") + "\n";
      const exec = await container.exec({
        Cmd: ["sh", "-c", `echo '${envScript.replace(/'/g, "'\\''")}' > /etc/profile.d/proxy-mcp.sh 2>/dev/null || true`],
        AttachStdout: true,
        AttachStderr: true,
      });
      await exec.start({});

      const target: ActiveTarget = {
        id: targetId,
        description: `${containerName} (${containerId.slice(0, 12)}) [restart mode]`,
        activatedAt: Date.now(),
        details: {
          containerId,
          containerName,
          mode: "restart",
          proxyUrl,
          restarted: true,
        },
      };

      this.targets.set(targetId, { target, containerId, mode: "restart", originalEnv });
      return { targetId, details: target.details };
    }
  }

  async deactivate(targetId: string): Promise<void> {
    const entry = this.targets.get(targetId);
    if (!entry) {
      throw new Error(`No Docker target with ID '${targetId}'`);
    }

    try {
      const Docker = (await import("dockerode")).default;
      const docker = new Docker();
      const container = docker.getContainer(entry.containerId);

      // Remove proxy profile script
      const exec = await container.exec({
        Cmd: ["sh", "-c", "rm -f /etc/profile.d/proxy-mcp.sh /tmp/proxy-mcp-ca.pem 2>/dev/null || true"],
        AttachStdout: true,
        AttachStderr: true,
      });
      await exec.start({});
    } catch {
      // Best effort — container may be stopped
    }

    this.targets.delete(targetId);
  }

  async deactivateAll(): Promise<void> {
    const ids = [...this.targets.keys()];
    for (const id of ids) {
      try {
        await this.deactivate(id);
      } catch { /* best effort */ }
    }
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return {
      id: this.id,
      name: this.name,
      description: "Inject proxy env vars and CA certificate into Docker containers via exec or restart mode.",
      isActivable: await this.isActivable(),
      activeTargets: [...this.targets.values()].map((t) => t.target),
    };
  }
}
