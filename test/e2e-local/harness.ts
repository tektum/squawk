import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";

export type LocalWorker = {
  readonly url: string;
  /** Captured `wrangler dev` output, printed when a check fails. */
  readonly logPath: string;
  stop(): Promise<void>;
};

export type StartWorkerOptions = {
  readonly config: string;
  readonly persistTo: string;
  readonly envFile: string;
  readonly hostname: string;
  readonly port: number;
};

const databaseName = "squawk";

/**
 * Binds to loopback so the same run works on a CI runner, which has no Tailscale
 * address. The repository's usual rule against loopback listeners was waived for this
 * harness precisely so one implementation covers both places; nothing here is meant to
 * be reachable off the machine, and every port is ephemeral.
 *
 * `E2E_HOST` overrides it for a run that should be reachable from elsewhere.
 */
export function bindAddress(): string {
  return process.env["E2E_HOST"] ?? "127.0.0.1";
}

export async function freePort(hostname: string): Promise<number> {
  const { promise, resolve, reject } = Promise.withResolvers<number>();
  const probe = createServer();
  probe.once("error", reject);
  probe.listen(0, hostname, () => {
    const address = probe.address();
    if (address === null || typeof address === "string") {
      probe.close(() => reject(new Error("could not resolve an ephemeral port")));
      return;
    }
    const { port } = address;
    probe.close(() => resolve(port));
  });
  return promise;
}

/** Strips JSONC comments without touching `//` inside string literals. */
function parseJsonc(source: string): Record<string, unknown> {
  let output = "";
  let inString = false;
  let escaped = false;
  let index = 0;
  while (index < source.length) {
    const character = source[index] ?? "";
    const next = source[index + 1] ?? "";
    if (inString) {
      output += character;
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      index += 1;
      continue;
    }
    if (character === '"') {
      inString = true;
      output += character;
      index += 1;
      continue;
    }
    if (character === "/" && next === "/") {
      while (index < source.length && source[index] !== "\n") index += 1;
      continue;
    }
    if (character === "/" && next === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/"))
        index += 1;
      index += 2;
      continue;
    }
    output += character;
    index += 1;
  }
  return JSON.parse(output) as Record<string, unknown>;
}

/**
 * Derives the local configuration from the committed one, so the end-to-end run
 * exercises the real bindings, compatibility date and migrations directory, and only
 * the external origins move to the fake server.
 *
 * It is written at the repository root because Wrangler resolves `main` and
 * `migrations_dir` relative to the configuration file, so a temporary directory would
 * silently need every path rewritten.
 */
export function writeLocalConfig(originUrl: string): string {
  const source = parseJsonc(readFileSync("wrangler.jsonc", "utf8"));
  const config: Record<string, unknown> = {
    ...source,
    name: "squawk-e2e",
    vars: {
      ...(source["vars"] as Record<string, unknown> | undefined),
      DISPATCH_ENABLED: "true",
      OSV_API_URL: originUrl,
      OSV_BASE_URL: originUrl,
      GITHUB_API_URL: originUrl,
      GHCR_URL: originUrl,
    },
    d1_databases: [{ binding: "DB", database_name: databaseName, database_id: databaseName }],
    observability: { enabled: false },
  };
  // Named environments carry deployed-only wiring. The queue binding stays: the advisory
  // requeue stage calls sendBatch on it and Miniflare runs queues locally, so dropping it
  // would leave that stage failing in every local run.
  delete config["env"];
  const path = "wrangler.e2e.local.json";
  writeFileSync(path, JSON.stringify(config, null, 2));
  return path;
}

/** Keeps Wrangler offline and quiet: a CI runner has no account and no consent to phone home. */
const wranglerEnv: Record<string, string> = {
  ...(process.env as Record<string, string>),
  WRANGLER_SEND_METRICS: "false",
};

function wrangler(args: readonly string[], persistTo: string): string {
  return execFileSync("bunx", ["wrangler", ...args, "--persist-to", persistTo], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: wranglerEnv,
  });
}

export function applyMigrations(config: string, persistTo: string): void {
  wrangler(["d1", "migrations", "apply", databaseName, "--local", "-c", config], persistTo);
}

export function query<Row extends Record<string, unknown> = Record<string, unknown>>(
  config: string,
  persistTo: string,
  command: string,
): readonly Row[] {
  const output = wrangler(
    ["d1", "execute", databaseName, "--local", "-c", config, "--json", "--command", command],
    persistTo,
  );
  const start = output.indexOf("[");
  if (start < 0) return [];
  const blocks = JSON.parse(output.slice(start)) as { readonly results?: readonly Row[] }[];
  return blocks.flatMap((block) => block.results ?? []);
}

export async function startWorker(options: StartWorkerOptions): Promise<LocalWorker> {
  const logPath = join(options.persistTo, "worker.log");
  const log = Bun.file(logPath).writer();
  const child = Bun.spawn(
    [
      "bunx",
      "wrangler",
      "dev",
      "-c",
      options.config,
      "--local",
      "--persist-to",
      options.persistTo,
      "--env-file",
      options.envFile,
      "--ip",
      options.hostname,
      "--port",
      String(options.port),
      "--test-scheduled",
    ],
    { stdout: "pipe", stderr: "pipe", stdin: "ignore", env: wranglerEnv },
  );
  // The Worker's own console output is the only account of what a stage did, so it is
  // kept rather than discarded: a failing check prints its tail.
  const drain = async (stream: ReadableStream<Uint8Array>): Promise<void> => {
    for await (const chunk of stream) log.write(chunk);
    await log.flush();
  };
  void drain(child.stdout);
  void drain(child.stderr);
  const url = `http://${options.hostname}:${options.port}`;
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${url}/health`, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) {
        await response.text();
        return {
          url,
          logPath,
          async stop() {
            child.kill();
            await child.exited;
            await log.end();
          },
        };
      }
    } catch {
      // The dev server is not listening yet.
    }
    await Bun.sleep(500);
  }
  child.kill();
  throw new Error(`wrangler dev did not become ready at ${url}`);
}
