import type { Principal } from "./domain";

export type WorkerBindings = {
  readonly BUILD_SHA?: string;
  readonly DB: D1Database;
  readonly DISPATCH_ENABLED: string;
  readonly DESCOPE_BASE_URL?: string;
  readonly DESCOPE_PROJECT_ID: string;
  readonly GH_APP_ID: string;
  readonly GH_APP_INSTALLATION_ID: string;
  readonly GH_APP_PRIVATE_KEY: string;
  readonly GH_WEBHOOK_SECRET: string;
  readonly GHCR_URL?: string;
  readonly GITHUB_API_URL?: string;
  readonly OSV_API_URL: string;
  readonly OSV_ADVISORY_JOBS: Queue;
  readonly OSV_BASE_URL: string;
  readonly FINDING_DISPATCH: Queue;
  readonly EXECUTION_CONTEXT: ExecutionContext;
};

export type WorkerEnv = {
  Bindings: WorkerBindings;
  Variables: { readonly principal: Principal };
};
