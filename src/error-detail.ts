type SafeIssue = {
  readonly code?: string;
  readonly path?: string;
  readonly message?: string;
};

/**
 * Validation issues carry an optional `input` field holding the offending
 * external value. Persisting or logging it would leak package names from
 * third-party SBOMs, so only the structural fields survive.
 */
export function safeIssues(issues: readonly unknown[]): readonly SafeIssue[] {
  return issues.map((issue) => {
    if (!issue || typeof issue !== "object") return {};
    const code = "code" in issue && typeof issue.code === "string" ? issue.code : undefined;
    const message =
      "message" in issue && typeof issue.message === "string" ? issue.message : undefined;
    const path =
      "path" in issue && Array.isArray(issue.path)
        ? issue.path.map((segment) => String(segment)).join(".")
        : undefined;
    return {
      ...(code === undefined ? {} : { code }),
      ...(path === undefined ? {} : { path }),
      ...(message === undefined ? {} : { message }),
    };
  });
}

/** Renders any thrown value as a log-safe, storage-safe string. */
export function describeError(error: unknown): string {
  if (!(error instanceof Error)) return `unknown error (${typeof error})`;
  const issues = "issues" in error ? error.issues : undefined;
  return Array.isArray(issues)
    ? `${error.name}: ${JSON.stringify(safeIssues(issues)).slice(0, 1_000)}`
    : `${error.name}: ${error.message}`;
}
