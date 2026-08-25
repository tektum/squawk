export class SubrequestBudget {
  #remaining: number;

  constructor(limit: number) {
    this.#remaining = limit;
  }

  take(): void {
    if (this.#remaining === 0) throw new Error("subrequest budget exhausted");
    this.#remaining -= 1;
  }

  get remaining(): number {
    return this.#remaining;
  }
}

/**
 * Scheduled Workers are killed at fifteen minutes of wall time. Per-request
 * timeouts do not bound a run: forty-five sequential requests that each take ten
 * seconds exceed the limit on their own, so every stage checks this deadline and
 * leaves the rest of its work for the next invocation.
 */
export class RunDeadline {
  readonly #expiresAt: number;

  constructor(startedAt: number, milliseconds: number) {
    this.#expiresAt = startedAt + milliseconds;
  }

  get expired(): boolean {
    return Date.now() >= this.#expiresAt;
  }
}
