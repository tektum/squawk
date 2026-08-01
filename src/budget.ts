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
