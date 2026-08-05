import { describe, expect, it } from "vitest";
import worker from "../src/index";

describe("Worker health", () => {
  it("returns 200 without storage or network access", async () => {
    const response = await worker.fetch(
      new Request("https://squawk.test/health"),
      { BUILD_SHA: "test-sha" },
      {} as ExecutionContext,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("x-squawk-version")).toBe("test-sha");
    await expect(response.json()).resolves.toEqual({ status: "ok" });
  });
});
