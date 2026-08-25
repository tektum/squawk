import { describe, expect, it } from "vitest";
import {
  countsLine,
  formatTime,
  relativeAge,
  severityRank,
  shortRef,
  total,
} from "../../client/admin/format";

describe("admin formatting", () => {
  it("ranks severities so the worst findings sort first", () => {
    const severities = ["low", null, "CRITICAL", "high", "moderate"];

    expect([...severities].sort((left, right) => severityRank(left) - severityRank(right))).toEqual(
      ["CRITICAL", "high", "moderate", "low", null],
    );
  });

  it("treats an unrecognised severity as unknown rather than as safe", () => {
    expect(severityRank("catastrophic")).toBe(severityRank(null));
  });

  it("keeps the registry path readable and truncates the digest", () => {
    expect(shortRef(`ghcr.io/tektum/ruby@sha256:${"a".repeat(64)}`)).toBe(
      "ghcr.io/tektum/ruby@aaaaaaaaaaaa",
    );
    expect(shortRef("ghcr.io/tektum/ruby:3.3")).toBe("ghcr.io/tektum/ruby:3.3");
  });

  it("renders absent timestamps as never instead of the epoch", () => {
    expect(formatTime(null)).toBe("never");
    expect(formatTime(0)).toBe("never");
    expect(formatTime(Date.UTC(2026, 7, 25, 12, 30, 5))).toBe("2026-08-25 12:30:05Z");
    expect(relativeAge(null, Date.now())).toBe("never");
  });

  it("ages timestamps through minutes, hours, and days", () => {
    const now = Date.UTC(2026, 7, 25, 12, 0, 0);

    expect(relativeAge(now - 30_000, now)).toBe("just now");
    expect(relativeAge(now - 5 * 60_000, now)).toBe("5m ago");
    expect(relativeAge(now - 3 * 3_600_000, now)).toBe("3h ago");
    expect(relativeAge(now - 5 * 86_400_000, now)).toBe("5d ago");
  });

  it("summarises count maps in stable order", () => {
    expect(countsLine({ pending: 108, complete: 52 })).toBe("complete 52 · pending 108");
    expect(countsLine({})).toBe("none");
    expect(total({ pending: 108, complete: 52 })).toBe(160);
  });
});
