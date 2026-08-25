/* Pure presentation helpers, kept apart from the DOM so they can be unit tested. */

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  moderate: 2,
  medium: 2,
  low: 3,
  unknown: 4,
};

export function severityRank(severity: string | null | undefined): number {
  return severityOrder[(severity ?? "unknown").toLowerCase()] ?? 4;
}

export function formatTime(timestamp: number | null | undefined): string {
  if (!timestamp) return "never";
  return new Date(timestamp).toISOString().replace("T", " ").replace(".000Z", "Z");
}

export function relativeAge(timestamp: number | null | undefined, now: number): string {
  if (!timestamp) return "never";
  const minutes = Math.floor((now - timestamp) / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/* Digest-bound refs are long and mostly noise: keep the registry path readable and
   truncate the digest, which stays copyable from the row title. */
export function shortRef(reference: string): string {
  const [path, digest] = reference.split("@sha256:");
  if (!digest) return reference;
  return `${path}@${digest.slice(0, 12)}`;
}

export function countsLine(counts: Readonly<Record<string, number>>): string {
  const entries = Object.entries(counts).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) return "none";
  return entries.map(([key, total]) => `${key} ${total}`).join(" · ");
}

export function total(counts: Readonly<Record<string, number>>): number {
  return Object.values(counts).reduce((sum, value) => sum + value, 0);
}
