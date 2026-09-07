export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("unsupported canonical JSON value");
    return encoded;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value))
      throw new TypeError("canonical JSON numbers must be safe integers");
    return value.toString();
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object") throw new TypeError("unsupported canonical JSON value");
  const object = value as Record<string, unknown>;
  const entries = Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`);
  return `{${entries.join(",")}}`;
}
