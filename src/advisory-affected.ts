export type AdvisoryAffected = {
  package: { ecosystem: string; name: string };
  ranges: {
    type: string;
    events: {
      introduced?: string | undefined;
      fixed?: string | undefined;
      last_affected?: string | undefined;
      limit?: string | undefined;
    }[];
  }[];
  versions: string[];
};

export async function effectiveAffectedEntries(
  database: D1Database,
  entries: readonly AdvisoryAffected[],
): Promise<readonly AdvisoryAffected[]> {
  const debianTargets = new Map<string, readonly string[]>();
  const grouped = new Map<string, AdvisoryAffected>();
  for (const entry of entries) {
    let ecosystems: readonly string[] = [entry.package.ecosystem];
    if (entry.package.ecosystem === "Debian") {
      let targets = debianTargets.get(entry.package.name);
      if (!targets) {
        targets = (
          await database
            .prepare(
              `SELECT DISTINCT c.ecosystem FROM components c JOIN sboms s ON s.id=c.sbom_id
               WHERE s.retired_at IS NULL AND c.matchable=1 AND c.package_name=?
                 AND (c.ecosystem='Debian' OR c.ecosystem LIKE 'Debian:%')
               ORDER BY c.ecosystem`,
            )
            .bind(entry.package.name)
            .all<{ readonly ecosystem: string }>()
        ).results.map(({ ecosystem }) => ecosystem);
        debianTargets.set(entry.package.name, targets);
      }
      ecosystems = targets;
    }
    for (const ecosystem of ecosystems) {
      const key = `${ecosystem}\u0000${entry.package.name}`;
      const prior = grouped.get(key);
      grouped.set(key, {
        package: { ecosystem, name: entry.package.name },
        ranges: [...(prior?.ranges ?? []), ...entry.ranges],
        versions: [...new Set([...(prior?.versions ?? []), ...entry.versions])],
      });
    }
  }
  return [...grouped.values()];
}
