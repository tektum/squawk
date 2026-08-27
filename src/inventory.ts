import { z } from "zod";
import { inventoryStyles } from "./inventory-styles";

const querySchema = z.object({ q: z.string().trim().max(80).catch("") });
const statsSchema = z.object({
  components: z.number(),
  findings: z.number(),
  images: z.number(),
  packages: z.number(),
  platforms: z.number(),
});
const imageSchema = z.object({
  components: z.number(),
  findings: z.number(),
  image_ref: z.string().regex(/@sha256:[a-f0-9]{64}$/),
  platforms: z.string(),
  status: z.string(),
});
const packageSchema = z.object({
  ecosystem: z.string(),
  images: z.number(),
  package_name: z.string(),
  version: z.string(),
});

const latestVex = `latest_vex AS (
  SELECT org_id, package_name, ecosystem, vuln_id, status,
    ROW_NUMBER() OVER (PARTITION BY org_id, package_name, ecosystem, vuln_id ORDER BY created_at DESC, id DESC) AS row_number
  FROM vex_statements
)`;

const immutableImage = `instr(s.logical_image_ref,'@sha256:')>0
  AND length(substr(s.logical_image_ref,instr(s.logical_image_ref,'@sha256:')+8))=64
  AND substr(s.logical_image_ref,instr(s.logical_image_ref,'@sha256:')+8) NOT GLOB '*[^0-9a-f]*'`;

export async function inventoryResponse(request: Request, database: D1Database): Promise<Response> {
  const { q } = querySchema.parse(Object.fromEntries(new URL(request.url).searchParams));
  const like = `%${q}%`;
  const [stats, images, packages] = await Promise.all([
    database
      .prepare(`WITH ${latestVex} SELECT
      (SELECT COUNT(DISTINCT s.logical_image_ref) FROM sboms s WHERE s.retired_at IS NULL AND ${immutableImage}) AS images,
      (SELECT COUNT(DISTINCT s.platform) FROM sboms s WHERE s.retired_at IS NULL AND ${immutableImage}) AS platforms,
      (SELECT COUNT(*) FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE s.retired_at IS NULL AND ${immutableImage}) AS components,
      (SELECT COUNT(DISTINCT c.package_name || char(0) || c.ecosystem || char(0) || c.version) FROM components c JOIN sboms s ON s.id=c.sbom_id WHERE s.retired_at IS NULL AND c.matchable=1 AND ${immutableImage}) AS packages,
      (SELECT COUNT(*) FROM findings f
        JOIN components c ON c.id=f.component_id JOIN sboms s ON s.id=c.sbom_id
        LEFT JOIN latest_vex x ON x.row_number=1 AND x.org_id=f.org_id AND x.package_name=c.package_name AND x.ecosystem=c.ecosystem AND x.vuln_id=f.vuln_id
        WHERE s.retired_at IS NULL AND ${immutableImage} AND f.dispatched_at IS NOT NULL AND COALESCE(x.status,'') NOT IN ('not_affected','fixed')) AS findings`)
      .first(),
    database
      .prepare(`WITH ${latestVex}, visible AS (
      SELECT f.component_id,f.vuln_id FROM findings f JOIN components c ON c.id=f.component_id
      LEFT JOIN latest_vex x ON x.row_number=1 AND x.org_id=f.org_id AND x.package_name=c.package_name AND x.ecosystem=c.ecosystem AND x.vuln_id=f.vuln_id
      WHERE f.dispatched_at IS NOT NULL AND COALESCE(x.status,'') NOT IN ('not_affected','fixed')
      ) SELECT s.logical_image_ref AS image_ref,
      GROUP_CONCAT(DISTINCT s.platform) AS platforms,
      COUNT(DISTINCT c.id) AS components,
      COUNT(DISTINCT f.vuln_id || char(0) || f.component_id) AS findings,
      CASE WHEN SUM(s.backfill_status!='complete')=0 THEN 'indexed' ELSE 'processing' END AS status
      FROM sboms s LEFT JOIN components c ON c.sbom_id=s.id
      LEFT JOIN visible f ON f.component_id=c.id
      WHERE s.retired_at IS NULL AND s.logical_image_ref LIKE ?
        AND ${immutableImage}
      GROUP BY s.logical_image_ref ORDER BY MAX(s.created_at) DESC LIMIT 50`)
      .bind(like)
      .all(),
    database
      .prepare(`SELECT c.package_name,c.ecosystem,c.version,
      COUNT(DISTINCT s.logical_image_ref) AS images
      FROM components c JOIN sboms s ON s.id=c.sbom_id
      WHERE s.retired_at IS NULL AND c.matchable=1 AND ${immutableImage}
        AND (c.package_name LIKE ? OR c.ecosystem LIKE ? OR c.version LIKE ?)
      GROUP BY c.package_name,c.ecosystem,c.version
      ORDER BY c.ecosystem,c.package_name,c.version LIMIT 100`)
      .bind(like, like, like)
      .all(),
  ]);
  const model = {
    stats: statsSchema.parse(stats),
    images: images.results.map((row) => imageSchema.parse(row)),
    packages: packages.results.map((row) => packageSchema.parse(row)),
    q,
  };
  return new Response(renderInventory(model), {
    headers: {
      "content-security-policy":
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "content-type": "text/html; charset=utf-8",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character] ?? character,
  );
}

/* Digest-bound refs read as registry path + digest: the path carries the ink, the
   digest recedes. Mirrors the Verity ImageRef chip. */
function renderImageRef(reference: string): string {
  const digestAt = reference.indexOf("@");
  if (digestAt < 0) {
    return `<span class="ref-path">${escapeHtml(reference)}</span>`;
  }
  return `<span class="ref-path">${escapeHtml(reference.slice(0, digestAt + 1))}</span><span class="ref-digest">${escapeHtml(reference.slice(digestAt + 1))}</span>`;
}

function findingsTone(count: number): string {
  return count === 0 ? "clean" : "risk";
}

function renderInventory(model: {
  readonly images: readonly z.infer<typeof imageSchema>[];
  readonly packages: readonly z.infer<typeof packageSchema>[];
  readonly q: string;
  readonly stats: z.infer<typeof statsSchema>;
}): string {
  const imageRows = model.images
    .map(
      (image) => `<article class="card">
    <div class="card-hd"><span class="status ${image.status}"><span class="dot"></span>${image.status}</span></div>
    <h3 class="ref">${renderImageRef(image.image_ref)}</h3>
    <dl><div><dt>Platforms</dt><dd>${escapeHtml(image.platforms.split(",").sort().join(" · "))}</dd></div>
    <div><dt>Components</dt><dd>${image.components}</dd></div>
    <div><dt>Findings</dt><dd class="${findingsTone(image.findings)}">${image.findings}</dd></div></dl>
  </article>`,
    )
    .join("");
  const packageRows = model.packages
    .map(
      (item) => `<tr><td><span class="eco">${escapeHtml(item.ecosystem)}</span></td>
    <td>${escapeHtml(item.package_name)}</td><td><code>${escapeHtml(item.version)}</code></td><td class="num">${item.images}</td></tr>`,
    )
    .join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Squawk inventory</title><style>${inventoryStyles}</style></head><body class="vr"><div class="topbar"><span class="wordmark">SQUAWK</span><span class="topbar-meta">public ledger</span></div><main>
  <header><p class="eyebrow">PUBLIC IMAGE LEDGER</p><h1>What’s inside the fleet.</h1>
  <p class="intro">Digest-bound software inventory from published container images. Updated by GitHub attestations and checked against OSV.</p></header>
  <section class="stats"><div><strong>${model.stats.images}</strong><span>images</span></div><div><strong>${model.stats.platforms}</strong><span>platforms</span></div>
  <div><strong>${model.stats.components}</strong><span>components</span></div><div><strong>${model.stats.packages}</strong><span>package versions</span></div>
  <div class="risk ${findingsTone(model.stats.findings)}"><strong>${model.stats.findings}</strong><span>findings</span></div></section>
  <form role="search"><label for="q">Filter the ledger</label><div><input id="q" name="q" value="${escapeHtml(model.q)}" maxlength="80" placeholder="image, package, ecosystem, version"><button>Search</button></div></form>
  <section><div class="section-title"><h2>Images</h2><span>${model.images.length} shown</span></div><div class="images">${imageRows || empty("No images match this filter.")}</div></section>
  <section><div class="section-title"><h2>Packages</h2><span>${model.packages.length} shown</span></div><div class="table-wrap"><table><thead><tr><th>Ecosystem</th><th>Package</th><th>Version</th><th class="num">Images</th></tr></thead>
  <tbody>${packageRows || `<tr><td colspan="4">${empty("No packages match this filter.")}</td></tr>`}</tbody></table></div></section>
  <footer>Squawk · immutable image inventory · <a href="/activity">activity history</a> · <a href="/health">system health</a></footer></main></body></html>`;
}

function empty(message: string): string {
  return `<p class="empty">${message}</p>`;
}
