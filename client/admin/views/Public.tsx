import { Descope } from "@descope/react-sdk/flows";
import { useState } from "react";
import { useResource } from "../api";
import { countsLine, relativeAge, severityRank, shortRef } from "../format";
import {
  type PublicImage,
  publicImageDetailSchema,
  publicImagesSchema,
  publicOverviewSchema,
} from "../schemas";
import { Field, Loaded, Section, Table, Tag, Truncated } from "./parts";

const imageLimit = 200;

/* What an anonymous visitor sees at `/`: the disclosed read surface of the panel with
   no actions. Findings appear here only once the pipeline has delivered them and VEX
   has not adjudicated them harmless. The server enforces that; this view renders
   whatever `/public` returns. Signing in swaps this for the operator console. */
export function Public() {
  const [tab, setTab] = useState<"overview" | "images">("overview");
  const [signingIn, setSigningIn] = useState(false);
  if (signingIn)
    return (
      <div className="login">
        <h1>Squawk admin</h1>
        <Descope flowId="sign-up-or-in" theme="dark" />
      </div>
    );
  return (
    <>
      <header>
        <span className="wordmark">SQUAWK</span>
        <span className="status">public · read-only</span>
        <button type="button" className="link" onClick={() => setSigningIn(true)}>
          Sign in
        </button>
      </header>
      <nav className="tabs">
        {(["overview", "images"] as const).map((name) => (
          <button
            key={name}
            type="button"
            className={name === tab ? "current" : ""}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </nav>
      <main>{tab === "overview" ? <PublicOverview /> : <PublicImages />}</main>
    </>
  );
}

function PublicOverview() {
  const resource = useResource("/public/overview", publicOverviewSchema);
  return (
    <Loaded resource={resource}>
      {(data) => {
        const now = Date.now();
        return (
          <>
            <Section title="Inventory">
              <dl className="grid">
                <Field label="Images" value={String(data.totals.images)} />
                <Field
                  label="Components"
                  value={`${data.totals.components} (${data.totals.matchable_components} matchable)`}
                />
                <Field label="Disclosed findings" value={String(data.totals.findings)} />
                <Field
                  label="Advisory corpus"
                  value={`${data.totals.vulnerabilities} across ${data.totals.ecosystems} ecosystems`}
                />
                <Field label="Latest SBOM" value={relativeAge(data.totals.latest_sbom_at, now)} />
              </dl>
            </Section>
            <Section title="Disclosed severity">
              <dl className="grid">
                <Field label="Severity" value={countsLine(data.severity)} />
              </dl>
            </Section>
          </>
        );
      }}
    </Loaded>
  );
}

function tone(image: PublicImage): string {
  if (image.status !== "indexed") return "pending";
  return image.findings === 0 ? "clean" : "risk";
}

function PublicImages() {
  const [selected, setSelected] = useState<string | null>(null);
  const resource = useResource(`/public/images?limit=${imageLimit}`, publicImagesSchema);
  if (selected) return <Detail reference={selected} onBack={() => setSelected(null)} />;
  return (
    <Loaded resource={resource}>
      {(data) => (
        <Section title="Images">
          <Table
            headers={["Image", "Platforms", "Components", "Disclosed findings", "Status"]}
            rows={data.images.map((image) => ({
              key: image.image_ref,
              cells: [
                <button
                  key="ref"
                  type="button"
                  className="link"
                  title={image.image_ref}
                  onClick={() => setSelected(image.image_ref)}
                >
                  {shortRef(image.image_ref)}
                </button>,
                image.platforms ?? "-",
                String(image.components),
                String(image.findings),
                <Tag key="status" text={image.status} tone={tone(image)} />,
              ],
            }))}
          />
          <Truncated shown={data.images.length} limit={imageLimit} />
        </Section>
      )}
    </Loaded>
  );
}

function Detail({ reference, onBack }: { reference: string; onBack: () => void }) {
  const resource = useResource(
    `/public/image?ref=${encodeURIComponent(reference)}`,
    publicImageDetailSchema,
  );
  return (
    <Loaded resource={resource}>
      {(data) => (
        <>
          <button type="button" className="link" onClick={onBack}>
            ← All images
          </button>
          <Section title={shortRef(reference)}>
            <Table
              headers={["Digest image", "Platform", "Status", "Indexed"]}
              rows={data.platforms.map((platform) => ({
                key: platform.platform,
                cells: [
                  shortRef(platform.image_ref),
                  platform.platform,
                  <Tag
                    key="status"
                    text={platform.status}
                    tone={platform.status === "indexed" ? "clean" : "pending"}
                  />,
                  relativeAge(platform.created_at, Date.now()),
                ],
              }))}
            />
          </Section>
          <Section title={`Components (${data.components.length})`}>
            <Table
              headers={["Package", "Ecosystem", "Version"]}
              rows={data.components.map((component) => ({
                key: `${component.ecosystem}:${component.package_name}:${component.version}`,
                cells: [component.package_name, component.ecosystem, component.version],
              }))}
            />
          </Section>
          <Section title={`Disclosed findings (${data.findings.length})`}>
            <Table
              headers={["Vulnerability", "Severity", "Package", "Version", "Detected"]}
              rows={[...data.findings]
                .sort(
                  (left, right) =>
                    severityRank(left.severity) - severityRank(right.severity) ||
                    right.detected_at - left.detected_at,
                )
                .map((finding) => ({
                  key: `${finding.vuln_id}:${finding.package_name}:${finding.ecosystem}`,
                  cells: [
                    finding.vuln_id,
                    <Tag
                      key="severity"
                      text={finding.severity ?? "unknown"}
                      tone={
                        finding.severity === "critical" || finding.severity === "high"
                          ? "risk"
                          : "muted"
                      }
                    />,
                    `${finding.package_name} (${finding.ecosystem})`,
                    finding.version,
                    relativeAge(finding.detected_at, Date.now()),
                  ],
                }))}
            />
          </Section>
        </>
      )}
    </Loaded>
  );
}
