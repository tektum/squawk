import { useState } from "react";
import { send, useResource } from "../api";
import { formatTime, shortRef } from "../format";
import type { Image, ImageDetail } from "../types";
import { Field, Loaded, Section, Table, Tag } from "./parts";

function statusTone(image: Image): string {
  if (image.retired_at) return "muted";
  if (image.backfill_status === "failed") return "risk";
  return image.backfill_status === "complete" ? "clean" : "pending";
}

export function Images({ orgId, canManage }: { orgId: string; canManage: boolean }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const resource = useResource<{ images: readonly Image[] }>(
    `/v1/orgs/${encodeURIComponent(orgId)}/images?limit=200&include_retired=true`,
    reloadKey,
  );
  if (selected) return <Detail orgId={orgId} sbomId={selected} onBack={() => setSelected(null)} />;
  return (
    <Loaded resource={resource}>
      {(data) => (
        <Section title="Images">
          <Table
            headers={[
              "Image",
              "Platform",
              "Status",
              "Components",
              "Findings",
              "Attempted",
              "Error",
              "",
            ]}
            rows={data.images.map((image) => ({
              key: image.id,
              cells: [
                <button
                  key="open"
                  type="button"
                  className="link"
                  title={image.image_ref}
                  onClick={() => setSelected(image.id)}
                >
                  {shortRef(image.logical_image_ref)}
                </button>,
                image.platform,
                <Tag
                  key="status"
                  text={image.retired_at ? "retired" : image.backfill_status}
                  tone={statusTone(image)}
                />,
                String(image.components),
                String(image.findings),
                formatTime(image.backfill_attempted_at),
                image.backfill_error ?? "-",
                canManage && !image.retired_at ? (
                  <Retire
                    key="retire"
                    sbomId={image.id}
                    onDone={() => setReloadKey((key) => key + 1)}
                  />
                ) : (
                  "-"
                ),
              ],
            }))}
          />
        </Section>
      )}
    </Loaded>
  );
}

function Retire({ sbomId, onDone }: { sbomId: string; onDone: () => void }) {
  const [label, setLabel] = useState("Retire");
  return (
    <button
      type="button"
      onClick={async () => {
        setLabel("Retiring…");
        try {
          await send("DELETE", `/v1/sboms/${encodeURIComponent(sbomId)}`);
          onDone();
        } catch (error) {
          setLabel(error instanceof Error ? error.message : "Failed");
        }
      }}
    >
      {label}
    </button>
  );
}

function Detail({ orgId, sbomId, onBack }: { orgId: string; sbomId: string; onBack: () => void }) {
  const resource = useResource<ImageDetail>(
    `/v1/orgs/${encodeURIComponent(orgId)}/images/${encodeURIComponent(sbomId)}`,
  );
  return (
    <>
      <div className="actions">
        <button type="button" className="link" onClick={onBack}>
          ← all images
        </button>
      </div>
      <Loaded resource={resource}>
        {(detail) => (
          <>
            <Section title="Image">
              <dl className="grid">
                <Field label="Reference" value={detail.image.image_ref} />
                <Field label="Logical" value={detail.image.logical_image_ref} />
                <Field label="Platform" value={detail.image.platform} />
                <Field label="Backfill" value={detail.image.backfill_status} />
                <Field label="Backfill error" value={detail.image.backfill_error ?? "-"} />
                <Field label="Ingested" value={formatTime(detail.image.created_at)} />
                <Field label="Retired" value={formatTime(detail.image.retired_at)} />
                <Field label="Installation" value={detail.image.installation_id ?? "-"} />
                <Field label="Repository" value={detail.image.repository_id ?? "-"} />
              </dl>
            </Section>
            <Section title="Findings">
              <Table
                headers={["Advisory", "Severity", "Package", "Version", "Detected", "Dispatched"]}
                rows={detail.findings.map((finding) => ({
                  key: `${finding.vuln_id}-${finding.package_name}`,
                  cells: [
                    finding.vuln_id,
                    finding.severity ?? "unknown",
                    `${finding.ecosystem}/${finding.package_name}`,
                    finding.version,
                    formatTime(finding.detected_at),
                    formatTime(finding.dispatched_at),
                  ],
                }))}
              />
            </Section>
            <Section title="Webhook receipts">
              <Table
                headers={["Delivery", "Status", "Received", "Completed"]}
                rows={detail.deliveries.map((delivery) => ({
                  key: delivery.delivery_id,
                  cells: [
                    delivery.delivery_id,
                    delivery.status,
                    formatTime(delivery.created_at),
                    formatTime(delivery.completed_at),
                  ],
                }))}
              />
            </Section>
            <Section title={`Components (${detail.components.length})`}>
              <Table
                headers={["Package", "Ecosystem", "Version", "Matchable"]}
                rows={detail.components.map((component) => ({
                  key: component.purl,
                  cells: [
                    component.package_name,
                    component.ecosystem,
                    component.version,
                    component.matchable ? "yes" : "no",
                  ],
                }))}
              />
            </Section>
          </>
        )}
      </Loaded>
    </>
  );
}
