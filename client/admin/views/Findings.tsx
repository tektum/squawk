import { useState } from "react";
import { send, useResource } from "../api";
import { formatTime, severityRank, shortRef } from "../format";
import { type Finding, findingsSchema } from "../schemas";
import { Loaded, Section, Table, Tag, Truncated } from "./parts";

const findingLimit = 500;

const vexStatuses = ["not_affected", "affected", "fixed", "under_investigation"] as const;

export function Findings({ orgId, canAssess }: { orgId: string; canAssess: boolean }) {
  const [reloadKey, setReloadKey] = useState(0);
  const resource = useResource(
    `/v1/orgs/${encodeURIComponent(orgId)}/findings?include_suppressed=true&limit=${findingLimit}`,
    findingsSchema,
    reloadKey,
  );
  return (
    <Loaded resource={resource}>
      {(data) => {
        const findings = [...data.findings].sort(
          (left, right) => severityRank(left.severity) - severityRank(right.severity),
        );
        return (
          <Section title={`Findings (${findings.length})`}>
            <Table
              headers={[
                "Severity",
                "Advisory",
                "Package",
                "Version",
                "Image",
                "VEX",
                "Detected",
                "Dispatch",
                "Assess",
              ]}
              rows={findings.map((finding) => ({
                key: `${finding.sbom_id}-${finding.vuln_id}-${finding.package_name}`,
                cells: [
                  <Tag
                    key="severity"
                    text={finding.severity ?? "unknown"}
                    tone={severityRank(finding.severity) <= 1 ? "risk" : "pending"}
                  />,
                  finding.vuln_id,
                  `${finding.ecosystem}/${finding.package_name}`,
                  finding.version,
                  <span key="image" title={finding.image_ref}>
                    {shortRef(finding.logical_image_ref)}
                  </span>,
                  finding.vex_status ?? "-",
                  formatTime(finding.detected_at),
                  finding.dispatched_at ? "dispatched" : "pending",
                  canAssess ? (
                    <Vex
                      key="assess"
                      orgId={orgId}
                      finding={finding}
                      onDone={() => setReloadKey((key) => key + 1)}
                    />
                  ) : (
                    "-"
                  ),
                ],
              }))}
            />
            <Truncated shown={findings.length} limit={findingLimit} />
          </Section>
        );
      }}
    </Loaded>
  );
}

/* VEX is the one write an operator makes per finding, so it stays inline on the row
   rather than behind a dialog: pick a status, optionally justify, save. */
function Vex({ orgId, finding, onDone }: { orgId: string; finding: Finding; onDone: () => void }) {
  const [status, setStatus] = useState("");
  const [justification, setJustification] = useState("");
  const [label, setLabel] = useState("Save");
  return (
    <div className="vex">
      <select value={status} onChange={(event) => setStatus(event.target.value)}>
        <option value="">…</option>
        {vexStatuses.map((value) => (
          <option key={value} value={value}>
            {value}
          </option>
        ))}
      </select>
      <input
        type="text"
        placeholder="justification"
        maxLength={400}
        value={justification}
        onChange={(event) => setJustification(event.target.value)}
      />
      <button
        type="button"
        disabled={!status}
        onClick={async () => {
          setLabel("Saving…");
          try {
            await send("POST", `/v1/orgs/${encodeURIComponent(orgId)}/vex`, {
              package_name: finding.package_name,
              ecosystem: finding.ecosystem,
              vuln_id: finding.vuln_id,
              status,
              ...(justification ? { justification } : {}),
            });
            onDone();
          } catch (error) {
            setLabel(error instanceof Error ? error.message : "Failed");
          }
        }}
      >
        {label}
      </button>
    </div>
  );
}
