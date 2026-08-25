import { useState } from "react";
import { send, useResource } from "../api";
import { countsLine, relativeAge, total } from "../format";
import { overviewSchema } from "../schemas";
import { Field, Loaded, Section, Table } from "./parts";

export function Overview({ orgId, canRun }: { orgId: string; canRun: boolean }) {
  const [reloadKey, setReloadKey] = useState(0);
  const resource = useResource(
    `/v1/orgs/${encodeURIComponent(orgId)}/overview`,
    overviewSchema,
    reloadKey,
  );
  return (
    <>
      {canRun ? <RunScheduled onDone={() => setReloadKey((key) => key + 1)} /> : null}
      <Loaded resource={resource}>
        {(data) => {
          const totals = data.totals;
          const now = Date.now();
          return (
            <>
              <Section title="Inventory">
                <dl className="grid">
                  <Field label="Images" value={String(totals?.images ?? 0)} />
                  <Field label="SBOMs" value={String(total(data.sboms))} />
                  <Field
                    label="Components"
                    value={`${totals?.components ?? 0} (${totals?.matchable_components ?? 0} matchable)`}
                  />
                  <Field label="Findings" value={String(totals?.findings ?? 0)} />
                  <Field label="Undispatched" value={String(totals?.undispatched_findings ?? 0)} />
                  <Field label="Matching errors" value={String(totals?.matching_errors ?? 0)} />
                  <Field
                    label="Advisory corpus"
                    value={`${totals?.vulnerabilities ?? 0} across ${totals?.ecosystems ?? 0} ecosystems`}
                  />
                  <Field
                    label="Ecosystems cached"
                    value={relativeAge(totals?.ecosystems_cached_at, now)}
                  />
                  <Field label="Latest SBOM" value={relativeAge(totals?.latest_sbom_at, now)} />
                  <Field
                    label="Latest delivery"
                    value={relativeAge(totals?.latest_delivery_at, now)}
                  />
                </dl>
              </Section>
              <Section title="Pipeline">
                <dl className="grid">
                  <Field label="Backfill" value={countsLine(data.sboms)} />
                  <Field label="Severity" value={countsLine(data.findings)} />
                  <Field label="Ingestion jobs" value={countsLine(data.ingestion_jobs)} />
                  <Field label="Advisory jobs" value={countsLine(data.advisory_jobs)} />
                  <Field label="Dispatch" value={countsLine(data.dispatch_deliveries)} />
                </dl>
              </Section>
              <Section title="Sync cursors">
                <Table
                  headers={["Ecosystem", "Last synced", "Continuation"]}
                  rows={data.sync_cursors.map((cursor) => ({
                    key: cursor.ecosystem,
                    cells: [cursor.ecosystem, cursor.last_synced_at, cursor.continuation_id ?? "-"],
                  }))}
                />
              </Section>
            </>
          );
        }}
      </Loaded>
    </>
  );
}

function RunScheduled({ onDone }: { onDone: () => void }) {
  const [state, setState] = useState("");
  return (
    <div className="actions">
      <button
        type="button"
        disabled={state === "Running…"}
        onClick={async () => {
          setState("Running…");
          try {
            await send("POST", "/v1/operations/scheduled");
            setState("Completed");
            onDone();
          } catch (error) {
            setState(error instanceof Error ? error.message : "Failed");
          }
        }}
      >
        Run scheduled work now
      </button>
      <span className="status">{state}</span>
    </div>
  );
}
