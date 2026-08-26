import { useResource } from "../api";
import { formatTime } from "../format";
import { jobsSchema, sourcesSchema } from "../schemas";
import { Loaded, Section, Table, Truncated } from "./parts";

const jobLimit = 100;

export function JobsView({ orgId }: { orgId: string }) {
  const resource = useResource(
    `/v1/orgs/${encodeURIComponent(orgId)}/jobs?limit=${jobLimit}`,
    jobsSchema,
  );
  return (
    <Loaded resource={resource}>
      {(data) => (
        <>
          <Section title="Image ingestion">
            <Table
              headers={["Image", "Status", "Descriptor", "SPDX", "Attempted", "Error"]}
              rows={data.ingestion.map((job) => ({
                key: job.subject_digest,
                cells: [
                  job.logical_image_ref,
                  job.status,
                  String(job.next_descriptor),
                  job.saw_spdx ? "yes" : "no",
                  formatTime(job.attempted_at),
                  job.error ?? "-",
                ],
              }))}
            />
            <Truncated shown={data.ingestion.length} limit={jobLimit} />
          </Section>
          <Section title="Advisory jobs">
            <Table
              headers={["Advisory", "Ecosystem", "Status", "Attempted", "Error"]}
              rows={data.advisories.map((job) => ({
                key: job.job_id,
                cells: [
                  job.advisory_id,
                  job.ecosystem,
                  job.status,
                  formatTime(job.attempted_at),
                  job.error ?? "-",
                ],
              }))}
            />
            <Truncated shown={data.advisories.length} limit={jobLimit} />
          </Section>
          <Section title="Dispatch deliveries">
            <Table
              headers={["Image", "Package", "Advisory", "Status", "Attempted", "Error"]}
              rows={data.dispatch.map((delivery) => ({
                key: delivery.delivery_id,
                cells: [
                  delivery.logical_image_ref,
                  delivery.package_name,
                  delivery.vuln_id,
                  delivery.status,
                  formatTime(delivery.attempted_at),
                  delivery.error ?? "-",
                ],
              }))}
            />
            <Truncated shown={data.dispatch.length} limit={jobLimit} />
          </Section>
          <Section title="Matching errors">
            <Table
              headers={["Advisory", "Package", "Version", "Reason", "Recorded"]}
              rows={data.matching_errors.map((row) => ({
                key: `${row.vuln_id}-${row.package_name}-${row.created_at}`,
                cells: [
                  row.vuln_id,
                  `${row.ecosystem}/${row.package_name}`,
                  row.version,
                  row.reason,
                  formatTime(row.created_at),
                ],
              }))}
            />
            <Truncated shown={data.matching_errors.length} limit={jobLimit} />
          </Section>
        </>
      )}
    </Loaded>
  );
}

export function Sources({ orgId }: { orgId: string }) {
  const resource = useResource(`/v1/orgs/${encodeURIComponent(orgId)}/sources`, sourcesSchema);
  return (
    <Loaded resource={resource}>
      {(data) => (
        <Section title="GitHub sources">
          <Table
            headers={[
              "Installation",
              "Repository",
              "Dispatch workflow",
              "Ref",
              "SBOMs",
              "Pending jobs",
            ]}
            rows={data.sources.map((source) => ({
              key: `${source.installation_id}-${source.repository_id}`,
              cells: [
                source.installation_id,
                source.repository_id,
                source.dispatch_workflow ?? "not configured",
                source.dispatch_ref ?? "-",
                String(source.sboms),
                String(source.pending_jobs),
              ],
            }))}
          />
        </Section>
      )}
    </Loaded>
  );
}
