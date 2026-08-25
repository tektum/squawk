import type { ReactNode } from "react";
import type { Resource } from "../api";

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

export function Tag({ text, tone }: { text: string; tone: string }) {
  return <span className={`tag ${tone}`}>{text}</span>;
}

/* Rows render as React children, so database strings are escaped by React and a hostile
   SBOM cannot inject markup into an operator's session. */
export function Table({
  headers,
  rows,
}: {
  headers: readonly string[];
  rows: readonly { readonly key: string; readonly cells: readonly ReactNode[] }[];
}) {
  if (rows.length === 0) return <p className="empty">Nothing here yet.</p>;
  return (
    <table>
      <thead>
        <tr>
          {headers.map((header) => (
            <th key={header}>{header}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            {row.cells.map((cell, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: cells are positional columns
              <td key={index}>{cell}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Loaded<T>({
  resource,
  children,
}: {
  resource: Resource<T>;
  children: (data: T) => ReactNode;
}) {
  if (resource.error) return <p className="status risk">{resource.error}</p>;
  if (!resource.data) return <p className="status">Loading…</p>;
  return <>{children(resource.data)}</>;
}

/* A silently truncated list is misleading in a security console. The endpoints report
   no total, so this claims only what a full page proves: the limit was reached, and
   further rows may exist beyond it. */
export function Truncated({ shown, limit }: { shown: number; limit: number }) {
  if (shown < limit) return null;
  return <p className="status risk">Showing the first {limit} rows; more may exist.</p>;
}
