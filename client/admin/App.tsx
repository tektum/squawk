import { Descope, useDescope, useSession } from "@descope/react-sdk/flows";
import { useCallback, useState } from "react";
import { useResource } from "./api";
import type { Me } from "./types";
import { Findings } from "./views/Findings";
import { Images } from "./views/Images";
import { Overview } from "./views/Overview";
import { JobsView, Sources } from "./views/Pipeline";
import { Loaded } from "./views/parts";

const tabs = ["overview", "images", "findings", "jobs", "sources"] as const;
type Tab = (typeof tabs)[number];

export function App() {
  const { isAuthenticated, isSessionLoading } = useSession();
  if (isSessionLoading) return <p className="status">Loading…</p>;
  if (!isAuthenticated)
    return (
      <div className="login">
        <h1>Squawk admin</h1>
        <Descope flowId="sign-up-or-in" theme="dark" />
      </div>
    );
  return <Panel />;
}

/* `/v1/me` rather than the JWT's own claims: the Worker decides which capabilities it
   honours, so the panel shows exactly the controls the API will accept. */
function Panel() {
  const resource = useResource<Me>("/v1/me");
  return <Loaded resource={resource}>{(me) => <Console me={me} />}</Loaded>;
}

function Console({ me }: { me: Me }) {
  const [tab, setTab] = useState<Tab>("overview");
  const { logout } = useDescope();
  const handleLogout = useCallback(() => {
    void logout();
  }, [logout]);
  const can = (capability: string) => me.capabilities.includes(capability);
  return (
    <>
      <header>
        <span className="wordmark">SQUAWK</span>
        <span className="status">
          {me.user_id ?? "unknown"} · {me.tenant_id}
        </span>
        <span className="status">{me.capabilities.join(" · ") || "no capabilities"}</span>
        <button type="button" className="link" onClick={handleLogout}>
          Sign out
        </button>
      </header>
      <nav className="tabs">
        {tabs.map((name) => (
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
      <main>
        {tab === "overview" ? (
          <Overview orgId={me.tenant_id} canRun={can("operations.run")} />
        ) : null}
        {tab === "images" ? <Images orgId={me.tenant_id} canManage={can("sbom.manage")} /> : null}
        {tab === "findings" ? <Findings orgId={me.tenant_id} canAssess={can("vex.write")} /> : null}
        {tab === "jobs" ? <JobsView orgId={me.tenant_id} /> : null}
        {tab === "sources" ? <Sources orgId={me.tenant_id} /> : null}
      </main>
    </>
  );
}
