import { Descope, useDescope, useSession } from "@descope/react-sdk/flows";
import { useCallback, useState } from "react";
import { TokenProvider, useResource } from "./api";
import { type Me, meSchema } from "./schemas";
import { Findings } from "./views/Findings";
import { Images } from "./views/Images";
import { Overview } from "./views/Overview";
import { JobsView, Sources } from "./views/Pipeline";
import { Loaded } from "./views/parts";

const tabs = ["overview", "images", "findings", "jobs", "sources"] as const;
type Tab = (typeof tabs)[number];

export function App() {
  const { isAuthenticated, isSessionLoading, sessionToken } = useSession();
  if (isSessionLoading) return <p className="status">Loading…</p>;
  if (!isAuthenticated)
    return (
      <div className="login">
        <h1>Squawk admin</h1>
        <Descope flowId="sign-up-or-in" theme="dark" />
      </div>
    );
  return (
    <TokenProvider value={sessionToken ?? ""}>
      <Panel />
    </TokenProvider>
  );
}

/* `/v1/me` rather than the JWT's own claims: the Worker decides which capabilities it
   honours, so the panel shows exactly the controls the API will accept. */
function Panel() {
  const resource = useResource("/v1/me", meSchema);
  return <Loaded resource={resource}>{(me) => <Console me={me} />}</Loaded>;
}

/* Exported as a render seam: the authenticated console can then be mounted with a
   known principal in a browser harness, which a Descope-issued session cannot be
   forged to produce. `App` remains the only path that reaches it in production. */
export function Console({ me }: { me: Me }) {
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
