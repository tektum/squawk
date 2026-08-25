import { AuthProvider } from "@descope/react-sdk/flows";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";

/* Configuration arrives on data attributes rather than an inline script, so the shell
   keeps `script-src 'self'` without `unsafe-inline`.

   `persistTokens={false}` keeps the session and refresh tokens out of localStorage, so
   a reload costs a round trip through the flow rather than leaving durable credentials
   in a store any injected script could read. */
const host = document.getElementById("admin");
if (host) {
  const projectId = host.dataset["projectId"] ?? "";
  const baseUrl = host.dataset["baseUrl"];
  createRoot(host).render(
    <StrictMode>
      <AuthProvider projectId={projectId} persistTokens={false} {...(baseUrl ? { baseUrl } : {})}>
        <App />
      </AuthProvider>
    </StrictMode>,
  );
}
