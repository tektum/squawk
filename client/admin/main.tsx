import { AuthProvider } from "@descope/react-sdk/flows";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";

/* Configuration arrives on data attributes rather than an inline script, so the shell
   keeps `script-src 'self'` without `unsafe-inline`. */
const host = document.getElementById("admin");
if (host) {
  const projectId = host.dataset["projectId"] ?? "";
  const baseUrl = host.dataset["baseUrl"];
  createRoot(host).render(
    <StrictMode>
      <AuthProvider projectId={projectId} persistTokens {...(baseUrl ? { baseUrl } : {})}>
        <App />
      </AuthProvider>
    </StrictMode>,
  );
}
