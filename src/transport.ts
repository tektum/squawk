/* The panel sends a session token on every request, so a plaintext hop would leak it.
   `workers.dev` answers on HTTP and offers no zone-level redirect, so the Worker refuses
   plaintext itself. Loopback and bare-IP hosts are exempt: that is `wrangler dev`, which
   has no certificate and never carries a real token. */

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);
const IP_LITERAL = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$/i;

export function insecurePublicRequest(url: URL): boolean {
  if (url.protocol !== "http:") return false;
  const hostname = url.hostname.toLowerCase();
  return !LOOPBACK.has(hostname) && !IP_LITERAL.test(hostname);
}

export function httpsRedirect(url: URL): Response {
  const secure = new URL(url.toString());
  secure.protocol = "https:";
  secure.port = "";
  return Response.redirect(secure.toString(), 301);
}
