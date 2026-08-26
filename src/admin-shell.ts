import { adminClientDigest, adminClientSource } from "./generated/admin-client";

/* The panel is a static shell: it carries no tenant data and no secret. Everything it
   shows arrives from `/v1` under the operator's own Descope session, so the HTML stays
   cacheable and the authorization decision stays on the Worker. */

const DESCOPE_DEFAULT_ORIGIN = "https://api.descope.com";
/* Hosted flows are rendered by Descope's web component, which pulls its screens and UI
   chunks from Descope's static and CDN origins at runtime. Using Descope Flows means
   accepting those origins in `script-src`; the alternative is hand-built auth screens,
   which forfeits console-configured SSO, MFA, and social login. Descope documents
   `api.descope.com` and `static.descope.com` as the required egress, and the bundled
   web component also reaches its CDN mirrors. */
const DESCOPE_ASSET_ORIGINS = [
  "https://static.descope.com",
  "https://static2.descope.com",
  "https://descopecdn.com",
] as const;

function descopeOrigin(baseUrl: string | undefined): string {
  if (!baseUrl) return DESCOPE_DEFAULT_ORIGIN;
  try {
    return new URL(baseUrl).origin;
  } catch {
    return DESCOPE_DEFAULT_ORIGIN;
  }
}

/* Configuration travels on data attributes because an inline bootstrap script would
   force `unsafe-inline`, and `frame-ancestors 'none'` keeps the panel out of frames
   even though flows may open their own. */
export function adminShellResponse(projectId: string, baseUrl: string | undefined): Response {
  const origin = descopeOrigin(baseUrl);
  const assets = DESCOPE_ASSET_ORIGINS.join(" ");
  return new Response(shell(projectId, baseUrl ? origin : null), {
    headers: {
      "content-security-policy": [
        "default-src 'none'",
        `script-src 'self' ${assets}`,
        `style-src 'unsafe-inline' ${assets}`,
        `font-src data: ${assets}`,
        `connect-src 'self' ${origin} ${assets}`,
        "img-src 'self' data: https:",
        `frame-src ${origin}`,
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ].join("; "),
      "content-type": "text/html; charset=utf-8",
      "referrer-policy": "no-referrer",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-content-type-options": "nosniff",
    },
  });
}

export function adminClientResponse(request: Request): Response {
  const etag = `"${adminClientDigest}"`;
  if (request.headers.get("if-none-match") === etag)
    return new Response(null, { status: 304, headers: { etag } });
  return new Response(adminClientSource, {
    headers: {
      "cache-control": "public, max-age=31536000, immutable",
      "content-type": "text/javascript; charset=utf-8",
      etag,
      "x-content-type-options": "nosniff",
    },
  });
}

function attribute(value: string): string {
  return value.replace(/[&"<>]/g, (character) => `&#${character.charCodeAt(0)};`);
}

function shell(projectId: string, baseUrl: string | null): string {
  const base = baseUrl ? ` data-base-url="${attribute(baseUrl)}"` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>Squawk admin</title><style>${styles}</style></head>
<body><div id="admin" data-project-id="${attribute(projectId)}"${base}><p class="status">Loading…</p></div>
<script type="module" src="/admin/app.js?v=${adminClientDigest}"></script></body></html>`;
}

/* Same Verity palette as the public surface so the panel reads as one product. */
const styles = `:root{color-scheme:dark;--ink:#e8edf2;--muted:#7f94a1;--line:#172732;--surface:#0a1720;--void:#060d12;--teal:#00f0cc;--orange:#fb923c;--red:#f87171;--mono:"SFMono-Regular",Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--void);color:var(--ink);font:13px/1.5 var(--mono)}
header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:14px max(20px,calc((100% - 1400px)/2));border-bottom:1px solid var(--line)}
.wordmark{letter-spacing:.18em;font-size:16px}
.status{color:var(--muted);font-size:11px;letter-spacing:.04em}
.status.risk{color:var(--red)}
nav.tabs{display:flex;gap:8px;padding:10px max(20px,calc((100% - 1400px)/2));border-bottom:1px solid var(--line)}
nav.tabs button{text-transform:uppercase;letter-spacing:.12em;font-size:11px}
main{padding:20px max(20px,calc((100% - 1400px)/2))}
section{margin-bottom:28px}
h1{font-size:18px;letter-spacing:.06em}h2{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
button{font:inherit;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:3px;padding:5px 10px;cursor:pointer}
button:hover{border-color:var(--teal)}button[disabled]{opacity:.5;cursor:progress}
button.link{background:none;border:none;color:var(--teal);padding:0;text-align:left}
input,select{font:inherit;background:var(--void);color:var(--ink);border:1px solid var(--line);border-radius:3px;padding:5px 8px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--muted);font-weight:400;text-transform:uppercase;letter-spacing:.1em;font-size:10px;padding:6px 10px 6px 0;border-bottom:1px solid var(--line)}
td{padding:6px 10px 6px 0;border-bottom:1px solid var(--line);vertical-align:top;max-width:420px;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:0}
.field dt{color:var(--muted);font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.field dd{margin:2px 0 0;overflow-wrap:anywhere}
.tag{padding:1px 6px;border:1px solid var(--line);border-radius:2px;font-size:11px}
.tag.clean{color:var(--teal);border-color:var(--teal)}.tag.risk{color:var(--red);border-color:var(--red)}
.tag.pending{color:var(--orange);border-color:var(--orange)}.tag.muted{color:var(--muted)}
.actions{display:flex;gap:10px;align-items:center;margin-bottom:18px;flex-wrap:wrap}
.vex{display:flex;gap:6px}.vex input{width:150px}
.empty{color:var(--muted)}
.login{max-width:380px;margin:12vh auto;padding:0 20px}`;
