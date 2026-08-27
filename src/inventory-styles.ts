/* Verity surface (Tektum design system, `--vr-*` tokens): near-black void ground,
   teal nucleus accent, monospace register, CVE severity ramp. Self-contained so the
   page keeps its `default-src 'none'` CSP: no webfont or stylesheet fetches, so the
   display voice falls back to the system mono stack. */
export const inventoryStyles = `:root{
color-scheme:dark;
--vr-nucleus:#00f0cc;--vr-nucleus-dim:#00d4b8;
--vr-void:#060d12;--vr-void-2:#0b1419;--vr-surface:#0a1720;--vr-surface-2:#111b22;
--vr-border:#152230;--vr-border-2:#1f2b35;
--vr-text:#e8edf2;--vr-text-1:#c5d5dd;--vr-text-2:#95a8b8;--vr-text-muted:#7a8e9c;--vr-text-dim:#2e4a5a;
--vr-sev-high:#fb923c;--vr-sev-high-bg:rgba(67,20,7,.4);--vr-clean:#00f0cc;
--vr-line:rgba(232,237,242,.07);
--vr-radius-sm:2px;--vr-radius:4px;--vr-radius-lg:10px;
--vr-shadow-card:0 1px 0 rgba(255,255,255,.02),0 8px 24px rgba(0,0,0,.5);
--vr-font-display:"Share Tech Mono","SF Mono",ui-monospace,monospace;
--vr-font-code:"JetBrains Mono","SF Mono",ui-monospace,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--vr-void);color:var(--vr-text);font-family:var(--vr-font-code);
background-image:radial-gradient(rgba(0,240,204,.03) 1px,transparent 1px);background-size:48px 48px}
main{max-width:1160px;margin:auto;padding:0 30px 72px}
.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:14px;height:58px;padding:0 30px;
background:rgba(6,13,18,.86);backdrop-filter:blur(8px);border-bottom:1px solid var(--vr-border)}
.wordmark{font:400 17px/1 var(--vr-font-display);letter-spacing:.18em}
.topbar-meta{font:11px/1 var(--vr-font-code);letter-spacing:.14em;text-transform:uppercase;color:var(--vr-text-muted)}
.eyebrow,dt,th,label,.section-title span,footer,.status,.eco,.stats span{font-family:var(--vr-font-code);
font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--vr-text-muted)}
header{padding:62px 0 44px;border-bottom:1px solid var(--vr-line)}
.eyebrow{font-family:var(--vr-font-display);letter-spacing:.22em;margin:0}
h1{font:400 clamp(28px,4.6vw,40px)/1.14 var(--vr-font-display);color:var(--vr-text);text-wrap:balance;margin:18px 0 0}
.intro{max-width:620px;font:14px/1.7 var(--vr-font-code);color:var(--vr-text-2);margin:20px 0 0}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;margin:44px 0;
background:var(--vr-border);border:1px solid var(--vr-border);border-radius:var(--vr-radius-lg);overflow:hidden}
.stats div{background:var(--vr-surface);padding:22px 24px}
.stats strong{display:block;font:400 32px/1 var(--vr-font-display);font-variant-numeric:tabular-nums}
.stats span{display:block;margin-top:10px;font-size:10px}
.stats .risk strong{color:var(--vr-sev-high)}
.stats .risk.clean strong{color:var(--vr-clean)}
form{margin:0 0 8px}
label{display:block;margin-bottom:10px}
form>div{display:flex;gap:12px}
input{flex:1;min-width:0;background:var(--vr-void-2);border:1px solid var(--vr-border-2);border-radius:var(--vr-radius);
padding:11px 13px;font:13px var(--vr-font-code);color:var(--vr-text)}
input::placeholder{color:var(--vr-text-muted)}
input:focus{border-color:var(--vr-nucleus);outline:none}
button{border:1px solid rgba(0,240,204,.28);border-radius:var(--vr-radius);background:rgba(0,240,204,.1);
color:var(--vr-nucleus);padding:0 22px;font:12px var(--vr-font-code);letter-spacing:.14em;text-transform:uppercase;cursor:pointer}
button:hover{background:rgba(0,240,204,.16)}
.section-title{display:flex;justify-content:space-between;align-items:baseline;gap:16px;
margin:52px 0 16px;padding-bottom:12px;border-bottom:1px solid var(--vr-line)}
h2{font:400 22px/1 var(--vr-font-display);letter-spacing:.04em;margin:0}
.images{display:grid;grid-template-columns:repeat(auto-fill,minmax(336px,1fr));gap:16px}
.card{display:flex;flex-direction:column;gap:14px;padding:18px;background:var(--vr-surface);
border:1px solid var(--vr-border);border-radius:var(--vr-radius-lg);transition:border-color 160ms,box-shadow 160ms}
.card:hover{border-color:var(--vr-border-2);box-shadow:var(--vr-shadow-card)}
.status{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;font-size:10px;font-weight:600;
letter-spacing:.12em;border-radius:var(--vr-radius-sm);color:var(--vr-clean);
background:rgba(0,240,204,.08);border:1px solid rgba(0,240,204,.28)}
.status .dot{width:5px;height:5px;border-radius:50%;background:currentColor;flex:none}
.status.processing{color:var(--vr-sev-high);background:var(--vr-sev-high-bg);border-color:rgba(251,146,60,.28)}
.status.processing .dot{animation:pulse 2s cubic-bezier(.4,0,.2,1) infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(251,146,60,.5)}50%{box-shadow:0 0 0 4px rgba(251,146,60,0)}}
@media(prefers-reduced-motion:reduce){.status.processing .dot{animation:none}}
.ref{margin:0;font:13px/1.6 var(--vr-font-code);font-weight:400;overflow-wrap:anywhere}
.ref-path{color:var(--vr-text)}
.ref-digest{color:var(--vr-text-muted)}
dl{display:flex;flex-wrap:wrap;gap:22px;margin:auto 0 0;padding-top:14px;border-top:1px solid var(--vr-line)}
dl div{min-width:0}
dt{font-size:10px;letter-spacing:.14em}
dd{margin:6px 0 0;font:13px var(--vr-font-code);font-variant-numeric:tabular-nums;color:var(--vr-text-1)}
dd.clean{color:var(--vr-clean)}
dd.risk{color:var(--vr-sev-high)}
.table-wrap{overflow:auto;border:1px solid var(--vr-border);border-radius:var(--vr-radius-lg)}
table{width:100%;border-collapse:collapse;background:var(--vr-surface)}
th,td{text-align:left;padding:12px 16px;border-bottom:1px solid var(--vr-line)}
th{background:var(--vr-void-2)}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--vr-surface-2)}
td{font:13px var(--vr-font-code);color:var(--vr-text-1)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.eco{display:inline-block;padding:3px 8px;font-size:10px;letter-spacing:.14em;color:var(--vr-text-2);
border:1px solid var(--vr-border-2);border-radius:var(--vr-radius-sm)}
code{font:inherit}
.empty{padding:28px;margin:0;font:13px var(--vr-font-code);color:var(--vr-text-muted)}
footer{margin-top:60px;padding-top:18px;border-top:1px solid var(--vr-line);letter-spacing:.12em}
a{color:var(--vr-nucleus)}
a:hover{color:var(--vr-nucleus-dim)}
button:focus-visible,input:focus-visible,a:focus-visible{outline:2px solid var(--vr-nucleus);outline-offset:2px}
@media(max-width:720px){
main{padding:0 16px 48px}
.topbar{padding:0 16px}
header{padding:36px 0 28px}
.stats{grid-template-columns:repeat(2,1fr)}
.images{grid-template-columns:1fr}
dl{gap:16px}}`;
