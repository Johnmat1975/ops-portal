// Shared by every page: theme toggle, header title, small helpers.
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Theme: the stored choice is applied before first paint; the Light / System / Dark switch lives in chrome.js.
// 'system' (or nothing stored) follows the operating system.
try { const t = localStorage.getItem('lg-portal-theme'); if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t); } catch {}
try { if (localStorage.getItem('lg-density') === 'compact') document.body.classList.add('compact'); } catch {}

// JavaScript scrolling honours reduced motion too (CSS scroll-behavior doesn't cover scrollIntoView).
const SMOOTH = () => { try { return matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'; } catch { return 'auto'; } };
const fmtDate = (iso, year) => { if (!iso) return ''; const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', ...(year ? { year: 'numeric' } : {}), timeZone: 'UTC' }); };

async function paintHeader() {
  let s = await window.portal.settings();
  // One-time move (0.5): report branding and seat prices used to live in browser storage; the app keeps them now,
  // so they survive a reinstall and go into Settings › Export. Browser copies are removed only once saved.
  try {
    const b = JSON.parse(localStorage.getItem('qbr-brand') || 'null'), pk = `prices:${s.instance}`, pr = JSON.parse(localStorage.getItem(pk) || 'null');
    const patch = {};
    if (b && !s.branding) patch.branding = { name: b.name || '', logo: b.logo || null };
    if (pr && !s.prices) patch.prices = pr;
    if (Object.keys(patch).length) { await window.portal.updateSettings(patch); s = await window.portal.settings(); }
    if (b) localStorage.removeItem('qbr-brand');
    if (pr) localStorage.removeItem(pk);
  } catch {}
  const name = (s.env && s.env.Name) || 'Liongard';
  $('portalTitle').textContent = `${name} portal`;
  document.title = document.title.replace(/^[^·]*·/, `${name} ·`);
  if (typeof chromeSettings === 'function') { try { chromeSettings(s); } catch (err) { console.error('chrome', err); } }   // top bar: switcher, ribbon, present
  return s;
}

const SEV_VAR = { ok: 'var(--ok-ink)', warn: 'var(--warn-ink)', bad: 'var(--crit)', info: 'var(--none)', none: 'var(--none)' };   // neutral counts in Liongard's slate grey
// sev 'none' = not covered (no tool of that kind): neutral slate with a dashed frame, never amber.
const kpiStrip = list => list.map(x => `<div class="kpi${x.v === '—' ? ' no-evidence' : ''}${x.sev === 'none' && x.v !== '—' ? ' dashed' : ''}" data-k="${esc(x.k)}" data-s="${esc(x.s)}" style="--sev:${SEV_VAR[x.sev] || SEV_VAR.info}"><span class="k">${esc(x.k)}</span><span class="v">${esc(x.v)}</span><span class="s" title="${esc(x.s)}">${esc(x.s)}</span></div>`).join('');
// Money in the MSP's currency (Settings › Defaults), or in the currency the source bills in (Anthropic:
// USD). With no currency set, a plain number: never a guessed symbol.
const fmtMoney = (v, cur) => {
  const n = +v; if (!Number.isFinite(n)) return '–';
  if (cur && /^[A-Z]{3}$/.test(cur)) { try { return new Intl.NumberFormat('en-GB', { style: 'currency', currency: cur, minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(n); } catch {} }
  return n.toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
};
// A seat price as typed: "12.50", "12,50", "1 234,50", "1,234.50", "€18". A number, or null if it isn't one.
// Keep in step with parsePrice in src/main/validate.js.
function parsePrice(v) {
  if (typeof v === 'number') return Number.isFinite(v) && v >= 0 ? v : null;
  let s = String(v ?? '').replace(/[\s\u00a0£€$]/g, '');
  if (!s) return null;
  s = s.replace(/,(?=\d{1,2}$)/, '.');
  s = s.replace(/[.,](?=\d{3}(\D|$))/g, '');
  return /^\d+(\.\d{1,4})?$/.test(s) ? +s : null;
}
const mspCurrency = () => ((typeof SETTINGS !== 'undefined' && SETTINGS && SETTINGS.defaults) || {}).currency || '';
const cleanErr = e => String(e && e.message || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');

// Standalone snapshot: inline the CSS and any page images, drop the scripts and buttons. The top bar has no logo image
// any more (the "Powered by" mark is text), so nothing here may assume one exists.
async function exportPage() {
  const css = [...document.styleSheets].map(s => { try { return [...s.cssRules].map(r => r.cssText).join('\n'); } catch { return ''; } }).join('\n');
  const doc = document.documentElement.cloneNode(true);
  doc.querySelectorAll('script, link[rel=stylesheet], meta[http-equiv], #themeSw, #presentBtn, #swKbd, .page-acts, #cmdk, #drawer, .nav-open-btn, .skip').forEach(n => n.remove());
  // Images that point at app files (not data: URIs) won't load from a saved file: inline them, or drop them if they can't be.
  doc.querySelectorAll('img[src]:not([src^="data:"])').forEach(n => {
    const live = [...document.images].find(i => i.getAttribute('src') === n.getAttribute('src') && i.complete && i.naturalWidth);
    if (!live) { n.remove(); return; }
    try { const c = document.createElement('canvas'); c.width = live.naturalWidth; c.height = live.naturalHeight; c.getContext('2d').drawImage(live, 0, 0); n.setAttribute('src', c.toDataURL('image/png')); } catch { n.remove(); }
  });
  const head = doc.querySelector('head');
  // The saved file never runs anything: no scripts, no remote loads, only its own styles and embedded images.
  if (head) {
    head.insertAdjacentHTML('afterbegin', `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:">`);
    head.insertAdjacentHTML('beforeend', `<style>${css}</style>`);
  }
  doc.querySelectorAll('a.back').forEach(a => a.remove());
  const saved = await window.portal.exportHtml('<!doctype html>\n' + doc.outerHTML);
  if (saved) $('statusLine').textContent = `Saved to ${saved}`;
  return saved;
}

// ---------- Risk chips ----------
// One scale wherever Critical / High / Medium / Low appear: Critical solid red, High red tint, Medium amber, Low grey.
const RISK_CHIP = {
  critical: ['r-critical', 'Critical'],
  high: ['r-high', 'High'],
  medium: ['r-medium', 'Medium'],
  low: ['r-low', 'Low'],
};
const riskKey = r => { const k = String(r ?? '').trim().toLowerCase(); return RISK_CHIP[k] ? k : k === 'info' || k === 'informational' || k === 'none' ? 'low' : ''; };
const riskChip = (r, label) => { const k = riskKey(r); return k ? `<span class="chip ${RISK_CHIP[k][0]}">${esc(label != null ? label : RISK_CHIP[k][1])}</span>` : `<span class="chip c-none">${esc(label != null ? label : r || 'Unknown')}</span>`; };

// Section every page gets for the client's inspectors it has no detailed rules for, built from Liongard's metrics.
const SEV_CHIP = { bad: 'c-crit', warn: 'c-warn' };
function moreSection(more, ctx) {
  if (!more) return '';
  if (more.error) return `<div class="card flag warn more"><h3>Other inspectors</h3><p>Couldn’t read Liongard metrics for this client: ${esc(more.error)}</p></div>`;
  const has = more.findings.length || more.expiries.length || more.drift.length || (more.facts || []).length;
  const head = `<h3>${esc(more.title)}</h3><p class="sub">${more.tools.length ? `Read from Liongard’s metrics for ${more.tools.map(esc).join(', ')}.` : 'This client has no other inspectors that feed this page.'}${more.blind.length ? ` <b>${more.blind.length} of them aren’t returning fresh data</b> (${more.blind.slice(0, 4).map(esc).join(', ')}), so problems there won’t show.` : ''}</p>`;
  if (!has) return `<div class="card more">${head}${more.tools.length ? '<p>Nothing to report from these inspectors.</p>' : ''}</div>`;
  const findings = more.findings.length ? `<div class="tw"><table><thead><tr><th>Severity</th><th>What Liongard reports</th><th class="c">Value</th><th>Where</th></tr></thead><tbody>${more.findings.map(f => `<tr><td><span class="chip ${SEV_CHIP[f.sev]}">${f.sev === 'bad' ? 'Problem' : 'Review'}</span></td><td class="wrap">${esc(f.label)}${f.list && f.list.length ? `<details><summary class="sub">Show ${f.list.length}</summary><div class="sub">${f.list.map(x => esc(typeof x === 'string' ? x : JSON.stringify(x))).join('<br>')}</div></details>` : +f.value > 0 && f.metric && f.systemDetailId ? `<div><button type="button" class="linkbtn mi-look no-print" data-m="${esc(f.metric)}" data-sd="${esc(f.systemDetailId)}" data-t="${esc(f.label)}" data-s="${esc(`${f.system} · ${f.inspector}`)}">Show which ones →</button></div>` : ''}</td><td class="c mono">${esc(f.value)}</td><td class="wrap">${toolIcon(f.inspector)}${ctx && f.systemId ? lgA(LG.system(ctx, f.systemId, f.systemDetailId), esc(f.system), 'Open this system in Liongard') : esc(f.system)}<div class="sub" style="margin:0">${esc(f.inspector)}</div></td></tr>`).join('')}</tbody></table></div>` : '';
  const exp = more.expiries.length ? `<h4>Renewal dates</h4><div class="tw"><table><thead><tr><th>Date</th><th class="c">Days</th><th>What</th><th>Where</th></tr></thead><tbody>${more.expiries.map(e => `<tr><td class="num">${fmtDate(e.date, true)}</td><td class="c mono"><span class="chip ${e.days < 0 ? 'c-crit' : e.days <= 90 ? 'c-warn' : 'c-none'}">${e.days < 0 ? `${agoText(-e.days)}` : `${e.days}`}</span></td><td class="wrap">${esc(e.label)}</td><td class="wrap">${toolIcon(e.inspector)}${esc(e.system)}<div class="sub" style="margin:0">${esc(e.inspector)}</div></td></tr>`).join('')}</tbody></table></div>` : '';
  const drift = more.drift.length ? `<h4>Version drift</h4><ul class="plain">${more.drift.map(d => `<li><span><b>${esc(d.inspector)}: ${esc(d.label)}</b> differs across devices. ${d.values.map(v => `${esc(v.value)} on ${v.systems.map(esc).join(', ')}`).join('; ')}.</span></li>`).join('')}</ul>` : '';
  const facts = (more.facts || []).length ? `<h4>Key values</h4><div class="two even">${more.facts.map(x => `<div class="card"><b>${esc(x.system)}</b><span class="sub" style="margin:0">${esc(x.inspector)}</span><div class="kv">${x.rows.map(r => `<span>${esc(r.n)}</span><span class="mono">${esc(r.v)}</span>`).join('')}</div></div>`).join('')}</div>` : '';
  return `<div class="card more">${head}${findings}${exp}${drift}${facts}</div>`;
}

// ---------- Times ----------
// Shown in UTC (Liongard's own timestamps) or this computer's time zone; the choice is remembered on this machine.
const tzPref = () => { try { return localStorage.getItem('tz') || 'utc'; } catch { return 'utc'; } };
function fmtWhen(iso) {
  const d = new Date(iso); if (isNaN(d)) return '';
  const local = tzPref() === 'local';
  return d.toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', ...(local ? {} : { timeZone: 'UTC' }) }) + (local ? '' : ' UTC');
}

// ---------- Links ----------
// Into Liongard (formats confirmed in the Liongard UI, Oct 2026) and between pages of this app.
const LG = {
  base: ctx => `https://${ctx.instance}.app.liongard.com`,
  system: (ctx, sysId, sdId, tab) => sysId && sdId ? `${LG.base(ctx)}/environment/${ctx.envId}/dataprint/${sysId}/${sdId}${tab ? `?tab=${tab}` : ''}` : null,
  launchpoint: (ctx, inspectorId, lpId) => inspectorId && lpId ? `${LG.base(ctx)}/admin/inspector/${inspectorId}/launchpoint/${lpId}` : null,
  device: (ctx, id) => id ? `${LG.base(ctx)}/environment/${ctx.envId}?tab=cyber-asset-inventory&view=devices&sourceTab=Inventory&expandedDeviceViewQuery=${encodeURIComponent(id)}` : null,
  identity: (ctx, id) => id ? `${LG.base(ctx)}/environment/${ctx.envId}?tab=cyber-asset-inventory&view=identities-and-accounts&sourceTab=Inventory&expandedIdentityViewQuery=${encodeURIComponent(id)}` : null,
  alert: (ctx, id) => id ? `${LG.base(ctx)}/environment/${ctx.envId}?tab=overview&view=alerts&alertId=${encodeURIComponent(id)}` : null,
  alerts: ctx => `${LG.base(ctx)}/environment/${ctx.envId}?tab=overview&view=alerts`,
};
const EXT_ICON = '<svg class="ext" viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const lgA = (url, label, what = 'Open in Liongard') => url ? `<a class="lg" href="${esc(url)}" target="_blank" rel="noopener" title="${esc(what)}">${label}${EXT_ICON}</a>` : label;
// Arrow links ("Wallboard →", "↗") only move between pages: Present hides them (.xp-go). Links whose label is content stay, inert.
const pageA = (id, q, label, what) => `<a class="xp${/(→|↗)\s*$/.test(String(label)) ? ' xp-go' : ''}" href="panel.html?id=${id}${q ? `&q=${encodeURIComponent(q)}` : ''}" title="${esc(what || 'Open in this app')}">${label}</a>`;
// The best Liongard link for a reference object ({systemId, systemDetailId, deviceId, identityId, alertId, lpId, inspectorId}).
function lgFor(ctx, r, tab) {
  return LG.device(ctx, r.deviceId) || LG.identity(ctx, r.identityId) || LG.alert(ctx, r.alertId) || LG.system(ctx, r.systemId, r.systemDetailId, tab) || LG.launchpoint(ctx, r.inspectorId, r.lpId);
}

// ---------- CSV ----------
// Names, hostnames and DNS records come from the client's tenant: a cell that starts like a formula (= + - @) is
// prefixed with ' so Excel shows it as text instead of running it. Plain numbers (-5, +3%) are left alone.
const csvCell = v => {
  let s = String(v ?? '').replace(/\s+/g, ' ').trim();
  if (/^[=+\-@\t\r]/.test(s) && !/^[-+]?\d[\d,]*(\.\d+)?%?$/.test(s)) s = `'${s}`;
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
function tableCsv(table) {
  // Exports what the filters show, including rows only paged out of view (tr.paged); never the "Show more" row or a
  // group heading inside the table (tr.csv-skip), whose label is already a column.
  return [...table.rows].filter(r => !r.classList.contains('more-row') && !r.classList.contains('csv-skip') && (!r.closest('tr.detail') && (r.offsetParent !== null || r.classList.contains('paged')) || r.parentElement.tagName === 'THEAD'))
    .map(r => [...r.cells].map(c => csvCell(c.dataset.csv ?? c.innerText)).join(',')).join('\n');
}
// Adds a "CSV" button above every table on the page.
function addCsvButtons(root, baseName) {
  root.querySelectorAll('.tw > table').forEach((t, i) => {
    const tw = t.parentElement; if (tw.previousElementSibling && tw.previousElementSibling.classList.contains('csvbar')) return;
    const h = (tw.closest('.card') && tw.closest('.card').querySelector('h3')) || [...root.querySelectorAll('h3')].filter(x => x.compareDocumentPosition(tw) & Node.DOCUMENT_POSITION_FOLLOWING).pop();
    const label = (h ? h.textContent : `table-${i + 1}`).trim();
    tw.insertAdjacentHTML('beforebegin', `<div class="csvbar"><button type="button" class="btn ghost sm" data-csv-i="${i}">CSV</button></div>`);
    tw.previousElementSibling.querySelector('button').addEventListener('click', async () => {
      const saved = await window.portal.exportCsv({ name: `${baseName}-${label}`.replace(/[^\w-]+/g, '-').slice(0, 80), csv: tableCsv(t) });
      if (saved) $('statusLine').textContent = `Saved ${saved}`;
    });
  });
}

// ---------- PDF ----------
// mode 'full' prints everything (details opened); 'exec' prints the summary only (anything marked .tech is left out).
async function exportPdf(mode, title, kicker) {
  const body = document.body, opened = [];
  document.querySelectorAll('details:not([open])').forEach(d => { if (mode === 'full' && !d.closest('.no-print') && !d.classList.contains('screen-only')) { d.open = true; opened.push(d); } });
  const hidden = [];
  if (mode === 'full') document.querySelectorAll('tr.detail[hidden]:not(.screen-only)').forEach(r => { r.hidden = false; hidden.push(r); });   // .screen-only: too long to print (offered as CSV)
  const theme = document.documentElement.getAttribute('data-theme');
  document.documentElement.setAttribute('data-theme', 'light');   // reports always print light
  const htmlBg = document.documentElement.style.background; document.documentElement.style.background = '#fff';
  body.classList.add('printing', mode === 'exec' ? 'print-exec' : mode === 'review' ? 'print-review' : 'print-full');
  // Executive summary: a section whose tables are all left out prints nothing, not a heading over an empty space.
  const skipped = [];
  if (mode === 'exec') document.querySelectorAll('.psec').forEach(sec => {
    const b = sec.querySelector('.psec-body');
    const shows = b && [...b.children].some(c => !(c.matches('p.sub') || c.classList.contains('sr-only')) && getComputedStyle(c).display !== 'none');
    if (!shows) { sec.classList.add('print-skip'); skipped.push(sec); }
  });
  const cover = document.getElementById('printCover');
  // the MSP's own logo (Settings › Your MSP) on every cover, and the Liongard text mark.
  let brand = null; try { brand = ((await window.portal.settings()) || {}).branding || null; } catch {}
  const logo = brand && typeof brand.logo === 'string' && /^data:image\/(png|jpeg|svg\+xml|webp);/.test(brand.logo) ? brand.logo : '';
  if (cover) {
    cover.classList.toggle('has-logo', !!logo);
    cover.innerHTML = `<div class="pc-k">${esc(kicker || (mode === 'exec' ? 'Executive summary' : mode === 'review' ? 'For client sign-off' : 'Technical report'))}</div><h1>${esc(title)}</h1><p>${esc(document.getElementById('portalTitle').textContent.replace(/ portal$/, ''))} · prepared ${brand && brand.name ? `by ${esc(brand.name)} ` : ''}${fmtDate(new Date().toISOString(), true)} · ${esc($('statusLine').textContent)}</p>${logo ? `<img class="pc-logo" src="${esc(logo)}" alt="${esc((brand && brand.name) || 'Logo')}">` : ''}<p class="pc-by">Powered by Liongard’s <em>Data Lake</em></p>`;
  }
  try {
    const env = (document.getElementById('portalTitle').textContent || '').replace(/ portal$/, '');
    const saved = await window.portal.exportPdf({ name: `${env}-${title}${mode === 'review' ? '' : `-${mode === 'exec' ? 'summary' : 'report'}`}`, landscape: mode !== 'exec' });   // full reports have wide tables
    if (saved) $('statusLine').textContent = `Saved ${saved}`;
  } finally {
    body.classList.remove('printing', 'print-exec', 'print-full', 'print-review');
    if (theme) document.documentElement.setAttribute('data-theme', theme); else document.documentElement.removeAttribute('data-theme');
    document.documentElement.style.background = htmlBg;
    opened.forEach(d => { d.open = false; }); hidden.forEach(r => { r.hidden = true; });
    skipped.forEach(sec => sec.classList.remove('print-skip'));
  }
}

// ---------- Data age ----------
// "40 days ago", but "6.8 years ago" once it's past a year.
const agoText = d => d >= 365 ? `${(d / 365).toFixed(1).replace(/\.0$/, '')} years ago` : `${d} day${d === 1 ? '' : 's'} ago`;
function dataAgeNote(pulledOn) {
  const h = (Date.now() - new Date(pulledOn)) / 36e5;
  // Daily inspectors make data up to a day old normal, so only flag it after 24 hours (amber after 48).
  if (!pulledOn || isNaN(h) || h < 24) return '';
  return `<div class="card flag ${h >= 48 ? 'warn' : 'info'} age no-print-exec"><p style="margin:0"><b>This page shows data pulled ${h < 48 ? `${Math.round(h)} hours` : `${Math.round(h / 24)} days`} ago</b> (${fmtWhen(pulledOn)}). Click <b>Refresh all</b> for the latest.</p></div>`;
}

// ---------- Tool icons (as in Liongard's Asset Inventory) ----------
// Each inspector's icon, fetched once by the main process and handed over as data: URIs. toolIcon("SentinelOne") gives the
// small icon; names that are a little different from the inspector's ("CrowdStrike" → "CrowdStrike EDR") still match.
let TOOL_ICONS = {};
const iconsLoaded = (window.portal && window.portal.icons ? window.portal.icons() : Promise.resolve({})).then(m => { TOOL_ICONS = m || {}; }).catch(() => {});
// Names that aren't an inspector: Defender is reported by the Windows agent (Windows Security Center), so it shows that icon.
const ICON_ALIAS = { 'microsoft defender': 'windows workstation', 'defender': 'windows workstation', 'windows security center': 'windows workstation', 'liongard inventory': '', 'm365': 'microsoft 365', 'office 365': 'microsoft 365', 'intune': 'microsoft 365' };
function toolIconSrc(name) {
  let n = String(name || '').toLowerCase().replace(/\s*\(.*\)\s*$/, '').trim();
  if (!n) return '';
  if (n in ICON_ALIAS) n = ICON_ALIAS[n];
  if (!n) return '';
  if (TOOL_ICONS[n]) return TOOL_ICONS[n];
  // "CrowdStrike" → "crowdstrike edr"; "Datto RMM agent" → "datto rmm": the longest alias that one name starts with.
  const keys = Object.keys(TOOL_ICONS);
  const k = keys.filter(a => a.startsWith(n + ' ') || n.startsWith(a + ' ')).sort((a, b) => b.length - a.length)[0];
  return k ? TOOL_ICONS[k] : '';
}
const toolIcon = name => { const src = toolIconSrc(name); return src ? `<img class="ti" src="${src}" alt="" aria-hidden="true" title="${esc(name)}">` : ''; };
// Icon + name, e.g. in "Protection" cells: toolName("SentinelOne") → [icon] SentinelOne
const toolName = (name, label) => `<span class="tn">${toolIcon(name)}${label != null ? label : esc(name)}</span>`;

// ---------- Pages (shared by the launcher and the side menu) ----------
const ICONS = {
  receipt: '<path d="M6 3h12v18l-3-2-3 2-3-2-3 2z"/><path d="M9 8h6M9 12h6M9 16h3"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  check: '<path d="M9 11l3 3 8-8"/><path d="M20 12v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h9"/>',
  spark: '<path d="M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z"/>',
  net: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
  cal: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  gauge: '<path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-6"/>',
  tv: '<rect x="3" y="5" width="18" height="12" rx="2"/><path d="M8 21h8M12 17v4"/>',
  pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-5-5"/>',
  flag: '<path d="M5 21V4"/><path d="M5 4h11l-2 4 2 4H5"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  layers: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
  home: '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  cog: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
};
const svg = k => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[k]}</svg>`;
const GROUPS = [
  // client: true marks the pages a client may see in Present mode; the rest are internal.
  // Grouped by job, Today first. `s` is the card's short line (≤70 characters, so every tile holds
  // it in two lines); `d` is the full description, shown on hover.
  { g: 'Today', items: [
    { id: 'overview', client: true, ic: 'gauge', t: 'Overview', s: 'Every area for this client, worst first, with its top problem.', d: 'The areas that need attention for this client right now, worst first: threats, identity, devices, email, network, backup, renewals and monitoring, each with its worst open problem.' },
    { id: 'actions', ic: 'flag', t: 'Action plan', s: 'Fixes ranked by risk, with owner, effort and ticket text to copy.', d: 'Everything to fix for this client, ranked by risk: what it affects, how to fix it, who owns it and the effort, with quick wins, ticket text and a client remediation plan.' },
    { id: 'changes', ic: 'pulse', t: 'Change pulse', s: 'Real config changes in the last 90 days, routine churn filtered out.', d: '90 days of real configuration changes, with counters and routine churn filtered out and each change linked to Liongard.' },
    { id: 'inspectors', ic: 'gauge', t: 'Inspector health', s: 'Which inspectors are failing, stale or unscheduled, and why.', d: 'Every inspector, when it last produced good data, why it\u2019s failing, and which aren\u2019t on a schedule.' },
  ]},
  { g: 'Security', items: [
    { id: 'identity', client: true, ic: 'key', t: 'Identity & access', s: 'Admins, MFA gaps, leavers still active and stale accounts.', d: 'Who can administer what across every tool, MFA gaps by system, leavers still in other tools, stale accounts, and a user access review for client sign-off.' },
    { id: 'coverage', ic: 'shield', t: 'Stack coverage', s: 'Each device\u2019s RMM, AV/EDR and backup, and the ones missing any.', d: 'Every device with the actual AV/EDR, RMM and backup products on it, gaps against this client\u2019s coverage policy, and where the tools disagree.' },
    { id: 'email', client: true, ic: 'mail', t: 'Email & domains', s: 'SPF, DKIM, DMARC, filtering and certs, with the DNS fix to publish.', d: 'SPF, DKIM and DMARC for every domain, mail filtering, registrar lock and certificates, with the exact DNS records to publish.' },
    { id: 'cyber', client: true, ic: 'radar', t: 'Cyber security', s: 'Exposures now, risky changes and the ATT&CK techniques Liongard sees.', d: 'Where this client is exposed right now, security-relevant changes mapped to MITRE ATT&CK, and which attack techniques Liongard can and can\u2019t see.' },
  ]},
  { g: 'QBR & commercial', items: [
    { id: 'compliance', client: true, ic: 'check', t: 'Compliance', s: 'Technical-control evidence for CE, CIS, PCI, HIPAA, NIS2 and DORA.', d: 'Technical-control evidence mapped to Cyber Essentials, CIS, PCI DSS, HIPAA, NIS2 and DORA, with an evidence pack per framework.' },
    { id: 'licences', client: true, ic: 'receipt', t: 'Licence reconciliation', s: 'Paid vs used seats, people missing a seat and spare seat cost.', d: 'Seats purchased against seats used, missing seats, stale licensed users and what spare seats cost, with a true-up for the client.' },
    { id: 'lifecycle', client: true, ic: 'cal', t: 'Lifecycle & renewals', s: 'Warranties, OS support, subscriptions, certs and domains by date.', d: 'Warranties, OS support, subscriptions, licences, certificates and domains from every tool on one timeline, with a calendar export.' },
    { id: 'ai', ic: 'spark', t: 'AI usage', s: 'Who uses Claude and ChatGPT, the cost, key age and MFA on accounts.', d: 'Who uses Claude and ChatGPT, what it costs, how old the API keys are, and whether those accounts are protected.' },
  ]},
  { g: 'Estate & tools', items: [
    { id: 'network', client: true, ic: 'net', t: 'Network & firmware', s: 'Firewalls, switches and APs: health, firmware drift and licences.', d: 'Every firewall, switch and access point: health, security services, licences, firmware drift and network admins.' },
    { id: 'stack', ic: 'layers', t: 'Customer stack', s: 'Every tool this client runs, by job, with the issues each reports.', d: 'Every inspector this client runs, grouped by what it does, with the problems, renewals and gaps Liongard\u2019s metrics show for each one.' },
    { id: 'lookup', ic: 'search', t: 'Lookup', s: 'Find a person, device or domain and every system that knows it.', d: 'Search, or pick a person, device or domain, to see every system that knows about it.' },
    { id: 'wallboard', ic: 'tv', t: 'Wallboard', s: 'Open alerts and inspector health for the service-desk screen.', d: 'Open alerts, inspector health and exposed domains for the service-desk screen, with auto-refresh and full screen.' },
  ]},
  { g: 'About this app', items: [
    { id: 'register', ic: 'list', t: 'Function register', d: 'Each page is a saved question to Liongard. See the question and the API data behind every page.' },
  ]},
];

// The launcher and the side menu list every page except the Function register, which lives under Settings.
const NAV_GROUPS = GROUPS.filter(g => !g.items.every(x => x.id === 'register'));

// ---------- Side menu ----------
function paintNav(current, ready = true) {
  if (document.getElementById('sideNav')) return;
  let collapsed = false; try { collapsed = localStorage.getItem('navCollapsed') === '1'; } catch {}
  const nav = document.createElement('nav');
  nav.id = 'sideNav'; nav.className = 'no-print'; nav.setAttribute('aria-label', 'Pages');
  nav.innerHTML = `<div class="nav-top"><a href="index.html" class="nav-home${current === 'home' ? ' on' : ''}" title="Portal home">${svg('home')}<span>Portal home</span></a>
    <button type="button" class="nav-toggle" id="navToggle" aria-label="Collapse or expand the menu" title="Collapse or expand the menu">${svg('menu')}</button></div>
    ${NAV_GROUPS.map(g => `<div class="nav-g"><div class="nav-h">${esc(g.g)}</div>${g.items.map(x => `<a href="panel.html?id=${x.id}" class="${x.id === current ? 'on' : ''}${ready ? '' : ' locked'}" title="${esc(x.t)}" data-id="${x.id}" ${x.id === current ? 'aria-current="page"' : ''}${ready ? '' : ' aria-disabled="true"'}>${svg(x.ic)}<span>${esc(x.t)}</span>${ready ? '' : '<span class="sr-only nv-lock"> (locked: pick a client)</span>'}</a>`).join('')}${g === NAV_GROUPS[NAV_GROUPS.length - 1] ? `<a href="settings.html" class="${current === 'settings' ? 'on' : ''}" title="Settings" ${current === 'settings' ? 'aria-current="page"' : ''}>${svg('cog')}<span>Settings</span></a>` : ''}</div>`).join('')}`;
  // After the top bar in reading and Tab order (it's drawn fixed on the left either way), behind the skip link.
  const bar = document.querySelector('.hero');
  if (bar) bar.after(nav); else document.body.prepend(nav);
  document.body.classList.add('has-nav');
  if (typeof decorateNav === 'function') decorateNav();   // status dots and the Action plan count, from cached models only
  document.body.classList.toggle('nav-collapsed', collapsed);
  nav.querySelector('#navToggle').addEventListener('click', () => {
    if (matchMedia('(max-width: 900px)').matches) { document.body.classList.toggle('nav-open'); return; }
    const c = document.body.classList.toggle('nav-collapsed'); try { localStorage.setItem('navCollapsed', c ? '1' : '0'); } catch {}
  });
  nav.addEventListener('click', e => { const a = e.target.closest('a.locked'); if (a) { e.preventDefault(); location.href = 'index.html'; } });
  // Keep the menu just below the full-width banner, sliding up to the top as the banner scrolls away.
  const place = () => { const h = document.querySelector('.hero'); const b = h && h.offsetParent !== null ? Math.max(0, h.getBoundingClientRect().bottom) : 0; document.documentElement.style.setProperty('--nav-top', `${Math.round(b)}px`); };
  place(); window.addEventListener('scroll', place, { passive: true }); window.addEventListener('resize', place);
  // The banner can grow after load (title, fonts, environment name), so re-place the menu whenever it changes size.
  const hero = document.querySelector('.hero'); if (hero && window.ResizeObserver) new ResizeObserver(place).observe(hero);
  if (document.fonts) document.fonts.ready.then(place);
  // Small screens: a button in the page opens the menu over the content.
  // it sits above the top bar (z-index), says whether the menu is open, and moves focus into the menu.
  const open = document.createElement('button'); open.type = 'button'; open.className = 'nav-open-btn no-print'; open.setAttribute('aria-label', 'Open the menu'); open.setAttribute('aria-controls', 'sideNav'); open.setAttribute('aria-expanded', 'false'); open.innerHTML = svg('menu');
  open.addEventListener('click', () => {
    const on = document.body.classList.toggle('nav-open');
    open.setAttribute('aria-expanded', String(on));
    if (on) { const first = nav.querySelector('a[aria-current], a'); if (first) first.focus(); }
  });
  nav.addEventListener('keydown', e => { if (e.key === 'Escape' && document.body.classList.contains('nav-open')) { document.body.classList.remove('nav-open'); open.setAttribute('aria-expanded', 'false'); open.focus(); } });
  document.body.append(open);
}

// ---------- Modal focus: the page behind a drawer or the command bar is inert, and closing it puts focus
// back on whatever opened it. A drawer that replaces another (Compliance drill-down crumbs) keeps the first invoker.
let MODAL = null;
function modalOn(root) {
  if (!root || typeof document === 'undefined') return;
  const from = MODAL ? MODAL.from : document.activeElement;
  modalOff(false);
  const off = [...document.body.children].filter(n => n !== root && !n.contains(root) && n.tagName !== 'SCRIPT' && !n.inert);
  off.forEach(n => { n.inert = true; });
  MODAL = { root, from, off };
}
function modalOff(restore = true) {
  if (!MODAL) return false;
  MODAL.off.forEach(n => { n.inert = false; });
  const f = MODAL.from; MODAL = null;
  if (restore && f && f.isConnected && f !== document.body && typeof f.focus === 'function') { f.focus(); return true; }
  return false;
}

// ---------- KPI pop-out: the rows behind a number ----------
// Views give kpiItems: { 'KPI label': (m, ctx) => [{ t, d, url, page, q, sev }] }. Tiles with items become clickable.
function wireKpis(view, m, ctx) {
  const map = view.kpiItems || {};
  document.querySelectorAll('.kpi[data-k]').forEach(el => {
    const key = Object.keys(map).find(k => el.dataset.k === k || el.dataset.k.startsWith(k));   // labels like "Spend (14 days reported)" match by prefix
    const fn = key && map[key]; if (!fn) return;
    el.classList.add('clickable'); el.tabIndex = 0; el.setAttribute('role', 'button'); el.title = 'Show what\u2019s behind this number';
    const go = () => { let items = []; try { items = fn(m, ctx) || []; } catch (err) { console.error(err); } openDrawer(el.dataset.k, el.dataset.s, items, m); };
    el.addEventListener('click', go); el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });
}
function openDrawer(title, sub, items, m) {
  closeDrawer();
  const d = document.createElement('div'); d.id = 'drawer'; d.className = 'no-print';
  d.innerHTML = `<div class="dr-back"></div><aside class="dr" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <div class="dr-h"><div><h3>${esc(title)}</h3><p class="sub" style="margin:2px 0 0">${esc(sub || '')}</p></div><button type="button" class="btn ghost sm" id="drClose" aria-label="Close">Close</button></div>
    <div class="dr-tools"><input id="drQ" placeholder="Search ${items.length} item${items.length === 1 ? '' : 's'}" autocomplete="off" aria-label="Search"><button type="button" class="btn ghost sm" id="drCsv">CSV</button></div>
    <ul class="plain dr-list" id="drList"></ul></aside>`;
  document.body.append(d);
  modalOn(d);
  const draw = q => {
    const rows = items.filter(i => !q || `${i.t} ${i.d || ''}`.toLowerCase().includes(q));
    $('drList').innerHTML = rows.map(i => `<li class="${i.sev ? `dr-${i.sev}` : ''}"><div><b>${i.url ? lgA(i.url, esc(i.t)) : esc(i.t)}</b>${i.page ? ` ${pageA(i.page, i.q || i.t, '↗', 'Open in this app')}` : ''}${i.d ? `<div class="sub" style="margin:2px 0 0">${esc(i.d)}</div>` : ''}</div></li>`).join('')
      || `<li class="sub">${items.length ? 'Nothing matches.' : 'Nothing behind this number.'}</li>`;
  };
  draw('');
  $('drQ').addEventListener('input', e => draw(e.target.value.trim().toLowerCase()));
  $('drClose').addEventListener('click', closeDrawer); d.querySelector('.dr-back').addEventListener('click', closeDrawer);
  $('drCsv').addEventListener('click', async () => {
    const csv = ['Item,Detail', ...items.map(i => [i.t, i.d || ''].map(csvCell).join(','))].join('\n');
    const saved = await window.portal.exportCsv({ name: `${(m && m.environment && m.environment.Name) || 'portal'}-${title}`.replace(/[^\w-]+/g, '-').slice(0, 80), csv });
    if (saved) $('statusLine').textContent = `Saved ${saved}`;
  });
  setTimeout(() => $('drQ').focus(), 30);
}
function closeDrawer() { const d = document.getElementById('drawer'); if (d) { d.remove(); modalOff(); } }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

// ---------- Pop-out tiles (details.pt) ----------
// One open at a time; the pop-out flips to the left near the window's right edge; Esc or a click elsewhere closes it.
document.addEventListener('toggle', e => {
  const d = e.target;
  if (!(d instanceof HTMLDetailsElement) || !d.classList.contains('pt') || !d.open || document.body.classList.contains('printing')) return;
  document.querySelectorAll('details.pt[open]').forEach(o => { if (o !== d) o.open = false; });
  const pop = d.querySelector('.pt-pop'); if (!pop) return;
  pop.classList.remove('flip');
  if (pop.getBoundingClientRect().right > window.innerWidth - 16) pop.classList.add('flip');
}, true);
document.addEventListener('click', e => {
  if (document.body.classList.contains('printing') || e.target.closest('details.pt')) return;
  document.querySelectorAll('details.pt[open]').forEach(o => { o.open = false; });
});
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  const open = document.querySelector('details.pt[open]');
  if (open) { open.open = false; open.querySelector('summary').focus(); }
});

// "Show which ones" on a metric that only reports a number: Liongard's own query for it, run without the count, lists the items.
document.addEventListener('click', async e => {
  const b = e.target.closest('.mi-look'); if (!b) return;
  const label = b.textContent; b.disabled = true; b.textContent = 'Asking Liongard…';
  try {
    const r = await window.portal.metricItems({ metric: b.dataset.m, systemDetailId: +b.dataset.sd });
    openDrawer(b.dataset.t, r.error ? b.dataset.s : `${b.dataset.s} · from Liongard query ${r.query}`,
      r.error ? [{ t: 'Not available', d: r.error, sev: 'info' }] : r.items.map(t => ({ t })), null);
  } catch (err) { openDrawer(b.dataset.t, b.dataset.s, [{ t: 'Couldn’t read this from Liongard', d: cleanErr(err), sev: 'info' }], null); }
  finally { b.disabled = false; b.textContent = label; }
});

// ---------- Long pages: "On this page" bar and collapsible sections ----------
// Every top-level heading (an <h3> directly in the page body) becomes a section that folds. A bar of chips at the top
// jumps to a section (opening it), with Collapse all / Expand all. Folded sections are remembered per page; PDFs print all.
function sectionize(root, pageId) {
  const heads = [...root.children].filter(el => el.tagName === 'H3');
  if (heads.length < 2) return;
  const key = `sections:${pageId}`;
  let folded = []; try { folded = JSON.parse(localStorage.getItem(key) || '[]'); } catch {}
  const save = () => { try { localStorage.setItem(key, JSON.stringify([...root.querySelectorAll('.psec.folded')].map(s => s.dataset.id))); } catch {} };
  const slug = t => t.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'section';
  const secs = heads.map((h, i) => {
    const sec = document.createElement('section'); sec.className = `psec${h.classList.contains('msp') ? ' msp' : ''}`; sec.dataset.id = slug(h.textContent);   // an internal section stays internal in Present
    sec.id = `sec-${sec.dataset.id}`;
    const body = document.createElement('div'); body.className = 'psec-body';
    h.before(sec);
    let n = h.nextSibling;
    // Print-only blocks (.review-only) stay at the top level: print-review hides everything else at that level.
    while (n && !(n.nodeType === 1 && n.tagName === 'H3' && heads.includes(n))) { const next = n.nextSibling; if (!(n.nodeType === 1 && n.classList.contains('review-only'))) body.append(n); n = next; }
    h.style.marginTop = '';
    // the heading stays a heading; a button inside it folds the section. A heading that already holds a control
    // gets a separate small button, since controls can't nest.
    h.classList.add('psec-h');
    body.id = `${sec.id}-body`;
    const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'psec-btn'; btn.setAttribute('aria-expanded', 'true'); btn.setAttribute('aria-controls', body.id);
    if (h.querySelector('a,button,input,select')) { btn.innerHTML = `<span class="psec-arrow" aria-hidden="true"></span><span class="sr-only">Fold or unfold: ${esc(h.textContent.trim())}</span>`; h.prepend(btn); }
    else { btn.append(...h.childNodes); btn.insertAdjacentHTML('afterbegin', '<span class="psec-arrow" aria-hidden="true"></span>'); h.append(btn); }
    sec.append(h, body);
    if (folded.includes(sec.dataset.id)) { sec.classList.add('folded'); btn.setAttribute('aria-expanded', 'false'); }
    const toggle = () => { const f = sec.classList.toggle('folded'); btn.setAttribute('aria-expanded', String(!f)); save(); };
    btn.addEventListener('click', toggle);
    h.addEventListener('click', e => { if (e.target === h) toggle(); });   // the rest of the heading row, for the mouse
    return sec;
  });
  const bar = document.createElement('nav'); bar.className = 'onpage no-print'; bar.setAttribute('aria-label', 'On this page');
  bar.innerHTML = `<span class="onpage-h">On this page</span>${secs.map(s => `<button type="button" class="onpage-c" data-to="${s.id}">${esc(s.querySelector('.psec-h').textContent.trim())}</button>`).join('')}
    <span class="onpage-sp"></span><button type="button" class="linkbtn" data-all="fold">Collapse all</button><button type="button" class="linkbtn" data-all="open">Expand all</button>`;
  secs[0].before(bar);
  bar.addEventListener('click', e => {
    const c = e.target.closest('[data-to]'), a = e.target.closest('[data-all]');
    if (c) { const s = document.getElementById(c.dataset.to); s.classList.remove('folded'); s.querySelector('.psec-btn').setAttribute('aria-expanded', 'true'); save(); s.scrollIntoView({ behavior: SMOOTH(), block: 'start' }); }
    if (a) { secs.forEach(s => { s.classList.toggle('folded', a.dataset.all === 'fold'); s.querySelector('.psec-btn').setAttribute('aria-expanded', String(a.dataset.all !== 'fold')); }); save(); }
  });
}

// ---------- Remediation list (Compliance drill-down items), shown on Compliance and the Action plan ----------
// Each item is one person, device, domain or firewall to fix. Status is the MSP's; `state` adds what Liongard's data says.
const REM_STATE = { open: ['bad', 'Still found'], progress: ['bad', 'Still found'], awaiting: ['warn', 'Awaiting next pull'], verified: ['ok', 'Verified fixed'], fixed: ['ok', 'No longer found'], reopened: ['bad', 'Reopened: still found'] };
const REM_WHY = { open: 'Liongard’s latest data still finds this', progress: 'Liongard’s latest data still finds this', awaiting: 'Waiting for the next data pull to confirm', verified: 'Marked done, and Liongard no longer finds it', fixed: 'Liongard no longer finds it (nobody marked it done)', reopened: 'Marked done, but Liongard’s newer data still finds it' };
function remTableHtml(list, ctx) {
  if (!list.length) return '<p class="sub">Nothing on the remediation list yet. On Compliance at a glance, click a heat map cell, a radar area or a matrix row, then use “+ Remediation list” on the people, devices or network gear that need fixing.</p>';
  return `<div class="tw"><table class="rem-t"><thead><tr><th>Item</th><th>Problem</th><th>Severity</th><th>Owner</th><th>Due</th><th>Status</th><th>Liongard says</th></tr></thead><tbody>${list.map(r => {
    const st = REM_STATE[r.state] || REM_STATE[r.status] || REM_STATE.open;
    const over = r.due && r.status !== 'done' && r.due < new Date().toISOString().slice(0, 10);
    return `<tr data-rid="${esc(r.id)}">
    <td class="wrap"><span class="cp-kind">${esc(r.kind)}</span> <b>${r.link && ctx ? lgA(lgFor(ctx, r.link), esc(r.t)) : esc(r.t)}</b>${r.d ? `<div class="sub" style="margin:0" title="${esc(r.d)}">${esc(r.d.length > 110 ? `${r.d.slice(0, 108)}…` : r.d)}</div>` : ''}</td>
    <td class="wrap">${esc(r.checkName || r.check)}</td>
    <td data-csv="${esc(r.sev)}"><span class="present-only">${esc(r.sev)}</span><select class="msp" data-rf="sev" aria-label="Severity">${['Critical', 'High', 'Medium', 'Low'].map(s => `<option${s === r.sev ? ' selected' : ''}>${s}</option>`).join('')}</select></td>
    <td data-csv="${esc(r.owner || '')}"><span class="present-only">${esc(r.owner || '')}</span><input class="msp" data-rf="owner" type="text" value="${esc(r.owner || '')}" placeholder="Name" maxlength="80" aria-label="Owner"></td>
    <td data-csv="${esc(r.due || '')}"><span class="present-only">${esc(r.due ? fmtDate(r.due, true) : '')}</span><input class="msp" data-rf="due" type="date" value="${esc(r.due || '')}" aria-label="Due date">${over ? '<div class="sub cp-stale" style="margin:0">Overdue</div>' : ''}</td>
    <td data-csv="${esc({ open: 'Open', progress: 'In progress', done: 'Done' }[r.status])}"><span class="present-only">${esc({ open: 'Open', progress: 'In progress', done: 'Done' }[r.status] || '')}</span><select class="msp" data-rf="status" aria-label="Status">${[['open', 'Open'], ['progress', 'In progress'], ['done', 'Done']].map(([k, l]) => `<option value="${k}"${k === r.status ? ' selected' : ''}>${l}</option>`).join('')}</select></td>
    <td data-csv="${esc(st[1])}"><span class="cp-tag t-${st[0]}" title="${esc(REM_WHY[r.state] || '')}">${esc(st[1])}</span>${r.seenAt ? `<div class="sub" style="margin:2px 0 0">${esc(fmtDate(r.seenAt, true))}</div>` : ''}<div class="no-print"><button type="button" class="linkish" data-rdel>Remove</button></div></td></tr>`; }).join('')}</tbody></table></div>`;
}
// Saves each change straight away; `after` runs once a change is saved (for example to redraw counts).
function wireRemTable(root, after) {
  const save = async (tr, patch) => {
    try { await window.portal.updateRemediation({ id: tr.dataset.rid, ...patch }); if (after) after(); }
    catch (err) { $('statusLine').textContent = `Couldn’t save: ${cleanErr(err)}`; }
  };
  root.addEventListener('change', e => { const el = e.target.closest('[data-rf]'); if (el) save(el.closest('tr'), { [el.dataset.rf]: el.value }); });
  root.addEventListener('click', e => { const b = e.target.closest('[data-rdel]'); if (b) save(b.closest('tr'), { remove: true }); });
}
