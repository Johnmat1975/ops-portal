// Top bar and app-wide chrome: the client switcher, the Light / System / Dark switch,
// the ⌘K / Ctrl K command bar, the client health ribbon, "Present to client", launcher and side-menu
// status and the Overview delta chips. Loaded after shared.js, before the page's own script.
// Nothing here calls Liongard: badges, dots and the ribbon come only from models already cached on this computer.
// The pure helpers at the top have no DOM access, so the tests can run them on their own.

const CH_THEME_KEY = 'lg-portal-theme';

// Light / System / Dark. 'system' clears the stored override, so the page follows the operating system again.
function themeApply(t, root, store) {
  const v = t === 'light' || t === 'dark' ? t : 'system';
  if (v === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', v);
  try { if (v === 'system') store.removeItem(CH_THEME_KEY); else store.setItem(CH_THEME_KEY, v); } catch {}
  return v;
}
function themePref(store) {
  let t = null; try { t = store.getItem(CH_THEME_KEY); } catch {}
  return t === 'light' || t === 'dark' ? t : 'system';
}

// Where to land after switching client: the same page (panel.html?id=…), without anything client-specific (?q=, #…).
function switchHref(href) {
  let u; try { u = new URL(href); } catch { return 'index.html'; }
  const file = u.pathname.split('/').pop() || 'index.html';
  if (file === 'panel.html') { const id = u.searchParams.get('id'); return id && /^[a-z-]+$/.test(id) ? `panel.html?id=${id}` : 'index.html'; }
  if (file === 'settings.html') return 'settings.html';
  return 'index.html';
}

// One short status for a page, from its model's KPI tiles: the first problem, else the first thing to review, else
// "All clear" when a tile was actually checked. A tile with no evidence ("—") never turns into an all-clear.
function pageBadge(m) {
  // A page can set its own badge (Compliance: "Set client profile", or distinct failing checks).
  if (m && m.badge && typeof m.badge.text === 'string' && ['act', 'review', 'ok', 'none'].includes(m.badge.tone)) return { text: m.badge.text, tone: m.badge.tone };
  if (m && m.badge === null) return null;
  const kpis = m && Array.isArray(m.kpis) ? m.kpis : [];
  if (!kpis.length) return null;
  const num = v => (typeof v === 'number' ? v : typeof v === 'string' && /^\s*\d/.test(v) ? parseFloat(v) : NaN);
  const plain = v => typeof v === 'number' || /^\s*\d+\s*$/.test(String(v));   // "3", not "9 / 39" or "82%"
  // A plain count reads best on a badge ("Admins without MFA: 2"); a ratio ("Meet policy: 9 / 39") only if there's no count.
  const first = sev => kpis.find(k => k.sev === sev && plain(k.v) && num(k.v) > 0) || kpis.find(k => k.sev === sev && num(k.v) > 0);
  const label = k => `${k.k}: ${k.v}`;
  const bad = first('bad'); if (bad) return { text: label(bad), tone: 'act' };
  const warn = first('warn'); if (warn) return { text: label(warn), tone: 'review' };
  const none = first('none'); if (none) return { text: label(none), tone: 'none' };
  if (kpis.some(k => k.v === '—' || k.v == null)) return null;
  return kpis.some(k => k.sev === 'ok') ? { text: 'All clear', tone: 'ok' } : null;
}

// Calm the red: a launcher badge is red only when that page holds an open Critical or High action;
// otherwise a problem count shows amber. `hot` is the set of pages with one (from the cached Action plan), or null.
function hotPages(actionsModel) {
  if (!actionsModel || !Array.isArray(actionsModel.actions)) return null;
  const pages = new Set(actionsModel.actions.filter(a => ['open', 'progress', 'ticketed'].includes(a.status) && (a.risk === 'critical' || a.risk === 'high')).map(a => a.page));
  if (pages.size) { pages.add('overview'); pages.add('actions'); }
  return pages;
}
function calmBadge(id, b, hot) {
  if (!b || b.tone !== 'act') return b;
  return hot && hot.has(id) ? b : { ...b, tone: 'review' };
}
// Side-menu dots: only for pages behind an Overview area that is "Act now". Nothing for Review.
function navDots(areas) {
  const out = {};
  for (const a of areas || []) if (a && a.state === 'act' && a.page) (out[a.page] = out[a.page] || []).push(a.t);
  return out;
}

// Overview counts and the change since the last different snapshot (delta chips). Kept per instance and client.
function ovCounts(m) {
  const out = {};
  for (const k of (m && m.kpis) || []) if (typeof k.v === 'number') out[k.k] = k.v;
  return out;
}
function ovSnapNext(stored, counts, at) {
  const cur = stored && stored.cur;
  const keys = o => Object.keys(o || {}).sort().join('|');
  const same = cur && keys(cur.counts) === keys(counts) && Object.keys(counts).every(k => cur.counts[k] === counts[k]);
  if (same) return stored;   // unchanged: keep the baseline, so the chip still says what changed and since when
  return { prev: cur || null, cur: { at, counts } };
}
function sinceLabel(iso, now = Date.now()) {
  const d = new Date(iso); if (isNaN(d)) return '';
  const hrs = (now - d) / 36e5;
  if (hrs < 20 && new Date(now).toDateString() === d.toDateString()) return `since ${d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`;
  if (hrs < 6.5 * 24) return `since ${d.toLocaleDateString('en-GB', { weekday: 'short' })}`;
  return `since ${d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}`;
}
function ovDeltas(stored, now) {
  if (!stored || !stored.prev || !stored.cur) return {};
  const out = {};
  for (const [k, v] of Object.entries(stored.cur.counts)) {
    const p = stored.prev.counts[k];
    if (typeof p === 'number') out[k] = { d: v - p, since: sinceLabel(stored.prev.at, now) };
  }
  return out;
}
const CH_BETTER_UP = ['Looks fine'];   // tiles where a rise is good news

// Switcher for many clients: recent clients first (kept per instance on this computer), the
// rest by name; each with its last-known state from the Overview cached on this computer, and the age of that data.
function orderClients(list, recent) {
  const pos = new Map((recent || []).map((id, i) => [String(id), i]));
  const rec = list.filter(e => pos.has(String(e.ID))).sort((a, b) => pos.get(String(a.ID)) - pos.get(String(b.ID)));
  const rest = list.filter(e => !pos.has(String(e.ID))).sort((a, b) => String(a.Name).localeCompare(String(b.Name)));
  return { recent: rec, rest };
}
function recentNext(recent, id, max = 8) { return [String(id), ...(recent || []).map(String).filter(x => x !== String(id))].slice(0, max); }
function dataAge(iso, now = Date.now()) {
  const d = new Date(iso); if (!iso || isNaN(d)) return '';
  const h = (now - d) / 36e5;
  return h < 1 ? 'under an hour old' : h < 48 ? `${Math.round(h)} h old` : `${Math.round(h / 24)} days old`;
}
function stateHint(st, now) {
  if (!st) return '';
  const what = st.act ? `Act now: ${st.act}` : st.review ? `Review: ${st.review}` : st.unknown ? 'Couldn’t read' : 'Looks fine';
  return [what, dataAge(st.pulledOn, now) && `data ${dataAge(st.pulledOn, now)}`].filter(Boolean).join(' · ');
}
// Worst first: most Act now areas, then most Review, then the oldest data (Settings › Clients).
const worstFirst = (a, b) => (b.act - a.act) || (b.review - a.review) || (b.unknown - a.unknown) || String(a.pulledOn || '').localeCompare(String(b.pulledOn || ''));

// Initials for the client avatar: "Northwind Demo" -> "ND".
const chInitials = name => (String(name || '').match(/[A-Za-z0-9]+/g) || ['?']).slice(0, 2).map(w => w[0].toUpperCase()).join('');

// ------------------------------------------------------------------------------------------------------------------
// Everything below touches the page.
let CH = { s: null, envs: null, sel: 0, items: [], loadingEnvs: false, states: null };
const chSafe = (fn, d) => { try { return fn(); } catch { return d; } };
// Present to client is a hard client-safe mode: no client list, no switcher, no ⌘K, no internal controls or links.
const chPresenting = () => typeof document !== 'undefined' && !!document.body && document.body.classList.contains('present');
const chKey = s => (s && s.env ? `${s.instance}|${s.env.ID}` : '');
const chSess = { get: (k, d) => chSafe(() => JSON.parse(sessionStorage.getItem(k) || 'null'), null) ?? d, set: (k, v) => chSafe(() => sessionStorage.setItem(k, JSON.stringify(v))) };
const chLocal = { get: (k, d) => chSafe(() => JSON.parse(localStorage.getItem(k) || 'null'), null) ?? d, set: (k, v) => chSafe(() => localStorage.setItem(k, JSON.stringify(v))) };

// ---------- Theme switch ----------
function paintTheme() {
  const t = themePref(localStorage);
  document.querySelectorAll('#themeSw [data-theme]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.theme === t)));
  document.querySelectorAll('#themeSeg [data-v]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === t)));   // Settings › Appearance
}
function setTheme(t) { themeApply(t, document.documentElement, localStorage); paintTheme(); }

// ---------- Present to client ----------
function setPresent(on) {
  document.body.classList.toggle('present', on);
  document.body.classList.remove('nav-open');
  chSafe(() => { if (on) sessionStorage.setItem('lg-present', '1'); else sessionStorage.removeItem('lg-present'); });
  const b = $('presentBtn');
  if (b) { b.setAttribute('aria-pressed', String(on)); b.querySelector('span').textContent = on ? 'Exit present' : 'Present'; b.title = on ? 'Leave present mode (Esc)' : 'Present to client: hides the menu, client list and internal controls'; }
  // The switcher can't be used while presenting, so it leaves the tab order too.
  const sw = $('switcher'); if (sw) { sw.tabIndex = on ? -1 : 0; sw.setAttribute('aria-disabled', String(!!on)); }
  if (on) { closeCmd(); if (typeof closeDrawer === 'function') closeDrawer(); }
  if (window.VIEWS && window.VIEWS.wallboard && window.VIEWS.wallboard._fit) setTimeout(() => window.VIEWS.wallboard._fit(), 50);
}

// ---------- Settings arrive (every page, from paintHeader) ----------
const chRecentKey = s => `lg-recent:${s && s.instance}`;
function chromeSettings(s) {
  CH.s = s;
  if (s && s.env) chLocal.set(chRecentKey(s), recentNext(chLocal.get(chRecentKey(s), []), s.env.ID));
  const sw = $('switcher');
  if (sw) {
    sw.disabled = !s.hasKey;
    $('swAv').textContent = s.env ? chInitials(s.env.Name) : '';
    $('swAv').hidden = !s.env;
    paintMeta();
  }
  // Pages that already have the Overview model in hand paint the ribbon themselves; others read the cached one.
  const page = document.body.dataset.page;
  if (s.ready && page !== 'home' && page !== 'overview' && window.portal && window.portal.cachedPanel) {
    window.portal.cachedPanel('overview').then(m => { if (m && CH.s === s) chromeModel('overview', m, { ribbonOnly: true }); }).catch(() => {});
  }
  if (typeof decorateNav === 'function') decorateNav();
}
function paintMeta() {
  const s = CH.s, el = $('swMeta'); if (!el || !s) return;
  if (!s.hasKey) { el.textContent = 'Not connected'; return; }
  if (!s.env) { el.textContent = 'Pick a client'; return; }
  const tools = chSess.get(`lg-tools:${chKey(s)}`, null), age = dataAge(chSess.get(`lg-age:${chKey(s)}`, null));
  // The age of the data on screen, not a position in Liongard's client list.
  el.textContent = [age ? `Data ${age}` : 'Switch client', tools != null ? `${tools} tool${tools === 1 ? '' : 's'} connected` : ''].filter(Boolean).join(' · ');
}
// Remembered for this session so the switcher can list clients without asking Liongard again.
function chromeEnvs(instance, list) { chSess.set('lg-envs', { instance, list: (list || []).map(e => ({ ID: e.ID, Name: e.Name })) }); CH.envs = null; paintMeta(); }
function chromeTools(s, n) { if (chKey(s)) chSess.set(`lg-tools:${chKey(s)}`, n); paintMeta(); }

// ---------- A page model arrived: freshness, badges, ribbon, deltas ----------
// opts.ribbonOnly: from the cached Overview on another page (don't touch that page's freshness pill).
function chromeModel(id, m, opts = {}) {
  if (!m) return;
  const key = chKey(CH.s) || (m.instance && m.envId ? `${m.instance}|${m.envId}` : '');
  if (key) {
    const store = chSess.get(`lg-badges:${key}`, {});
    const b = pageBadge(m);
    if (b) store[id] = { ...b, ...(id === 'actions' ? { count: (m.kpis.find(k => k.k === 'Open actions') || {}).v } : {}) }; else delete store[id];
    chSess.set(`lg-badges:${key}`, store);
  }
  if (key && m.pulledOn) { chSess.set(`lg-age:${key}`, m.pulledOn); paintMeta(); }
  if (id === 'overview') { paintRibbon(m); if (key) chSess.set(`lg-areas:${key}`, (m.areas || []).map(a => ({ page: a.page, state: a.state, t: a.t }))); }
  if (!opts.ribbonOnly && !opts.badgeOnly) paintFresh(m.pulledOn);
  if (id === 'overview' && document.body.dataset.page === 'overview' && !opts.badgeOnly) paintDeltas(m, key);
  decorateNav();
}
function chromeForget(id) {
  const key = chKey(CH.s); if (!key) return;
  const store = chSess.get(`lg-badges:${key}`, {}); delete store[id]; chSess.set(`lg-badges:${key}`, store);
}
function paintFresh(iso) {
  const el = $('fresh'); if (!el) return;
  const d = new Date(iso); if (!iso || isNaN(d)) { el.hidden = true; return; }
  const h = (Date.now() - d) / 36e5, local = typeof tzPref === 'function' && tzPref() === 'local';
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', ...(local ? {} : { timeZone: 'UTC' }) }) + (local ? '' : ' UTC');
  el.hidden = false;
  el.classList.toggle('old', h >= 24);
  $('freshText').textContent = h < 24 ? `Fresh · ${time}` : `Pulled ${h < 48 ? `${Math.round(h)} hours` : `${Math.round(h / 24)} days`} ago`;
  el.title = `Data pulled ${typeof fmtWhen === 'function' ? fmtWhen(iso) : d.toISOString()}`;
}
// The ribbon sits on the navy bar in both themes, so it has its own fixed colours, and a second cue per state:
// height (tall = Act now, medium = Review, short = Looks fine), dotted = Couldn't read, hatched = Not covered.
const CH_STATE = { act: ['var(--rb-act)', 'Act now'], review: ['var(--rb-review)', 'Review'], ok: ['var(--rb-ok)', 'Looks fine'], none: ['', 'Not covered'], unknown: ['var(--rb-blind)', 'Couldn’t read'] };
function paintRibbon(m) {
  const el = $('ribbon'); if (!el) return;
  const areas = (m && m.areas) || [];
  el.hidden = !areas.length;
  el.innerHTML = areas.map(a => { const [c, l] = CH_STATE[a.state] || CH_STATE.unknown;
    const s = CH_STATE[a.state] ? a.state : 'unknown';
    return `<a href="panel.html?id=${esc(a.page)}" class="${s === 'none' ? 'none' : ''}" data-s="${s}" style="--rb:${c}" title="${esc(a.t)}: ${esc(l)}" aria-label="${esc(a.t)}: ${esc(l)}"></a>`; }).join('');
  el.title = 'Tall red: Act now · medium amber: Review · short green: Looks fine · dotted: Couldn’t read · hatched: Not covered';
}
function paintDeltas(m, key) {
  if (!key) return;
  const k = `lg-ov-snap:${key}`;
  const next = ovSnapNext(chLocal.get(k, null), ovCounts(m), new Date().toISOString());
  chLocal.set(k, next);
  const deltas = ovDeltas(next);
  document.querySelectorAll('#panelBody .kpi[data-k]').forEach(el => {
    const x = deltas[el.dataset.k], v = el.querySelector('.v'); if (!x || !v || v.querySelector('.delta')) return;
    const better = CH_BETTER_UP.includes(el.dataset.k) ? x.d > 0 : x.d < 0;
    // the direction has a glyph, and whether it's good news is said in words, not only in colour.
    v.insertAdjacentHTML('beforeend', `<span class="delta ${x.d === 0 ? '' : better ? 'better' : 'worse'}" title="Change since this page last showed different numbers">${x.d === 0 ? 'no change' : `<span aria-hidden="true">${x.d > 0 ? '▲' : '▼'}</span> ${x.d > 0 ? '+' : '−'}${Math.abs(x.d)} ${esc(x.since)}<span class="sr-only">, ${better ? 'better' : 'worse'}</span>`}</span>`);
  });
}

// ---------- Side menu status: a dot per page and the open count on the Action plan ----------
function decorateNav() {
  const nav = document.getElementById('sideNav'); if (!nav || !CH.s) return;
  const store = chSess.get(`lg-badges:${chKey(CH.s)}`, {});
  const dots = navDots(chSess.get(`lg-areas:${chKey(CH.s)}`, []));
  nav.querySelectorAll('a[data-id]').forEach(a => {
    a.querySelectorAll('.nv-dot,.nv-cnt,.nv-sr').forEach(n => n.remove());
    const b = store[a.dataset.id];
    if (a.dataset.id === 'actions' && b && typeof b.count === 'number' && b.count > 0) a.insertAdjacentHTML('beforeend', `<span class="nv-cnt" aria-hidden="true">${b.count}</span><span class="sr-only nv-sr">: ${b.count} open</span>`);
    else if (dots[a.dataset.id]) a.insertAdjacentHTML('beforeend', `<span class="nv-dot act" aria-hidden="true" title="Act now: ${esc(dots[a.dataset.id].join(', '))}"></span><span class="sr-only nv-sr">: Act now</span>`);
  });
}

// ---------- Command bar ----------
function chPages() {
  const ready = CH.s && CH.s.ready;
  return [{ t: 'Portal home', href: 'index.html' },
    ...GROUPS.flatMap(g => g.items.map(x => ({ t: x.t, g: g.g === 'About this app' ? 'Settings' : g.g, href: ready ? `panel.html?id=${x.id}` : 'index.html' }))),
    { t: 'Settings', href: 'settings.html' }];
}
function cmdItems(q) {
  q = q.trim().toLowerCase();
  const hit = t => !q || t.toLowerCase().includes(q);
  const out = [];
  const s = CH.s || {};
  if (chPresenting()) return [{ none: 'Not available while presenting' }];   // never list clients (or anything) on a shared screen
  if (s.hasKey) {
    const envs = chSess.get('lg-envs', null);
    const list = envs && envs.instance === s.instance ? envs.list : null;
    const only = CH.mode === 'clients';   // the client dropdown lists every client and nothing else
    const { recent, rest } = orderClients(list ? list.filter(e => hit(e.Name)) : [], chLocal.get(chRecentKey(s), []));
    const cap = only ? Infinity : q ? 8 : 6;
    const rec = recent.slice(0, cap), cl = rest.slice(0, Math.max(0, cap - rec.length));
    const states = CH.states || {};
    const item = e => ({ t: e.Name, hint: [s.env && String(s.env.ID) === String(e.ID) ? 'Current client' : '', stateHint(states[e.ID]) || (only ? '' : 'Switch client, stay on this page')].filter(Boolean).join(' · '), env: e, tone: states[e.ID] ? (states[e.ID].act ? 'act' : states[e.ID].review ? 'review' : '') : '' });
    if (rec.length) { out.push({ grp: 'Recent clients' }); rec.forEach(e => out.push(item(e))); }
    if (cl.length || (CH.loadingEnvs && !rec.length)) out.push({ grp: rec.length ? 'Other clients' : 'Clients' });
    if (!list && CH.loadingEnvs) out.push({ none: 'Loading clients…' });
    cl.forEach(e => out.push(item(e)));
    if (only) { if (!out.some(x => !x.grp && !x.none) && !CH.loadingEnvs) out.push({ none: 'No client matches' }); return out; }
  }
  const pg = chPages().filter(p => hit(p.t)).slice(0, q ? 8 : 20);
  if (pg.length) { out.push({ grp: 'Pages' }); pg.forEach(p => out.push({ t: p.t, hint: p.g || 'Open', href: p.href })); }
  if (q && s.ready) { out.push({ grp: 'Lookup' }); out.push({ t: `Look up “${q}”`, hint: 'Person, device or domain', href: `panel.html?id=lookup&q=${encodeURIComponent(q)}` }); }
  if (!out.some(x => !x.grp && !x.none)) out.push({ none: 'Nothing matches' });
  return out;
}
function drawCmd() {
  const q = $('cmdQ').value;
  CH.items = cmdItems(q);
  const opts = CH.items.filter(x => !x.grp && !x.none);
  CH.sel = Math.min(Math.max(0, CH.sel), Math.max(0, opts.length - 1));
  let n = -1, grp = '';
  // group headings are visual only; each option carries its group in its accessible name.
  $('cmdL').innerHTML = CH.items.map(x => {
    if (x.grp) { grp = x.grp; return `<li class="grp" role="presentation" aria-hidden="true">${esc(x.grp)}</li>`; }
    if (x.none) return `<li class="none" role="presentation">${esc(x.none)}</li>`;
    n++;
    return `<li class="opt${x.tone ? ` tone-${x.tone}` : ''}" role="option" id="cmdo-${n}" data-n="${n}" aria-selected="${n === CH.sel}"><span>${grp ? `<span class="sr-only">${esc(grp)}: </span>` : ''}${esc(x.t)}</span><small>${esc(x.hint || '')}</small></li>`;
  }).join('');
  // no empty IDREF when nothing matches, and the number of results is announced as you type.
  if (opts.length) $('cmdQ').setAttribute('aria-activedescendant', `cmdo-${CH.sel}`); else $('cmdQ').removeAttribute('aria-activedescendant');
  if ($('cmdN')) $('cmdN').textContent = `${opts.length} result${opts.length === 1 ? '' : 's'}`;
  const cur = document.getElementById(`cmdo-${CH.sel}`); if (cur) cur.scrollIntoView({ block: 'nearest' });
}
async function runCmd(n) {
  const x = CH.items.filter(i => !i.grp && !i.none)[n]; if (!x) return;
  if (x.env) {
    const s = CH.s || {};
    if (s.env && String(s.env.ID) === String(x.env.ID)) { closeCmd(); return; }
    await window.portal.selectEnvironment({ ID: x.env.ID, Name: x.env.Name });
    location.href = switchHref(location.href);
    return;
  }
  location.href = x.href;
}
function ensureCmd() {
  if ($('cmdk')) return;
  const d = document.createElement('div');
  d.id = 'cmdk'; d.className = 'cmdk no-print'; d.hidden = true;
  d.innerHTML = `<div class="box" role="dialog" aria-modal="true" aria-label="Jump to"><div class="sr-only" role="status" id="cmdN"></div><input id="cmdQ" type="text" role="combobox" aria-expanded="true" aria-controls="cmdL" aria-autocomplete="list" autocomplete="off" spellcheck="false" placeholder="Jump to a client or a page, or look up a person, device or domain…" aria-label="Jump to">
    <ul id="cmdL" role="listbox" aria-label="Results"></ul><div class="foot"><span>↑ ↓ move</span><span>Enter open</span><span>Esc close</span></div></div>`;
  document.body.append(d);
  d.addEventListener('mousedown', e => { if (e.target === d) closeCmd(); });
  $('cmdQ').addEventListener('input', () => { CH.sel = 0; drawCmd(); });
  $('cmdQ').addEventListener('keydown', e => {
    const n = CH.items.filter(i => !i.grp && !i.none).length;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); CH.sel = (CH.sel + (e.key === 'ArrowDown' ? 1 : -1) + n) % Math.max(1, n); drawCmd(); }
    else if (e.key === 'Enter') { e.preventDefault(); runCmd(CH.sel).catch(err => { $('statusLine') && ($('statusLine').textContent = `Couldn’t switch client: ${cleanErr(err)}`); }); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeCmd(); }
    else if (e.key === 'Tab') e.preventDefault();   // keep focus in the dialog
  });
  $('cmdL').addEventListener('mousedown', e => { const li = e.target.closest('li[data-n]'); if (li) { e.preventDefault(); runCmd(+li.dataset.n).catch(() => {}); } });
}
// mode 'clients' (the top-bar dropdown): only the client list. 'all' (⌘K / Ctrl K): clients, pages and lookup.
function openCmd(mode) {
  if (chPresenting() || !CH.s || !CH.s.hasKey) return;
  ensureCmd();
  CH.mode = mode === 'clients' ? 'clients' : 'all';
  const clients = CH.mode === 'clients';
  $('cmdQ').placeholder = clients ? 'Search clients…' : 'Jump to a client or a page, or look up a person, device or domain…';
  $('cmdk').querySelector('.box').setAttribute('aria-label', clients ? 'Switch client' : 'Jump to');
  $('cmdk').hidden = false; if (typeof modalOn === 'function') modalOn($('cmdk')); $('cmdQ').value = ''; CH.sel = 0; drawCmd(); $('cmdQ').focus();
  // The client list is only fetched when someone opens the switcher (it's a Liongard call), then kept for the session.
  const envs = chSess.get('lg-envs', null);
  if ((!envs || envs.instance !== CH.s.instance) && !CH.loadingEnvs && window.portal) {
    CH.loadingEnvs = true; drawCmd();
    window.portal.environments().then(list => { chromeEnvs(CH.s.instance, list); loadStates(); }).catch(() => {}).finally(() => { CH.loadingEnvs = false; if (!$('cmdk').hidden) drawCmd(); });
  } else loadStates();
}
// Last-known state per client, from each client's Overview cached on this computer (never a Liongard call). Recent
// clients first; kept for the session so the next page opens with them.
let statesRun = 0;
async function loadStates() {
  const s = CH.s; if (!s || !window.portal || !window.portal.cachedPanel) return;
  const envs = chSess.get('lg-envs', null); if (!envs || envs.instance !== s.instance) return;
  const sk = `lg-states:${s.instance}`;
  CH.states = { ...chSess.get(sk, {}), ...(CH.states || {}) };
  const run = ++statesRun;
  const { recent, rest } = orderClients(envs.list, chLocal.get(chRecentKey(s), []));
  for (const e of [...recent, ...rest]) {
    let st = null; try { st = await window.portal.cachedPanel('overview', e.ID); } catch {}
    if (run !== statesRun) return;
    if (st) CH.states[e.ID] = st; else delete CH.states[e.ID];
    chSess.set(sk, CH.states);
    if ($('cmdk') && !$('cmdk').hidden) drawCmd();
  }
}
// Focus goes back to whatever opened the bar (a table, a field, the switcher), or to the switcher.
function closeCmd() {
  const c = $('cmdk'); if (!c || c.hidden) return; c.hidden = true; statesRun++;
  const back = typeof modalOff === 'function' && modalOff();
  const sw = $('switcher'); if (!back && sw && !sw.disabled) sw.focus();
}

// ---------- Wiring ----------
function initChrome() {
  paintTheme();
  document.querySelectorAll('#themeSw [data-theme]').forEach(b => b.addEventListener('click', () => setTheme(b.dataset.theme)));
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', paintTheme);
  const mac = /Mac/i.test(navigator.platform || navigator.userAgent || '');
  if ($('swKbd')) $('swKbd').textContent = mac ? '⌘K' : 'Ctrl K';
  if ($('switcher')) { $('switcher').title = `Switch client (${mac ? '⌘K' : 'Ctrl K'} also jumps to any page)`; $('switcher').addEventListener('click', () => openCmd('clients')); }
  if ($('presentBtn')) $('presentBtn').addEventListener('click', () => setPresent(!document.body.classList.contains('present')));
  if (chSafe(() => sessionStorage.getItem('lg-present') === '1', false)) setPresent(true);
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && String(e.key || '').toLowerCase() === 'k') { e.preventDefault(); if (!chPresenting()) openCmd('all'); }
  });
  // Present: links to other pages and into Liongard do nothing (the client sees this client's page and nothing else).
  document.addEventListener('click', e => {
    if (!chPresenting()) return;
    const a = e.target.closest && e.target.closest('a.xp, a.lg, #ribbon a, #sideNav a, a.crumb-link, #launcher a.lc:not([data-client])');
    if (a) { e.preventDefault(); e.stopPropagation(); }
  }, true);
  // Esc leaves present mode, unless it's closing something else first (the drawer, the command bar, a pop-out or menu).
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || !document.body.classList.contains('present')) return;
    if (document.getElementById('drawer') || document.getElementById('cpDr') || ($('cmdk') && !$('cmdk').hidden) || document.querySelector('details.pt[open], details.menu[open], dialog[open]') || document.fullscreenElement) return;
    setPresent(false);
  }, true);
}
if (typeof document !== 'undefined' && document.getElementById) initChrome();
