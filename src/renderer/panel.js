// Generic panel page: panel.html?id=<panel>. Loads views/<panel>.js, which registers window.VIEWS[id].
const PANEL_ID = new URLSearchParams(location.search).get('id') || '';
window.VIEWS = window.VIEWS || {};
document.body.dataset.page = PANEL_ID;

// the intro shows its first sentence; the rest opens behind "How this is worked out".
const introParts = t => { const m = /^(.+?[.!?])\s+(?=[A-Z‘“(])/.exec(String(t || '')); return m ? [m[1], String(t).slice(m[0].length)] : [String(t || ''), '']; };

function loadView(id) {
  return new Promise((resolve, reject) => {
    if (!/^[a-z-]+$/.test(id)) return reject(new Error('Unknown panel.'));
    const s = document.createElement('script');
    s.src = `views/${id}.js`; s.onload = () => resolve(window.VIEWS[id]); s.onerror = () => reject(new Error(`No view for "${id}".`));
    document.body.appendChild(s);
  });
}

let VIEW, SETTINGS, CURRENT = null;   // CURRENT: the page model last drawn (for exports that build their own file)
const PAGE_LABEL = { overview: 'Overview', actions: 'Action plan', identity: 'Identity', coverage: 'Stack coverage', email: 'Email', network: 'Network', inspectors: 'Inspector health', changes: 'Change pulse', licences: 'Licences', lifecycle: 'Lifecycle', ai: 'AI usage', cyber: 'Cyber security', compliance: 'Compliance', wallboard: 'Wallboard', lookup: 'Lookup', stack: 'Customer stack', register: 'Function register' };
async function refreshAll() {
  $('refreshBtn').disabled = true;
  const off = window.portal.onRefreshProgress(p => { $('statusLine').textContent = `Pulling from Liongard: ${PAGE_LABEL[p.id] || p.id} (${p.n + 1} of ${p.of})…`; });
  try {
    const r = await window.portal.refreshAll();
    off();
    await load(false);
    if (r.failed.length) $('statusLine').textContent += ` · ${r.failed.length} page${r.failed.length > 1 ? 's' : ''} couldn’t refresh: ${r.failed.map(f => PAGE_LABEL[f.id] || f.id).join(', ')}`;
  } catch (err) { off(); $('statusLine').textContent = `Refresh failed: ${cleanErr(err)}`; }
  finally { $('refreshBtn').disabled = false; }
}
async function load(refresh) {
  $('refreshBtn').disabled = true;
  if (refresh) $('statusLine').textContent = 'Pulling from Liongard…';
  try {
    const m = await window.portal.panel(PANEL_ID, { refresh });
    $('exportMenu').hidden = false;
    CURRENT = m;
    const ctx = { instance: m.instance || SETTINGS.instance, envId: (m.environment && m.environment.ID) || m.envId };
    // Lists Liongard returned only in part are flagged, so a page never looks complete when it isn't.
    const cut = (m.truncated || []).length ? `<div class="card flag warn trunc"><p style="margin:0"><b>Partial data:</b> Liongard returned only part of ${esc(m.truncated.join(', '))}. Counts on this page may be low.</p></div>` : '';
    // Saved work (statuses, marks, remediation) that was damaged and set aside: say so on every page until it's dealt with.
    const warn = (m.warnings || []).length ? `<div class="card flag warn"><p style="margin:0"><b>Saved data:</b> ${esc(m.warnings.join(' '))}</p></div>` : '';
    $('panelBody').innerHTML = dataAgeNote(m.pulledOn) + warn + cut + VIEW.render(m, ctx) + moreSection(m.more, ctx);
    // Once the page is drawn, a fault in one extra (charts, filters, drill-downs) shouldn't blank the whole page.
    const safe = (what, fn) => { try { fn(); } catch (err) { console.error(what, err); } };
    if (VIEW.after) safe('after', () => VIEW.after(m, ctx));
    safe('kpis', () => wireKpis(VIEW, m, ctx));
    safe('chrome', () => chromeModel(PANEL_ID, m));   // freshness pill, this page's menu dot, Overview ribbon and deltas
    safe('csv', () => addCsvButtons($('panelBody'), `${m.environment.Name}-${VIEW.title}`));
    // ?q= from a link on another page: pre-fill the page's search box.
    const q = new URLSearchParams(location.search).get('q');
    const box = q && !VIEW.handlesQuery && document.querySelector('#panelBody .search input');
    if (box) { box.value = q; box.dispatchEvent(new Event('input')); }
    safe('how', () => { $('howBuilt').textContent = VIEW.how(m, ctx); });
    // Long pages: an "On this page" bar and sections that fold (not the wallboard, which fits one screen).
    if (!['wallboard', 'register'].includes(PANEL_ID)) safe('sections', () => sectionize($('panelBody'), PANEL_ID));
    $('statusLine').textContent = `Data pulled ${fmtWhen(m.pulledOn)}`;
    $('footer').textContent = `Built from the Liongard API for ${m.environment.Name}.`;
    $('footer').title = `Environment ID ${m.environment.ID}`;
  } catch (err) {
    // A failed refresh keeps the last good page on screen (a wallboard on a desk TV must not go blank after one blip).
    if (refresh && CURRENT) {
      $('statusLine').textContent = `Last refresh failed at ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} (${cleanErr(err)}). Showing data pulled ${fmtWhen(CURRENT.pulledOn)}.`;
      if (VIEW.retry) VIEW.retry();
      return;
    }
    $('exportMenu').hidden = true;   // nothing to export from an error card
    $('panelBody').innerHTML = `<div class="card state st-blind"><span class="st-ic" aria-hidden="true">!</span><div><h3>Couldn’t load this page</h3><p class="sub">${esc(cleanErr(err))}</p><p class="sub"><button type="button" class="btn ghost sm" id="retryBtn">Retry</button> <a href="index.html">Back to the portal page</a></p></div></div>`;
    if ($('retryBtn')) $('retryBtn').addEventListener('click', () => load(false));
    $('statusLine').textContent = '';
  } finally { $('refreshBtn').disabled = false; }
}

(async () => {
  SETTINGS = await paintHeader();
  if (!SETTINGS.ready) { location.href = 'index.html'; return; }   // no key or environment yet
  // The top bar shows just the client; the page's own title is in the header card below it.
  $('portalTitle').textContent = SETTINGS.env.Name; $('portalTitle').title = `${SETTINGS.env.Name} · Environment ID ${SETTINGS.env.ID}`;
  document.body.classList.add(`page-${PANEL_ID}`);   // lets a page adjust the shared layout (the wallboard drops the big header)
  paintNav(PANEL_ID);
  try { VIEW = await loadView(PANEL_ID); } catch (e) { $('panelBody').innerHTML = `<div class="card state st-blind"><span class="st-ic" aria-hidden="true">!</span><div><h3>${esc(e.message)}</h3><p class="sub"><a href="index.html">Back to the portal page</a></p></div></div>`; return; }
  // breadcrumb (client › group › page), a 24px title and a one-line intro.
  $('crumbHome').textContent = SETTINGS.env.Name; $('crumbHome').title = 'Portal home for this client';
  const grp = GROUPS.find(g => g.items.some(x => x.id === PANEL_ID));
  $('crumbGroup').textContent = grp ? (grp.g === 'About this app' ? 'Settings' : grp.g) : '';
  $('crumbPage').textContent = VIEW.title;
  $('panelTitle').textContent = VIEW.title;
  const [lead, more] = introParts(VIEW.intro);
  $('panelIntro').textContent = lead;
  if (more) {
    $('panelIntroMore').textContent = more;
    $('panelIntro').insertAdjacentHTML('beforeend', ' <button type="button" class="linkbtn" id="introMoreBtn" aria-expanded="false" aria-controls="panelIntroMore">How this is worked out</button>');
    $('introMoreBtn').addEventListener('click', e => { const open = $('panelIntroMore').hidden; $('panelIntroMore').hidden = !open; e.target.setAttribute('aria-expanded', String(open)); });
  }
  document.title = document.title.replace(/·.*$/, `· ${VIEW.title}`);
  // Refresh pulls every page for this client in one pass (one timestamp, so pages agree). The wallboard's own
  // auto-refresh only refreshes the wallboard.
  if (PANEL_ID === 'wallboard') $('refreshBtn').addEventListener('click', () => load(true));
  else {
    $('refreshLabel').textContent = 'Refresh all';
    $('refreshBtn').title = 'Pull every page for this client from Liongard in one go, so they all show the same moment';
    $('refreshBtn').addEventListener('click', refreshAll);
  }
  $('exportBtn').addEventListener('click', exportPage);
  // Diagnostics: the API calls behind the page, kept out of the way until someone asks for them.
  $('howBuiltBtn').addEventListener('click', () => {
    const box = $('howBuiltBox'), show = box.hidden;
    box.hidden = !show; box.open = show;
    $('howBuiltBtn').textContent = show ? 'Hide how this page is built' : 'Show how this page is built';
    $('howBuiltBtn').setAttribute('aria-expanded', String(show));
    if (show) box.scrollIntoView({ behavior: SMOOTH(), block: 'nearest' });
  });
  // Page-specific reports (for example the user access review) join the Export menu.
  for (const x of VIEW.exports || []) {
    const b = document.createElement('button'); b.type = 'button'; b.textContent = x.label;
    b.addEventListener('click', () => { b.closest('details').removeAttribute('open'); if (x.run) { if (CURRENT) x.run(CURRENT); } else exportPdf(x.mode, x.title || VIEW.title, x.kicker); });
    $('pdfFull').after(b);
  }
  document.addEventListener('click', e => { const d = document.querySelector('details.menu[open]'); if (d && !d.contains(e.target)) d.removeAttribute('open'); });
  $('pdfExec').addEventListener('click', () => exportPdf('exec', VIEW.title));
  $('pdfFull').addEventListener('click', () => exportPdf('full', VIEW.title));
  document.querySelectorAll('.menu-list button').forEach(b => b.addEventListener('click', () => b.closest('details').removeAttribute('open')));
  const tzPaint = () => $('tzSeg').querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === tzPref())));
  tzPaint();
  $('tzSeg').addEventListener('click', e => { const b = e.target.closest('button[data-v]'); if (!b || b.dataset.v === tzPref()) return; try { localStorage.setItem('tz', b.dataset.v); } catch {} tzPaint(); load(false); });
  iconsLoaded.then(() => load(false));   // draw once the tool icons are in
})();
