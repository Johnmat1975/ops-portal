// Settings page: connection, the MSP's details, defaults for new clients, the clients with their own settings, data kept
// on this computer, the MSP's saved work (export and import) and About. Every change is saved straight away by the main
// process, which checks each value; the access key is never sent to this page.
const ST_REGIONS = ['United Kingdom', 'European Union', 'United States', 'Australia', 'South Africa', 'Other'];
const ST_CATS = [['rmm', 'RMM / MDM'], ['edr', 'EDR / AV'], ['control', 'App control'], ['backup', 'Backup'], ['agent', 'Liongard agent']];
const ST_CURRENCIES = [['GBP', 'Pound sterling (£)'], ['EUR', 'Euro (€)'], ['USD', 'US dollar ($)'], ['AUD', 'Australian dollar'], ['NZD', 'New Zealand dollar'], ['CAD', 'Canadian dollar'], ['ZAR', 'South African rand'], ['CHF', 'Swiss franc'], ['SEK', 'Swedish krona'], ['NOK', 'Norwegian krone'], ['DKK', 'Danish krone'], ['PLN', 'Polish złoty'], ['SGD', 'Singapore dollar'], ['INR', 'Indian rupee'], ['JPY', 'Japanese yen']];
const ST_THEMES = [['light', 'Light'], ['system', 'Match system'], ['dark', 'Dark']];
const ST_DENSITY = [['comfortable', 'Comfortable'], ['compact', 'Compact']];
document.body.dataset.page = 'settings';
const ST_TZ = [['utc', 'UTC'], ['local', 'Local (this computer)']];
let S = {}, INFO = {}, ENVS = null;

const say = t => { $('statusLine').textContent = t; };
const saved = what => say(`${what} saved ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`);
async function update(patch, what) {
  try { await window.portal.updateSettings(patch); S = await window.portal.settings(); saved(what); return true; }
  catch (err) { say(`Not saved: ${cleanErr(err)}`); return false; }
}
const row = (k, sub, body, acts = '') => `<div class="st-row"><div class="k">${k}${sub ? `<span class="sub">${sub}</span>` : ''}</div><div>${body}</div><div class="acts">${acts}</div></div>`;
const seg = (id, opts, cur) => `<div class="seg" role="group" id="${id}">${opts.map(([v, l]) => `<button type="button" data-v="${esc(v)}" aria-pressed="${String(v) === String(cur)}">${esc(l)}</button>`).join('')}</div>`;
const when = iso => iso ? fmtDate(iso, true) : 'never';
const mb = b => b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`;
const getLs = (k, d) => { try { return localStorage.getItem(k) || d; } catch { return d; } };
const setLs = (k, v) => { try { if (v) localStorage.setItem(k, v); else localStorage.removeItem(k); } catch {} };

function render() {
  const b = S.branding || {}, D = S.defaults || {}, pol = D.coveragePolicy || { workstation: ['rmm', 'edr'], server: ['rmm', 'edr', 'backup'] };
  const prices = S.prices || {}, msp = S.msp || { domains: [], names: [] };
  const lt = S.lastTest, lr = S.lastRefresh;
  // Clients with their own settings: compliance profile and/or coverage policy, by environment ID.
  const ids = [...new Set([...Object.keys(S.complianceProfile || {}), ...Object.keys(S.coveragePolicy || {})])];
  const nameOf = id => ((S.complianceProfile || {})[id] || {}).name || ((S.coveragePolicy || {})[id] || {}).name || (ENVS && (ENVS.find(e => String(e.ID) === String(id)) || {}).Name) || `Environment ${id}`;
  const polText = p => p ? ['workstation', 'server'].map(k => `${k === 'server' ? 'Servers' : 'Workstations'}: ${(p[k] || []).map(c => (ST_CATS.find(x => x[0] === c) || [, c])[1]).join(', ') || 'nothing required'}`).join(' · ') : 'Default';
  $('nClients').textContent = ids.length || '';
  const tags = (list, kind) => `<div class="tags" data-kind="${kind}">${list.map((x, i) => `<span class="tag">${esc(x)} <button type="button" data-rm="${i}" aria-label="Remove ${esc(x)}">×</button></span>`).join('')}<input type="text" placeholder="Add ${kind === 'domains' ? 'a domain' : 'a name'}" aria-label="Add ${kind === 'domains' ? 'a domain' : 'an account name'}"></div>`;

  $('stBody').innerHTML = `
  <section class="card st-card" id="conn"><h3>Connection</h3><p class="sub">The Liongard instance and access key this app reads with. Read-only, and only ever sent to Liongard.</p>
    ${row('Instance', '', `<span class="mono">${esc(S.instance)}.app.liongard.com</span>`, '<a class="btn ghost sm" href="index.html#change">Change</a>')}
    ${row('Access key', 'The key itself is never shown', `<span class="chip c-ok">Saved · encrypted</span> <span class="sub">${lt ? `Last tested ${esc(fmtWhen(lt.at))} · sees ${lt.environments} client${lt.environments === 1 ? '' : 's'}` : 'Not tested yet'}</span>`,
      '<button type="button" class="btn ghost sm" id="testKey">Test connection</button><a class="btn ghost sm" href="index.html#change">Replace key</a><button type="button" class="btn ghost sm danger" id="removeKey">Remove key</button>')}
    ${row('API use', 'Stays under Liongard’s limit', `At most <span class="mono">80</span> requests a minute${lr && lr.calls ? ` · last Refresh all${lr.client ? ` (${esc(lr.client)})` : ''}: <span class="mono">${lr.calls}</span> calls in ${Math.max(1, Math.round(lr.ms / 1000))} s, ${esc(fmtWhen(lr.at))}` : ''}`)}
    <p class="sub safe" style="margin-top:10px"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg><span>Encrypted with the operating system’s keychain on this computer. Removing the key also deletes every cached client page. Use a key that belongs to a <b>read-only</b> Liongard user.</span></p>
  </section>

  <section class="card st-card" id="msp"><h3>Your MSP</h3><p class="sub">Used on every report cover, and to tell your own accounts apart from the client’s.</p>
    ${row('Company name', 'On report covers', `<input type="text" id="brandName" value="${esc(b.name || '')}" maxlength="60" aria-label="Company name">`)}
    ${row('Logo', 'PNG, JPEG, SVG or WebP, under 350 KB', `<div class="st-logo">${b.logo ? `<img src="${esc(b.logo)}" alt="Your logo">` : '<span class="sub">No logo</span>'}</div>`,
      `<label class="btn ghost sm" for="brandLogo">${b.logo ? 'Replace' : 'Upload'}</label><input type="file" id="brandLogo" accept="image/png,image/jpeg,image/svg+xml,image/webp" hidden>${b.logo ? '<button type="button" class="btn ghost sm" id="brandClear">Remove</button>' : ''}`)}
    ${row('Your own domains', 'Your staff’s accounts in client tenants', tags(msp.domains || [], 'domains'))}
    ${row('Your account names', 'Shared admin accounts you use everywhere', tags(msp.names || [], 'names'))}
    ${row('Times', 'On screen and in reports', seg('tzSeg', ST_TZ, getLs('tz', 'utc')))}
    ${row('Appearance', 'Also in the top bar', seg('themeSeg', ST_THEMES, themePref(localStorage)))}
    ${row('Table rows', 'Remembered on this computer', seg('densitySeg', ST_DENSITY, getLs('lg-density', 'comfortable')))}
  </section>

  <section class="card st-card" id="def"><h3>Defaults for new clients</h3><p class="sub">Used for a client until you change it on that client’s page. Changing a default doesn’t touch clients you’ve already set.</p>
    ${row('Coverage policy', 'What every device must have. A client is only asked for the kinds of tool it runs', `<table class="st-tbl"><thead><tr><th></th>${ST_CATS.map(c => `<th>${c[1]}</th>`).join('')}</tr></thead><tbody>${['workstation', 'server'].map(k => `<tr><td>${k === 'server' ? 'Servers' : 'Workstations'}</td>${ST_CATS.map(([c, l]) => `<td><input type="checkbox" data-pol="${k}" value="${c}" ${(pol[k] || []).includes(c) ? 'checked' : ''} aria-label="${k === 'server' ? 'Servers' : 'Workstations'} need ${l}"></td>`).join('')}</tr>`).join('')}</tbody></table>`)}
    ${row('Compliance target', 'Score out of 10', `<input type="number" id="defTarget" min="1" max="10" step="0.5" value="${esc(D.target || 8)}" style="width:90px" aria-label="Compliance target">`)}
    ${row('Region', 'Picks the frameworks that apply', `<select id="defRegion" aria-label="Default region"><option value="">Not set: show every framework</option>${ST_REGIONS.map(r => `<option ${D.region === r ? 'selected' : ''}>${esc(r)}</option>`).join('')}</select>`)}
    ${row('Stale after', 'One rule on every page', `Devices not seen for <input type="number" id="staleDev" min="7" max="365" value="${esc(D.staleDevice || 45)}" style="width:80px" aria-label="Device stale days"> days · Accounts with no sign-in for <input type="number" id="staleAcc" min="14" max="730" value="${esc(D.staleAccount || 90)}" style="width:80px" aria-label="Account stale days"> days`)}
    ${row('Currency', 'For the prices you enter and the costs worked out from them', `<select id="defCurrency" aria-label="Currency"><option value="">Not set: numbers only</option>${ST_CURRENCIES.map(([c, l]) => `<option value="${c}" ${D.currency === c ? 'selected' : ''}>${esc(l)} · ${c}</option>`).join('')}</select>`)}
    ${row('Licence prices', 'Monthly price per seat, used for spare-seat costs on Licence reconciliation', `<table class="st-tbl" id="priceTbl"><thead><tr><th>Product</th><th>Price</th><th></th></tr></thead><tbody>${Object.entries(prices).map(([p, v]) => `<tr><td>${esc(p)}</td><td><input type="text" data-price="${esc(p)}" value="${esc(v)}" style="width:100px" aria-label="Price for ${esc(p)}"></td><td><button type="button" class="linkish" data-rmprice="${esc(p)}">Remove</button></td></tr>`).join('') || '<tr><td colspan="3" class="sub">No prices yet. Add them here or on Licence reconciliation.</td></tr>'}</tbody></table>
      <div class="st-add"><input type="text" id="newProduct" placeholder="Product, as Liongard names it" style="min-width:260px" aria-label="Product"><input type="text" id="newPrice" placeholder="Price" style="width:100px" aria-label="Price"><button type="button" class="btn ghost sm" id="addPrice">Add</button></div>`)}
  </section>

  <section class="card st-card" id="clients"><h3>Clients</h3><p class="sub">Clients with their own settings. Each opens the page where it’s set, so you change it while looking at that client’s data.</p>
    ${ids.length ? `<table class="st-tbl"><thead><tr><th>Client</th><th>Compliance profile</th><th>Target</th><th>Coverage policy</th></tr></thead><tbody>${ids.map(id => { const p = (S.complianceProfile || {})[id], c = (S.coveragePolicy || {})[id]; return `<tr><td><b>${esc(nameOf(id))}</b></td><td>${p ? esc([p.industry, p.region, p.cards && 'card payments', p.insurance && 'cyber insurance', p.iso && 'ISO 27001'].filter(Boolean).join(' · ') || 'Set') : '<span class="sub">Default</span>'}</td><td>${p ? esc(p.target || 8) : '<span class="sub">Default</span>'}</td><td>${c ? esc(polText(c)) : '<span class="sub">Default</span>'}</td></tr>`; }).join('')}</tbody></table>
      <p class="sub" style="margin:8px 0 0">To change one, pick that client on the portal page, then open Compliance at a glance (profile and target) or Stack coverage (coverage policy).</p>` : '<p class="sub">No client has its own settings yet. Every client uses the defaults above.</p>'}
    <h4 style="margin:18px 0 4px">Last-known state</h4>
    <p class="sub" style="margin:0 0 8px">Clients whose Overview is cached on this computer, worst first. Read from those caches only: nothing is asked of Liongard, so a client you haven’t opened lately shows old data (its age is shown).</p>
    <div id="stStates"><p class="sub">${(INFO.cache && (INFO.cache.envIds || []).length) ? 'Reading the cached pages…' : 'No client’s Overview is cached yet. Open a client’s Overview, or use Refresh all, and it appears here.'}</p></div>
  </section>

  <section class="card st-card" id="data"><h3>Data and privacy</h3><p class="sub">Pages pulled from Liongard are kept on this computer so they open straight away. They hold client people, emails and devices.</p>
    ${row('Keep cached client data', 'After its last refresh, then deleted', seg('cacheSeg', [[7, '7 days'], [30, '30 days'], [90, '90 days']], S.cacheDays || 30))}
    ${row('Cached now', '', INFO.cache && INFO.cache.pages ? `<b>${INFO.cache.pages}</b> pages for <b>${INFO.cache.clients}</b> client${INFO.cache.clients === 1 ? '' : 's'} · ${mb(INFO.cache.bytes)} · oldest from ${esc(when(INFO.cache.oldest))}` : 'Nothing cached', INFO.cache && INFO.cache.pages ? '<button type="button" class="btn ghost sm danger" id="clearCache">Clear cached client data</button>' : '')}
    ${row('Encryption at rest', 'Coming in a later release', 'Cached pages are readable only by your user account on this computer. Until they’re encrypted by the app, rely on the computer’s disk encryption (FileVault or BitLocker).')}
  </section>

  <section class="card st-card" id="work"><h3>Your saved work</h3><p class="sub">What you’ve recorded in the app, which can’t be pulled again from Liongard. Export it for a backup, a new computer or a colleague taking over a client. The access key and cached client data are never included.</p>
    ${(INFO.warnings || []).map(w => `<div class="card flag warn"><p style="margin:0"><b>Repaired:</b> ${esc(w)}</p></div>`).join('')}
    <table class="st-tbl"><thead><tr><th>What</th><th>Clients</th><th>Items</th><th>Last changed</th></tr></thead><tbody>${(INFO.stores || []).map(r => `<tr><td>${esc(r.what)}</td><td class="mono">${r.clients}</td><td class="mono">${r.items}</td><td>${esc(when(r.changed))}</td></tr>`).join('')}
      <tr><td>Client profiles, coverage policies, prices, branding, defaults</td><td class="mono">${ids.length}</td><td class="mono">—</td><td>in settings</td></tr></tbody></table>
    <div class="st-add" style="margin-top:12px"><button type="button" class="btn" id="exportData">Export…</button><button type="button" class="btn ghost" id="importData">Import…</button><span class="sub" style="margin:0">Import merges with what’s here, and shows what will change before it does.</span></div>
    <div id="importBox"></div>
  </section>

  <section class="card st-card" id="about"><h3>About</h3>
    ${row('Version', '', `Liongard Ops Portal <b>${esc(INFO.version || S.version || '')}</b>`, '<button type="button" class="btn ghost sm" id="copyDetails">Copy details</button>')}
    ${row('Function register', 'Moved here from the menu', 'Every page as a saved question to Liongard, with the API data behind it.', `<a class="btn ghost sm${S.ready ? '' : ' locked'}" href="${S.ready ? 'panel.html?id=register' : 'index.html'}"${S.ready ? '' : ' aria-disabled="true"'}>Open${S.ready ? '' : '<span class="sr-only"> (locked: pick a client)</span>'}</a>`)}
    ${row('Distribution', '', '<span class="chip c-warn">Pilot build</span> Not yet code-signed. Share only with named pilot users until Liongard Security approves it, and check the SHA-256 hash of each download.')}
  </section>`;
  wire();
  paintStates();
}
// Settings › Clients: each cached client's last-known Act now / Review areas, worst first.
let stStatesRun = 0;
async function paintStates() {
  const ids = (INFO.cache && INFO.cache.envIds) || [], run = ++stStatesRun;
  if (!ids.length || !$('stStates')) return;
  const rows = [];
  for (const id of ids) { let st = null; try { st = await window.portal.cachedPanel('overview', id); } catch {} if (run !== stStatesRun) return; if (st) rows.push(st); }
  const nameOf = st => st.name || (ENVS && (ENVS.find(e => String(e.ID) === String(st.envId)) || {}).Name) || `Environment ${st.envId}`;
  rows.sort(worstFirst);
  $('stStates').innerHTML = rows.length ? `<table class="st-tbl"><thead><tr><th>Client</th><th>Act now</th><th>Review</th><th>Data</th><th></th></tr></thead><tbody>${rows.map(st => `<tr>
      <td><b>${esc(nameOf(st))}</b></td>
      <td>${st.act ? `<span class="chip c-crit">${st.act}</span> <span class="sub" style="margin:0">${esc(st.actAreas.join(', '))}</span>` : '<span class="sub" style="margin:0">None</span>'}</td>
      <td>${st.review ? `<span class="chip c-warn">${st.review}</span> <span class="sub" style="margin:0">${esc(st.reviewAreas.join(', '))}</span>` : '<span class="sub" style="margin:0">None</span>'}</td>
      <td>${esc(dataAge(st.pulledOn) || 'unknown')}</td>
      <td><button type="button" class="btn ghost sm" data-open-env="${esc(st.envId)}" data-name="${esc(nameOf(st))}">Open Overview</button></td></tr>`).join('')}</tbody></table>`
    : '<p class="sub">No client’s Overview is cached yet.</p>';
  $('stStates').querySelectorAll('[data-open-env]').forEach(b => b.addEventListener('click', async () => {
    try { await window.portal.selectEnvironment({ ID: b.dataset.openEnv, Name: b.dataset.name }); location.href = 'panel.html?id=overview'; } catch (err) { say(`Couldn’t switch client: ${cleanErr(err)}`); }
  }));
}

function wire() {
  // Connection
  $('testKey').addEventListener('click', async e => { e.target.disabled = true; say('Testing the key with Liongard…'); try { const r = await window.portal.testKey(); S = await window.portal.settings(); say(`Connected: the key sees ${r.environments} client${r.environments === 1 ? '' : 's'}.`); render(); } catch (err) { say(`Test failed: ${cleanErr(err)}`); e.target.disabled = false; } });
  $('removeKey').addEventListener('click', async () => { if (!confirm('Remove the saved key? Every cached client page is deleted too. Your statuses, marks and remediation lists stay.')) return; await window.portal.clearKey(); location.href = 'index.html'; });
  // Your MSP
  $('brandName').addEventListener('change', e => update({ branding: { ...(S.branding || {}), name: e.target.value } }, 'Company name'));
  $('brandLogo').addEventListener('change', e => {
    const f = e.target.files[0]; if (!f) return;
    if (f.size > 350e3) { say('That logo is over 350 KB. Use a smaller image.'); return; }
    const r = new FileReader(); r.onload = async () => { if (await update({ branding: { ...(S.branding || {}), logo: r.result } }, 'Logo')) render(); }; r.readAsDataURL(f);
  });
  if ($('brandClear')) $('brandClear').addEventListener('click', async () => { if (await update({ branding: { ...(S.branding || {}), logo: null } }, 'Logo removed;')) render(); });
  document.querySelectorAll('.tags').forEach(box => {
    const kind = box.dataset.kind, list = () => [...((S.msp || {})[kind] || [])];
    const save = async l => { await window.portal.setMsp({ ...(S.msp || { domains: [], names: [] }), [kind]: l }); S = await window.portal.settings(); saved(kind === 'domains' ? 'Your domains' : 'Your account names'); render(); };
    box.addEventListener('click', e => { const b = e.target.closest('[data-rm]'); if (b) { const l = list(); l.splice(+b.dataset.rm, 1); save(l); } });
    box.querySelector('input').addEventListener('keydown', e => { if (e.key !== 'Enter' || !e.target.value.trim()) return; e.preventDefault(); save([...list(), e.target.value.trim()]); });
  });
  const segOn = (id, fn) => $(id).addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; $(id).querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); fn(b.dataset.v); });
  segOn('tzSeg', v => { setLs('tz', v); saved('Times'); });
  segOn('themeSeg', v => { setTheme(v); saved('Appearance'); });   // 'system' clears the override (chrome.js)
  segOn('densitySeg', v => { setLs('lg-density', v === 'compact' ? 'compact' : ''); document.body.classList.toggle('compact', v === 'compact'); saved('Table rows'); });
  // Defaults
  const defaults = () => ({
    target: $('defTarget').value, region: $('defRegion').value || undefined, currency: $('defCurrency').value || undefined, staleDevice: $('staleDev').value, staleAccount: $('staleAcc').value,
    coveragePolicy: Object.fromEntries(['workstation', 'server'].map(k => [k, [...document.querySelectorAll(`[data-pol="${k}"]:checked`)].map(c => c.value)])),
  });
  ['defTarget', 'defRegion', 'defCurrency', 'staleDev', 'staleAcc'].forEach(id => $(id).addEventListener('change', () => update({ defaults: defaults() }, 'Defaults')));
  document.querySelectorAll('[data-pol]').forEach(c => c.addEventListener('change', () => update({ defaults: defaults() }, 'Default coverage policy')));
  const prices = () => ({ ...(S.prices || {}) });
  document.querySelectorAll('[data-price]').forEach(i => i.addEventListener('change', () => { const p = prices(); if (i.value.trim()) p[i.dataset.price] = i.value.trim(); else delete p[i.dataset.price]; update({ prices: p }, 'Prices'); }));
  document.querySelectorAll('[data-rmprice]').forEach(b => b.addEventListener('click', async () => { const p = prices(); delete p[b.dataset.rmprice]; if (await update({ prices: p }, 'Prices')) render(); }));
  $('addPrice').addEventListener('click', async () => { const k = $('newProduct').value.trim(), v = $('newPrice').value.trim(); if (!k || parsePrice(v) == null) { say('Enter a product and a number for its price, like 12.50.'); return; } if (await update({ prices: { ...prices(), [k]: v } }, 'Prices')) render(); });
  // Data and privacy
  segOn('cacheSeg', async v => { if (await update({ cacheDays: +v }, 'Retention')) { INFO = await window.portal.appInfo(); render(); } });
  if ($('clearCache')) $('clearCache').addEventListener('click', async () => { if (!confirm('Delete every page pulled from Liongard on this computer? Pages pull again the next time you open them. Your key, statuses, marks and remediation lists stay.')) return; const { removed } = await window.portal.clearCache(); say(`Cleared ${removed} cached page${removed === 1 ? '' : 's'}.`); INFO = await window.portal.appInfo(); render(); });
  // Saved work
  $('exportData').addEventListener('click', async () => { try { const f = await window.portal.exportData(); if (f) say(`Exported to ${f}`); } catch (err) { say(`Export failed: ${cleanErr(err)}`); } });
  $('importData').addEventListener('click', async () => {
    try {
      const r = await window.portal.importData(); if (!r) return;
      const lines = r.summary.filter(x => x.added || x.replaced).map(x => `<li><span><b>${esc(x.what)}</b>: ${x.added} new, ${x.replaced} replaced</span></li>`).join('');
      $('importBox').innerHTML = `<div class="card flag warn" style="margin-top:12px"><h3 style="margin-top:0">Import ${esc(r.file)}?</h3>
        <p class="sub">Exported ${esc(fmtWhen(r.exportedAt))} from ${esc(r.instance || 'an unknown instance')}.${r.otherInstance ? ` <b>That’s a different instance from ${esc(S.instance)}</b>, so its client records won’t show here unless you connect to it.` : ''}</p>
        <ul class="plain">${lines || '<li><span>No statuses, marks, remediation items or history to add.</span></li>'}${r.settings.length ? `<li><span><b>Settings</b>: client profiles and coverage policies are merged; ${esc(r.settings.filter(k => !['coveragePolicy', 'complianceProfile'].includes(k)).join(', ') || 'nothing else')} only fill in what isn’t set here.</span></li>` : ''}</ul>
        <p class="sub">Where both have the same item, the imported one replaces it.</p>
        <div class="st-add"><button type="button" class="btn" id="importGo">Import</button><button type="button" class="btn ghost" id="importNo">Cancel</button></div></div>`;
      $('importNo').addEventListener('click', () => { $('importBox').innerHTML = ''; });
      $('importGo').addEventListener('click', async () => { try { await window.portal.importApply(); S = await window.portal.settings(); INFO = await window.portal.appInfo(); say('Imported.'); render(); } catch (err) { say(`Import failed: ${cleanErr(err)}`); } });
    } catch (err) { say(`Import failed: ${cleanErr(err)}`); }
  });
  // About
  $('copyDetails').addEventListener('click', () => navigator.clipboard.writeText(`Liongard Ops Portal ${INFO.version} · ${navigator.platform} · instance ${S.instance}`).then(() => say('Copied.')));
  // The section list follows the scroll.
  const links = [...document.querySelectorAll('#stToc a')];
  const io = new IntersectionObserver(es => es.forEach(en => { if (en.isIntersecting) links.forEach(a => a.classList.toggle('on', a.getAttribute('href') === `#${en.target.id}`)); }), { rootMargin: '-15% 0px -75% 0px' });
  document.querySelectorAll('.st-card').forEach(s => io.observe(s));
}

(async () => {
  S = await paintHeader();
  if (!S.hasKey) { location.href = 'index.html'; return; }   // nothing to set until the app is connected
  $('portalTitle').textContent = S.env ? S.env.Name : 'Ops Portal';
  paintNav('settings', S.ready);
  INFO = await window.portal.appInfo();
  render();
  if (location.hash) document.querySelector(location.hash)?.scrollIntoView();
  // Client names for clients saved before names were kept with their settings.
  const unnamed = [...Object.values(S.complianceProfile || {}), ...Object.values(S.coveragePolicy || {})].some(x => !x.name);
  if (unnamed) try { ENVS = await window.portal.environments(); render(); } catch {}
})();
