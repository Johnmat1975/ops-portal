// Launcher page: data source bar, settings, cards.
// ICONS, svg and GROUPS live in shared.js, so the side menu and the launcher list the same pages.
// each card has a footer with what feeds the page and at most one status badge. The badge comes only from that
// page's model already cached on this computer; with no cache there's no badge (nothing is pulled to fill one).
// The Function register lives under Settings; the stack is one line under the cards.
document.body.dataset.page = 'home';
const CHEV = '<span class="go" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg></span>';
// every tile is the same fixed size at every window width; .lw sets 1, 2 or 4 columns.
$('launcher').innerHTML = '<p class="sub" id="launcherNote" hidden></p><div class="lw">' + NAV_GROUPS.map(g => `<div class="group"><h2>${g.g}</h2><div class="cards">${g.items.map(x => x.id
  ? `<a class="lc" data-id="${x.id}"${x.client ? ' data-client=""' : ''} href="panel.html?id=${x.id}" title="${esc(x.d)}"><span class="ic">${svg(x.ic)}</span><h3>${x.t}</h3><p>${x.s || x.d}</p><span class="ft"><span class="badge" hidden></span><span class="feeds"></span>${CHEV}</span></a>`
  : `<div class="lc soon"><span class="ic">${svg(x.ic)}</span><h3>${x.t}</h3><p>${x.s || x.d}</p><span class="tag"><i></i>Not in the app yet. Still in the hosted portal</span></div>`).join('')}</div></div>`).join('') +
  '</div><div class="card stackline" id="stackCard" hidden></div>';

// Three states: 'first' (no key yet: a guided setup card and nothing else), 'pick' (connected, no client chosen yet:
// the client picker is the next step and the pages stay locked) and 'ready' (the normal launcher).
let MODE = '';
function setMode(mode, s) {
  const was = MODE; MODE = mode;
  document.body.classList.toggle('firstrun', mode === 'first');
  document.body.classList.toggle('pickenv', mode === 'pick');
  $('sourceBar').hidden = mode !== 'ready';
  $('launcher').hidden = mode === 'first';
  const set = $('settings');
  set.classList.toggle('connected', mode === 'pick' && !set.classList.contains('editing'));
  if (mode !== 'pick') set.classList.remove('editing');
  if (mode === 'first' || mode === 'pick') set.hidden = false;
  else if (was && was !== 'ready') set.hidden = true;   // just picked a client: the setup card has done its job
  $('step3').hidden = mode === 'ready';
  $('setupTitle').textContent = mode === 'first' ? 'Connect to Liongard' : mode === 'pick' ? 'Pick a client to open' : 'Liongard connection';
  $('setupLead').textContent = mode === 'first' ? 'Three steps, about two minutes. The app only reads from Liongard. It never changes anything there.'
    : mode === 'pick' ? 'You’re connected. Choose the client (Liongard environment) whose pages you want to see. You can switch at any time.'
    : 'Change the instance or replace the access key. Saving a key for a different instance clears this app’s saved data.';
  $('saveKey').textContent = mode === 'first' ? 'Connect' : 'Save and test';
  $('step1Done').textContent = s.instance ? `${s.instance}.app.liongard.com` : '';
  $('changeKey').hidden = mode !== 'pick';
  // The client picker lives in step 3 while it's the next thing to do, and in the top bar afterwards.
  if (mode === 'pick') $('envSlot').append($('envWrap'));
  else $('sourceBar').querySelector('.bar-actions').prepend($('envWrap'));
}

async function refreshSource() {
  const s = await paintHeader();
  $('portalTitle').textContent = s.env ? s.env.Name : 'Ops Portal';
  $('portalTitle').title = s.env ? `${s.env.Name} · Environment ID ${s.env.ID}` : '';
  $('helloName').textContent = s.ready ? s.env.Name : '';
  setMode(!s.hasKey ? 'first' : !s.env ? 'pick' : 'ready', s);
  $('clearKey').hidden = !s.hasKey;
  $('clearCache').hidden = !s.hasKey;
  $('cacheNote').hidden = !s.hasKey && !(s.warnings || []).length;
  $('cacheNote').textContent = [...(s.warnings || []), s.hasKey ? `Client data pulled from Liongard is kept on this computer for ${s.cacheDays || 30} days after its last refresh, then deleted.` : ''].filter(Boolean).join(' ');
  if (s.hasKey && !$('instance').value) $('instance').value = s.instance || '';
  if (!s.hasKey) {
    $('sourceText').innerHTML = '<b>Not connected</b> · Enter a Liongard API key to start.';
    $('envWrap').hidden = true;
    $('step3Help').textContent = 'Shown after you connect. Each Liongard environment is one client.';
  } else {
    $('sourceText').innerHTML = `<b>Connected</b> · ${esc(s.instance)}.app.liongard.com${s.env ? ` · <span title="Environment ID ${esc(s.env.ID)}">${esc(s.env.Name)}</span>` : ' · <b>pick a client</b>'}`;
    $('envWrap').hidden = MODE === 'ready';   // once a client is picked, the switcher in the top bar changes it
    $('step3Help').textContent = 'Each Liongard environment is one client. The pages below unlock once you pick one.';
    $('envSelect').disabled = true;
    $('envSelect').innerHTML = '<option value="">Loading clients…</option>';
    try {
      const envs = await window.portal.environments();
      chromeEnvs(s.instance, envs);   // lets the top-bar switcher list clients on every page without asking again
      $('envSelect').innerHTML = `<option value="">${envs.length ? `Choose one of ${envs.length} clients…` : 'This key can’t see any clients'}</option>` + envs.map(e => `<option value="${esc(e.ID)}" ${s.env && s.env.ID === e.ID ? 'selected' : ''}>${esc(e.Name)}</option>`).join('');
      if (MODE === 'pick') $('envSelect').focus();
    } catch (err) {   // offline or key refused: say so, don't claim Connected
      $('sourceText').innerHTML = $('sourceText').innerHTML.replace('<b>Connected</b>', '<b>Can’t reach Liongard</b>') + ` · <span class="err">${esc(cleanErr(err))}</span>`;
      $('envSelect').innerHTML = '<option value="">Couldn’t load clients</option>';
      $('step3Help').innerHTML = `<span class="err">Couldn’t read the client list from Liongard: ${esc(cleanErr(err))}</span>`;
    } finally { $('envSelect').disabled = false; }
  }
  // Pages only open once there's a key and an environment; until then the cards are locked.
  // locked links say so (they still go to the setup card, so they stay focusable).
  const lock = (el, on) => { el.classList.toggle('locked', on); if (on) el.setAttribute('aria-disabled', 'true'); else el.removeAttribute('aria-disabled'); };
  document.querySelectorAll('#launcher .lc:not(.soon)').forEach(c => lock(c, !s.ready));
  paintNav('home', s.ready);
  document.querySelectorAll('#sideNav a[href^="panel.html"]').forEach(a => { lock(a, !s.ready); const t = a.querySelector('.nv-lock'); if (t && s.ready) t.remove(); else if (!t && !s.ready) a.insertAdjacentHTML('beforeend', '<span class="sr-only nv-lock"> (locked: pick a client)</span>'); });
  $('launcherNote').hidden = s.ready;
  $('launcherNote').textContent = !s.hasKey ? 'Connect to Liongard above to unlock these pages.' : 'Pick a client above to unlock these pages.';
  paintStack(s);
  paintBadges(s);
  $('footer').textContent = 'Data comes straight from the Liongard API with your access key. Nothing is stored in the app until you connect, and nothing is sent anywhere else.';
}

// Settings has its own page; the connection form here is for first run, picking a client, and Change or Replace key
// (Settings links back with #change).
$('settingsBtn').addEventListener('click', () => { location.href = 'settings.html'; });
function openChange() { $('settings').hidden = false; $('settings').classList.remove('connected'); $('settings').classList.add('editing'); $('changeKey').hidden = true; $('instance').focus(); $('settings').scrollIntoView({ block: 'nearest' }); }
$('changeKey').addEventListener('click', () => { $('settings').classList.remove('connected'); $('settings').classList.add('editing'); $('changeKey').hidden = true; $('instance').focus(); });
$('envSelect').addEventListener('change', async e => {
  const o = e.target.selectedOptions[0]; if (!o || !o.value) return;
  await window.portal.selectEnvironment({ ID: o.value, Name: o.textContent });
  refreshSource();
});
document.addEventListener('click', e => {
  const c = e.target.closest('.lc.locked'); if (!c) return;
  e.preventDefault(); $('settings').hidden = false; $('settings').scrollIntoView({ behavior: SMOOTH() });
  if (MODE === 'pick') $('envSelect').focus();
});
$('keyForm').addEventListener('submit', async e => {
  e.preventDefault();
  $('keyStatus').textContent = 'Testing the key with Liongard…'; $('saveKey').disabled = true;
  try {
    const r = await window.portal.saveKey({ instance: $('instance').value.trim(), accessKey: $('accessKey').value.trim(), accessSecret: $('accessSecret').value });
    $('keyStatus').textContent = `Connected. The key can see ${r.environments} client${r.environments === 1 ? '' : 's'}.`;
    $('accessKey').value = ''; $('accessSecret').value = '';
    $('settings').classList.remove('editing');
    await refreshSource();
    if (MODE === 'ready') $('settings').hidden = true;
    else $('step3').scrollIntoView({ behavior: SMOOTH(), block: 'nearest' });
  } catch (err) { $('keyStatus').innerHTML = `<span class="err">${esc(cleanErr(err))}</span>`; }
  finally { $('saveKey').disabled = false; }
});
$('clearCache').addEventListener('click', async () => {
  if (!confirm('Delete every page pulled from Liongard on this computer? Pages pull again the next time you open them. Your key, statuses, marks and remediation list stay.')) return;
  const { removed } = await window.portal.clearCache();
  $('keyStatus').textContent = `Cleared ${removed} cached page${removed === 1 ? '' : 's'}.`;
});
$('clearKey').addEventListener('click', async () => { await window.portal.clearKey(); $('keyStatus').textContent = 'Key removed.'; $('instance').value = ''; refreshSource(); });
// The MSP's stack, discovered from the instance, and which of this client's inspectors feed each page.
const PAGE_NOUN = { stack: 'inspector', inspectors: 'inspector', wallboard: 'inspector', changes: 'inspector', lookup: 'inspector' };
async function paintStack(s, refresh) {
  const card = $('stackCard');
  if (!s.hasKey) { card.hidden = true; document.querySelectorAll('#launcher .feeds').forEach(f => { f.textContent = ''; }); return; }
  card.hidden = false;
  card.innerHTML = `<div class="progress" role="status"><div class="progress-bar" aria-hidden="true"><i></i></div><p class="sub"><b>Finding which inspectors this Liongard instance uses…</b> This reads every client once, so it can take up to a minute on a large instance.${s.env ? '' : ' You can pick a client while it runs.'}</p></div>`;
  try {
    const p = await window.portal.stack({ refresh });
    const used = p.inUse.filter(i => i.enabled);
    const mine = p.env && s.env ? p.env.inspectors : null;
    if (mine) chromeTools(s, mine.length);
    card.innerHTML = `<div class="sl-row"><b>Your Liongard stack</b><span>${used.length} of Liongard’s ${p.catalogue} inspectors in use across ${p.environments} environments</span>${mine ? `<span>· <b>${esc(s.env.Name)}</b> runs ${mine.length}</span>` : ''}<span>· checked ${fmtDate(p.pulledOn, true)}</span><button type="button" class="linkbtn" id="rescan">Check again</button></div>` +
      `<details><summary class="sub">Show every inspector${mine ? ' and this client’s' : ''}</summary>${mine ? `<p class="sub" style="margin-top:6px"><b>${esc(s.env.Name)}</b> runs:</p><div class="stackbar">${capChips(mine)}</div>` : ''}<p class="sub" style="margin-top:6px">Across this instance:</p><div class="stackbar">${capChips(used)}</div>
        <div class="tw"><table><thead><tr><th>Inspector</th><th>Role</th><th class="c">Clients</th><th class="c">Launchpoints</th><th class="c">Liongard metrics</th></tr></thead><tbody>${used.map(i => `<tr><td>${toolIcon(i.alias)}${esc(i.alias)}${i.known ? '' : ' <span class="chip c-warn">New: not mapped yet</span>'}</td><td>${esc(i.role)}</td><td class="c mono">${i.envCount}</td><td class="c mono">${i.launchpoints}</td><td class="c mono">${i.metrics}</td></tr>`).join('')}</tbody></table></div></details>`;
    $('rescan').addEventListener('click', () => paintStack(s, true));
    document.querySelectorAll('#launcher .lc[data-id]').forEach(el => {
      const f = el.querySelector('.feeds'), list = s.env && p.env && p.env.pages[el.dataset.id];
      el.classList.toggle('nofeed', !!list && !list.length);
      if (list && !list.length) { const b = el.querySelector('.badge'); if (b) b.hidden = true; }   // nothing feeds it, so no all-clear
      if (!f) return;
      // What feeds the page is on hover, not on the tile face (it was near-identical on most tiles); a tile nothing feeds says so.
      f.textContent = list && !list.length ? 'No tool for this client feeds this page' : '';
      const item = GROUPS.flatMap(g => g.items).find(x => x.id === el.dataset.id);
      el.title = [item ? item.d : '', list && list.length ? `Fed by ${list.length} of this client’s ${PAGE_NOUN[el.dataset.id] ? 'inspectors' : 'tools'}: ${list.join(', ')}` : ''].filter(Boolean).join('\n\n');
    });
  } catch (err) { card.innerHTML = `<p class="sub">Couldn’t read the instance’s inspectors: ${esc(cleanErr(err))}</p>`; }
}
// One status badge per card, only from models already cached on this computer (never a Liongard call).
const BADGE_SKIP = ['lookup', 'register'];
let badgeRun = 0;
async function paintBadges(s) {
  const run = ++badgeRun;
  const cards = [...document.querySelectorAll('#launcher .lc[data-id]')];
  cards.forEach(el => { const b = el.querySelector('.badge'); if (b) b.hidden = true; });
  if (!s.ready || !window.portal.cachedPanel) return;
  // Overview first: it also fills the health ribbon and the freshness pill. The Action plan next: a badge is red only
  // when its page holds an open Critical or High action (calmBadge), otherwise amber.
  const ids = ['actions', 'overview', ...cards.map(el => el.dataset.id).filter(id => id !== 'overview' && id !== 'actions' && !BADGE_SKIP.includes(id))];
  let hot = null;
  for (const id of ids) {
    let m = null; try { m = await window.portal.cachedPanel(id); } catch {}
    if (id === 'actions') hot = hotPages(m);
    if (run !== badgeRun) return;   // the client changed while this ran
    const el = document.querySelector(`#launcher .lc[data-id="${id}"]`), b = el && el.querySelector('.badge');
    if (!m) { chromeForget(id); continue; }
    chromeModel(id, m, { badgeOnly: id !== 'overview' });
    const x = calmBadge(id, pageBadge(m), hot);
    if (b && x && !el.classList.contains('nofeed')) { b.textContent = x.text; b.title = x.text; b.className = `badge b-${x.tone}`; b.hidden = false; }
  }
}
// One chip per capability, with the inspectors behind it on hover.
function capChips(list) {
  const by = {};
  for (const i of list) for (const c of i.caps) (by[c] = by[c] || []).push(i.alias);
  return Object.keys(CAP_LABELS).filter(c => by[c]).map(c => `<span class="chip c-none" title="${esc(by[c].join(', '))}">${esc(CAP_LABELS[c])} · ${by[c].length}</span>`).join('');
}
const CAP_LABELS = { identity: 'Identity & access', email: 'Email & domains', security: 'Endpoint security', management: 'Device management', backup: 'Backup', network: 'Network', monitoring: 'Monitoring', servers: 'Servers', cloud: 'Cloud & SaaS', awareness: 'Training & dark web', ai: 'AI', business: 'PSA & docs', voice: 'Telephony', other: 'Other' };
// First paint once the tool icons are in. Settings › Change or Replace key arrives with #change and opens the connection form.
iconsLoaded.then(refreshSource).then(() => { if (location.hash === '#change' && MODE !== 'first') openChange(); });
