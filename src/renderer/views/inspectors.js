// Inspector health view.
// Misfiled systems: a launchpoint whose name contains ANOTHER client's name is usually filed
// under the wrong environment, which pollutes both clients' pages. Uses the client list this session already holds
// (from the switcher or the portal page) and the launchpoint names on this page: no extra Liongard call.
const INSP_GENERIC = /\b(inc|ltd|llc|limited|plc|gmbh|group|corp|corporation|company|co|the|and|of|demo|test|it|msp|services?)\b/g;
const inspNorm = s => ` ${String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()} `;
function inspMisfiled(rows, envs, env) {
  const mine = inspNorm(env && env.Name);
  const others = (envs || []).filter(e => e && String(e.ID) !== String(env && env.ID)).map(e => ({ e, n: inspNorm(e.Name) }))
    // Long enough to mean something once the generic words are gone, and not part of this client's own name.
    .filter(o => o.n.replace(INSP_GENERIC, ' ').replace(/\s+/g, '').length >= 5 && !mine.includes(o.n));
  const out = [];
  for (const r of rows || []) {
    const n = inspNorm(r.name);
    const hit = others.filter(o => n.includes(o.n)).sort((a, b) => b.n.length - a.n.length)[0];
    if (hit) out.push({ name: r.name, inspector: r.inspector, other: hit.e.Name, systemId: r.systemId, systemDetailId: r.systemDetailId, inspectorId: r.inspectorId, lpId: r.lpId });
  }
  return out;
}
window.VIEWS.inspectors = {
  title: 'Inspector health',
  kpiItems: Object.fromEntries([['Systems monitored', r => r.health !== 'Inactive'], ['Fresh', r => r.health === 'Fresh'], ['Due or stale', r => r.health === 'Due' || r.health === 'Stale'], ['Failing', r => r.health === 'Failing'], ['Not scheduled', r => r.unscheduled && r.health !== 'Inactive']]
    .map(([k, f]) => [k, (m, c) => m.rows.filter(f).map(r => ({ t: r.name, d: `${r.inspector} · ${r.health}${r.why ? ` · ${r.why}` : ''}`, url: LG.system(c, r.systemId, r.systemDetailId) || LG.launchpoint(c, r.inspectorId, r.lpId), sev: r.health === 'Failing' ? 'bad' : r.health === 'Fresh' ? 'ok' : 'warn' }))])),
  intro: 'Every inspector deployed for this client, when it last produced good data, and whether its last attempt failed. If an inspector goes stale, every page built on its data goes stale with it.',
  render(m) {
    const chip = { Fresh: 'c-ok', Due: 'c-warn', Stale: 'c-warn', Failing: 'c-crit', Inactive: 'c-none' };
    this._m = m;
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(x => `<li><span>${esc(x)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <div class="two">
        <div class="card flag"><h3>Needs attention</h3><ul class="plain">${m.attention.map(a => `<li><i class="tick t-${a.sev === 'bad' ? 'bad' : 'warn'}" style="flex:none;width:22px;height:22px;font-size:11px">${a.sev === 'bad' ? '✕' : '!'}</i><span><b>${esc(a.t)}</b> ${esc(a.d)}</span></li>`).join('') || '<li>Nothing needs attention.</li>'}</ul></div>
        <div class="card"><h3>Freshness by category</h3><div class="bars">${m.cats.map(c => `<div class="bar"><span>${esc(c.c)}</span><div class="track" style="display:flex"><div style="width:${c.fresh / c.n * 100}%;background:var(--ok)"></div><div style="width:${c.due / c.n * 100}%;background:var(--warn)"></div><div style="width:${c.fail / c.n * 100}%;background:var(--crit)"></div></div><span class="mono">${c.fresh}/${c.n} fresh</span></div>`).join('')}</div>
          <div class="legend"><span><i class="tick t-ok" style="width:12px;height:12px"></i>Fresh</span><span><i class="tick t-warn" style="width:12px;height:12px"></i>Due or stale</span><span><i class="tick t-bad" style="width:12px;height:12px"></i>Failing</span></div></div>
      </div>
      <div id="lpMisfiled"></div>
      <div class="filters"><div class="quick" id="lpH">${['All', 'Failing', 'Stale', 'Due', 'Not scheduled', 'Fresh', 'Inactive'].map((h, i) => `<button type="button" data-h="${h}" aria-pressed="${i === 0}">${h}</button>`).join('')}</div>
        <div class="search" style="flex:1;min-width:200px;margin:0"><input id="lpFilter" placeholder="Filter by name, inspector, category or health" autocomplete="off" aria-label="Filter inspectors"></div></div>
      <div class="tw"><table id="lpTable"></table></div>
      <p class="sub">Freshness is judged against each launchpoint's own schedule. Launchpoints that aren't on a schedule are judged against a daily run. Fresh means good data within one interval, Due within two, and Stale beyond that.</p>`;
  },
  after(m, ctx) {
    const chip = { Fresh: 'c-ok', Due: 'c-warn', Stale: 'c-warn', Failing: 'c-crit', Inactive: 'c-none' };
    let h = 'All', qq = '';
    const draw = q => {
      if (q !== undefined) qq = (q || '').toLowerCase();
      const rows = m.rows.filter(r => (h === 'All' || (h === 'Not scheduled' ? r.unscheduled && r.health !== 'Inactive' : r.health === h)) && (!qq || [r.name, r.inspector, r.category, r.health, r.every].join(' ').toLowerCase().includes(qq)));
      $('lpTable').innerHTML = `<thead><tr><th>Launchpoint</th><th>Schedule</th><th>Health</th><th>Last good data</th><th class="c">Days</th><th>Why</th><th></th></tr></thead><tbody>` +
        rows.map(r => `<tr><td class="wrap" style="min-width:180px" data-csv="${esc(r.name)}">${toolIcon(r.inspector)}${r.systemDetailId ? lgA(LG.system(ctx, r.systemId, r.systemDetailId), esc(r.name), 'Open the latest data in Liongard') : esc(r.name)}<div class="sub" style="margin:0">${esc(r.inspector)} · ${esc(r.category)}</div></td><td>${r.unscheduled ? '<span class="chip c-warn">Not scheduled</span>' : esc(r.every)}</td><td><span class="chip ${chip[r.health]}">${r.health}</span></td><td class="num">${r.lastGood ? fmtDate(r.lastGood, true) : '—'}</td><td class="c mono">${r.days ?? '—'}</td><td class="wrap">${esc(r.why)}</td><td class="no-print">${r.inspectorId ? lgA(LG.launchpoint(ctx, r.inspectorId, r.lpId), 'Settings', 'Open this launchpoint\u2019s settings in Liongard') : ''}</td></tr>`).join('') + '</tbody>';
    };
    draw('');
    // Misfiled check from the client list already in this session (never a Liongard call from this page).
    const envs = typeof chSess !== 'undefined' ? chSess.get('lg-envs', null) : null;
    const list = envs && envs.instance === m.instance ? envs.list : null;
    const mis = list ? inspMisfiled(m.rows, list, m.environment) : [];
    $('lpMisfiled').innerHTML = !list ? '<p class="sub">To check for systems filed under the wrong client, open the client switcher once (it lists your clients), then come back.</p>'
      : mis.length ? `<div class="card flag warn"><h3>Filed under the right client?</h3><p class="sub" style="margin:0 0 6px">These systems’ names mention another of your clients. A system filed under the wrong environment shows up on both clients’ pages and reports.</p><ul class="plain">${mis.map(x => `<li><span><b>${x.systemDetailId ? lgA(LG.system(ctx, x.systemId, x.systemDetailId), esc(x.name)) : lgA(LG.launchpoint(ctx, x.inspectorId, x.lpId), esc(x.name))}</b> <span class="sub" style="margin:0">${esc(x.inspector || '')} · name mentions <b>${esc(x.other)}</b></span></span></li>`).join('')}</ul></div>`
      : `<p class="sub">No system here is named after another of your ${list.length - 1} clients.</p>`;
    $('lpH').addEventListener('click', e => { const b = e.target.closest('[data-h]'); if (!b) return; [...$('lpH').children].forEach(x => x.setAttribute('aria-pressed', x === b)); h = b.dataset.h; draw(); });
  },
  how: m => [
    `GET /api/v1/launchpoints  (Environment/ID = ${m.environment.ID})  → name, inspector, schedule, enabled`,
    `GET /api/v1/timeline  (Environment/ID = ${m.environment.ID}, Latest is true)  → last attempt per launchpoint`,
    'GET /api/v1/timeline  (Launchpoint/ID = …, newest first)  → last good dataprint, only for launchpoints whose last attempt failed',
    'Rules: src/main/panels/inspectors.js',
  ].join('\n'),
};
