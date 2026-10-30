// Customer stack: every inspector this client runs, grouped by capability, with what Liongard's metrics say about each.
window.VIEWS.stack = {
  title: 'Customer stack',
  kpiItems: {
    'Inspectors in use': (m, c) => m.inspectors.filter(i => i.health !== 'Inactive').map(i => ({ t: i.alias, d: `${i.role} · ${i.caps.join(', ')} · ${i.health}`, sev: i.health === 'Failing' ? 'bad' : i.health === 'Fresh' ? 'ok' : 'warn' })),
    'Capabilities covered': m => m.caps.map(x => ({ t: x.label, d: x.tools.join(', ') || (x.state === 'gap' ? 'Not monitored' : 'Not in use'), sev: x.state === 'gap' || x.state === 'blind' || x.state === 'bad' ? 'bad' : x.state === 'warn' ? 'warn' : x.state === 'ok' ? 'ok' : '' })),
    'Problems': m => m.findings.filter(f => f.sev === 'bad' && !f.old).map(f => ({ t: f.label, d: `${f.value} · ${f.system} (${f.inspector})`, sev: 'bad' })),
    'Expired or due in 90 days': (m, c) => m.expiries.filter(e => e.days <= 90).map(e => ({ t: `${fmtDate(e.date, true)}: ${e.label}`, d: `${e.system} (${e.inspector})`, url: LG.system(c, e.systemId, e.systemDetailId), sev: e.days < 0 ? 'bad' : 'warn' })),
  },
  // The PDF is a client summary; every metric value for every system is a CSV (it would be 100+ pages as a PDF).
  exports: [{ label: 'CSV: every metric value for this client', run: async m => {
    const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = [['Inspector', 'System', 'Health', 'Last good data', 'Metric', 'Value']].concat(m.inspectors.flatMap(i => i.systems.flatMap(s => s.facts.map(f => [i.alias, s.name, s.health, s.lastGood || '', f.n, f.v]))));
    const saved = await window.portal.exportCsv({ name: `${m.environment.Name}-every-metric`.replace(/[^\w-]+/g, '-').slice(0, 80), csv: rows.map(r => r.map(q).join(',')).join('\n') });
    if (saved) $('statusLine').textContent = `Saved ${saved}`;
  } }],
  intro: 'Every inspector this client runs, grouped by what it does for them. Problems, renewals and version drift come from Liongard’s own metrics, so this works whatever tools the client uses.',
  render(m) {
    const STATE = { ok: ['var(--ok)', 'Monitored, nothing to report'], warn: ['var(--warn)', 'Monitored, items to review'], bad: ['var(--crit)', 'Problems reported'], blind: ['var(--blind)', 'Inspectors not returning data'], gap: ['var(--none)', 'Not monitored'], unused: ['var(--line)', 'Not in use'] };
    const HCHIP = { Fresh: 'c-ok', Due: 'c-warn', Stale: 'c-warn', Failing: 'c-crit', Inactive: 'c-none' };
    const caps = m.caps.map((c, i) => `<div class="cap" role="button" tabindex="0" data-i="${i}" title="Show every tool for ${esc(c.label)}" style="--sev:${STATE[c.state][0]}"><h4>${esc(c.label)}</h4><span class="sub" style="margin:0">${esc(STATE[c.state][1])}${c.bad ? ` · ${c.bad} problem${c.bad > 1 ? 's' : ''}` : ''}${c.warn ? ` · ${c.warn} to review` : ''}${c.failing ? ` · ${c.failing} not fresh` : ''}</span><span class="tools">${c.tools.length ? c.tools.map(esc).join(', ') : esc(c.q)}</span></div>`).join('');
    const exp = m.expiries.length ? `<div class="tw"><table><thead><tr><th>Date</th><th class="c">Days</th><th>What</th><th>Where</th></tr></thead><tbody>${m.expiries.map(e => `<tr><td class="num">${fmtDate(e.date, true)}</td><td class="c"><span class="chip ${e.days < 0 ? 'c-crit' : e.days <= 90 ? 'c-warn' : 'c-none'}">${e.days < 0 ? `${agoText(-e.days)}` : e.days}</span></td><td class="wrap">${esc(e.label)}</td><td class="wrap">${toolIcon(e.inspector)}${esc(e.system)}<div class="sub" style="margin:0">${esc(e.inspector)}</div></td></tr>`).join('')}</tbody></table></div>` : '<p class="sub">No renewal dates in the next 13 months.</p>';
    return `
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <h3>Capabilities</h3>
      <div class="capgrid">${caps}</div>
      <div class="legend" style="margin-top:8px">${Object.entries(STATE).map(([k, [c, t]]) => `<span><i class="tick" style="width:12px;height:12px;background:${c}"></i>${t}</span>`).join('')}</div>
      <h3 style="margin-top:22px">What Liongard reports</h3>
      <div class="search"><input id="fFilter" placeholder="Filter by inspector, system, capability or text" autocomplete="off" aria-label="Filter findings"></div>
      <div class="tw"><table id="fTable"></table></div>
      <h3 style="margin-top:22px">Renewals: expired or due within 13 months</h3>${exp}
      ${m.drift.length ? `<h3 style="margin-top:22px">Version drift</h3><ul class="plain">${m.drift.map(d => `<li><span><b>${esc(d.inspector)}: ${esc(d.label)}</b>. ${d.values.map(v => `${esc(v.value)} on ${v.systems.map(esc).join(', ')}`).join('; ')}.</span></li>`).join('')}</ul>` : ''}
      <h3 style="margin-top:22px">Inspectors</h3>
      <p class="sub">Open an inspector to see each system and the values Liongard’s metrics hold for it.${m.unmapped.length ? ` ${m.unmapped.length} inspector${m.unmapped.length > 1 ? 's are' : ' is'} new to this app and grouped by Liongard’s category: ${m.unmapped.map(esc).join(', ')}.` : ''}</p>
      <div class="tw"><table><thead><tr><th>Inspector</th><th>Role</th><th>Health</th><th class="c">Problems</th><th class="c">To review</th></tr></thead><tbody>${m.inspectors.map((i, n) => `
        <tr><td class="wrap"><details class="screen-only" data-i="${n}"><summary>${toolIcon(i.alias)}<b>${esc(i.alias)}</b>${i.count > 1 ? ` <span class="sub">(${i.count})</span>` : ''}</summary></details><div class="sub" style="margin:0">${i.caps.map(esc).join(' · ')}</div></td><td>${esc(i.role)}</td><td><span class="chip ${HCHIP[i.health]}">${i.health}</span></td><td class="c mono">${i.bad || ''}</td><td class="c mono">${i.warn || ''}</td></tr>
        <tr class="detail screen-only" id="det${n}" hidden><td colspan="5">${i.systems.map(s => `<div class="card" style="margin:6px 0"><b>${esc(s.name)}</b> <span class="chip ${HCHIP[s.health]}">${s.health}</span><span class="sub" style="margin:0">${s.lastGood ? `Last good data ${fmtDate(s.lastGood, true)}` : 'No good data yet'}${s.why ? ` · ${esc(s.why)}` : ''}</span>${s.facts.length ? `<div class="kv">${s.facts.map(f => `<span>${esc(f.n)}</span><span class="mono">${esc(f.v)}</span>`).join('')}</div>` : '<span class="sub">No metric values for this system.</span>'}</div>`).join('')}</td></tr>`).join('')}</tbody></table></div>`;
  },
  after(m) {
    const capOpen = el => { const c = m.caps[+el.dataset.i]; openDrawer(c.label, `${c.tools.length} tool${c.tools.length === 1 ? '' : 's'}${c.bad ? ` · ${c.bad} problem${c.bad > 1 ? 's' : ''}` : ''}${c.warn ? ` · ${c.warn} to review` : ''}`, c.tools.length ? c.tools.map(t => ({ t })) : [{ t: 'Not monitored', d: c.q }], m); };
    document.querySelector('.capgrid').addEventListener('click', e => { const el = e.target.closest('.cap[data-i]'); if (el) capOpen(el); });
    document.querySelector('.capgrid').addEventListener('keydown', e => { const el = e.target.closest('.cap[data-i]'); if (el && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); capOpen(el); } });
    const draw = q => {
      q = (q || '').toLowerCase();
      const rows = m.findings.filter(f => !q || [f.label, f.inspector, f.system, f.sev].join(' ').toLowerCase().includes(q));
      $('fTable').innerHTML = `<thead><tr><th>Severity</th><th>What Liongard reports</th><th class="c">Value</th><th>Where</th></tr></thead><tbody>` + (rows.map(f => `<tr><td><span class="chip ${f.sev === 'bad' ? 'c-crit' : 'c-warn'}">${f.sev === 'bad' ? 'Problem' : 'Review'}</span></td><td class="wrap">${esc(f.label)}${f.list && f.list.length ? `<details><summary class="sub">Show ${f.list.length}</summary><div class="sub">${f.list.map(x => esc(typeof x === 'string' ? x : JSON.stringify(x))).join('<br>')}</div></details>` : ''}</td><td class="c mono">${esc(f.value)}</td><td class="wrap">${toolIcon(f.inspector)}${esc(f.system)}<div class="sub" style="margin:0">${esc(f.inspector)}</div></td></tr>`).join('') || '<tr><td colspan="4">Nothing reported.</td></tr>') + '</tbody>';
    };
    draw('');
    $('fFilter').addEventListener('input', e => draw(e.target.value));
    document.querySelectorAll('details[data-i]').forEach(d => d.addEventListener('toggle', () => { $(`det${d.dataset.i}`).hidden = !d.open; }));
  },
  how: m => [
    'GET /api/v1/launchpoints, /api/v1/timeline (Latest is true)  → every inspector this client runs, and its health',
    `POST /api/v2/metrics/evaluate/systems  (25 systems per call)  → ${m.kpis.find(k => k.k === 'Liongard metrics read').v} Liongard metric values, already evaluated on each inspection`,
    'Capabilities: src/main/stack-catalog.js maps all 117 Liongard inspectors to what they do for a client',
    'Rules: src/main/metric-signals.js reads metric names and values (counts of threats, failures, missing MFA, stale items; expiry dates; versions)',
  ].join('\n'),
};
