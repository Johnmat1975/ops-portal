// Change pulse view: swimlane of changes by system over the window, source totals, and a feed with before/after values.
// Heat: 1 change a day is cool blue, 10+ is red. The same scale colours a system's total against the busiest system.
const changeHeat = n => `var(--heat-${n >= 10 ? 5 : n >= 5 ? 4 : n >= 3 ? 3 : n >= 2 ? 2 : 1})`;
// A change's one-line summary, with a chip when it looks worse (or better) for security.
const chSummary = f => f.summary ? `${f.summary.tone === 'risk' ? '<span class="chip c-crit">Worse</span> ' : f.summary.tone === 'better' ? '<span class="chip c-ok">Better</span> ' : ''}${esc(f.summary.text)}` : '';
const relHeat = (n, max) => `var(--heat-${Math.max(1, Math.min(5, Math.ceil(n / Math.max(1, max) * 5)))})`;
window.VIEWS.changes = {
  title: 'Change pulse',
  kpiItems: {
    'Changes in': (m, c) => (m.all || m.feed).map(f => ({ t: `${f.source}: ${String(f.name).replace(/^[^|:]+[|:]\s*/, '')}`, d: `${fmtWhen(f.at)}${f.routine ? ' · routine' : ''}`, url: LG.system(c, f.systemId, f.systemDetailId, 'changes') })),
    'Excluding routine churn': (m, c) => (m.all ? m.all.filter(f => !f.routine) : m.feed).map(f => ({ t: `${f.source}: ${String(f.name).replace(/^[^|:]+[|:]\s*/, '')}`, d: fmtWhen(f.at), url: LG.system(c, f.systemId, f.systemDetailId, 'changes') })),
    'Last 7 days': (m, c) => m.feed.filter(f => (new Date(m.pulledOn) - new Date(f.at)) / 864e5 <= 7).map(f => ({ t: `${f.source}: ${String(f.name).replace(/^[^|:]+[|:]\s*/, '')}`, d: fmtWhen(f.at), url: LG.system(c, f.systemId, f.systemDetailId, 'changes') })),
    'Busiest system': (m, c) => (m.all || []).filter(f => m.sources[0] && f.source === m.sources[0].source && !f.routine).map(f => ({ t: String(f.name).replace(/^[^|:]+[|:]\s*/, ''), d: fmtWhen(f.at), url: LG.system(c, f.systemId, f.systemDetailId, 'changes') })),   // that system's non-routine changes, as counted
  },
  intro: 'Configuration changes Liongard detected in the last 90 days, by system, with the before and after values. Routine churn, such as a certificate that changes name every day, can be hidden.',
  render(m, ctx) {
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(x => `<li><span>${esc(x)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <div class="card"><div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center"><h3>Changes by system</h3>
        <label class="toggle"><input type="checkbox" id="hideRoutine" checked> Hide routine churn</label></div>
        <div class="filters no-print ch-range">
          <div class="quick" id="chRange">${[[7, '7 days'], [30, '30 days'], [m.windowDays, `${m.windowDays} days`]].map(([d, l]) => `<button type="button" data-d="${d}" aria-pressed="${d === m.windowDays}">${l}</button>`).join('')}</div>
          <label class="fld-inline">From <input type="date" id="chFrom"></label><label class="fld-inline">To <input type="date" id="chTo"></label>
          <span class="sub" id="chRangeNote" style="margin:0"></span>
          <span class="heat-legend" aria-label="Changes per day">Changes per day: ${[[1, '1'], [2, '2'], [3, '3–4'], [5, '5–9'], [10, '10+']].map(([n, l]) => `<span><i style="background:${changeHeat(n)}"></i>${l}</span>`).join('')}</span>
        </div>
        <div class="lane-wrap"><svg id="lanes" role="group" aria-label="Changes by system over ${m.windowDays} days"></svg></div>
        ${m.routineSources.length ? `<p class="sub" style="margin:0">Routine: ${esc(m.routineSources.join('; '))}. The same change on the same system on most days usually means shared hosting, a CDN or a counter, not a real configuration change.</p>` : ''}</div>
      <div class="card"><h3>By system</h3><div class="bars sys" id="sysBars"></div>
          <div class="legend"><span><i class="tick" style="width:12px;height:12px;background:linear-gradient(90deg,var(--heat-1),var(--heat-3),var(--heat-5))"></i>Changes (hotter = busier than the other systems)</span><span><i class="tick" style="width:12px;height:12px;background:var(--none)"></i>Routine churn</span></div></div>
      <h3 style="margin-top:22px">Changes</h3>
      <div class="filters"><select id="chSys" aria-label="System"><option value="">All systems</option>${m.sources.filter(x => x.total > x.routine).map(x => `<option>${esc(x.source)}</option>`).join('')}</select>
        <div class="search" style="flex:1;min-width:200px;margin:0"><input id="chQ" placeholder="Search change, system or value" autocomplete="off" aria-label="Search changes"></div></div>
      <p class="sub" id="chCount"></p>
      <div class="tw tech"><table id="chTable"></table></div>`;
  },
  after(m, ctx) {
    // Date range, as UTC day strings (the same days the changes are grouped by). Liongard gives the app m.windowDays of changes.
    const day = t => new Date(t).toISOString().slice(0, 10);
    const endT = new Date(m.pulledOn || Date.now()).getTime(), minDay = day(endT - m.windowDays * 864e5), maxDay = day(endT);
    let from = minDay, to = maxDay;
    const inRange = d => d >= from && d <= to;
    const fromI = $('chFrom'), toI = $('chTo');
    for (const el of [fromI, toI]) { el.min = minDay; el.max = maxDay; }
    // Each system's changes inside the range: real, routine, and the days to draw.
    const ranged = () => m.sources.map(s => { const days = s.byDay.filter(d => inRange(d.day)); let real = 0, routine = 0; for (const d of days) { const r = d.real ?? (d.routine ? 0 : d.n); real += r; routine += d.n - r; } return { ...s, days, real, routine }; });
    const bars = R => {
      const B = R.filter(s => s.real + s.routine).sort((a, b) => (b.real - a.real) || (b.routine - a.routine)), max = Math.max(1, ...B.map(s => s.real + s.routine)), hot = Math.max(1, ...B.map(s => s.real));
      $('sysBars').innerHTML = B.map(s => `<div class="bar"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.source)}">${toolIcon(s.inspector)}${s.systemId ? lgA(LG.system(ctx, s.systemId, s.systemDetailId, 'changes'), esc(s.source), `Open ${s.source} in Liongard`) : esc(s.source)}</span><div class="track" style="display:flex"><div class="fill" style="width:${s.real / max * 100}%;background:${relHeat(s.real, hot)}"></div><div class="fill" style="width:${s.routine / max * 100}%;background:var(--none)"></div></div><span class="mono">${s.real + s.routine}</span></div>`).join('')
        || '<p class="sub" style="margin:0">No changes in this date range.</p>';
    };
    const draw = () => {
      const hide = $('hideRoutine').checked, R = ranged();
      bars(R);
      const L = R.filter(s => hide ? s.real : s.real + s.routine).sort((a, b) => (b.real - a.real) || (b.routine - a.routine)).slice(0, 16), hot = Math.max(1, ...L.map(s => s.real));
      $('chRangeNote').textContent = `${fmtDate(from + 'T12:00:00Z')} – ${fmtDate(to + 'T12:00:00Z')} · ${R.reduce((a, s) => a + s.real, 0)} changes${hide ? '' : `, ${R.reduce((a, s) => a + s.routine, 0)} routine`}`;
      // Drawn at its real width, so the text doesn't scale up on wide screens.
      // Same grid as the By system rows below: 300px of names, 28px rows, the plot ending where the bars end.
      const W = Math.max(1000, Math.round((($('lanes') || {}).parentElement || {}).clientWidth || 1000)), left = 310, right = 48, top = 26, rowH = 28, H = top + Math.max(1, L.length) * rowH + 8;
      const start = Date.parse(from + 'T00:00:00Z'), end = Date.parse(to + 'T23:59:59Z'), x = t => left + (t - start) / (end - start) * (W - left - right);
      let g = '';
      for (let i = 0; i <= 3; i++) { const t = start + i * (end - start) / 3, xx = x(t); g += `<line x1="${xx}" x2="${xx}" y1="${top - 6}" y2="${H - 6}" stroke="var(--line)"/><text x="${xx}" y="14" fill="var(--muted)" font-size="12" font-family="IBM Plex Sans, Arial" text-anchor="${i === 0 ? 'start' : i === 3 ? 'end' : 'middle'}">${fmtDate(new Date(t).toISOString())}</text>`; }
      L.forEach((s, i) => {
        const y = top + i * rowH + rowH / 2;
        g += `<line x1="${left}" x2="${W - right}" y1="${y}" y2="${y}" stroke="var(--line)"/>${(() => { const lbl = `<text x="0" y="${y + 4.5}" fill="${s.systemId ? 'var(--blue)' : 'var(--ink)'}" font-size="13.5" font-family="Lato, Arial">${esc(s.source.length > 34 ? s.source.slice(0, 33) + '…' : s.source)}<title>${esc(s.source)}: open in Liongard</title></text>`; const url = s.systemId && LG.system(ctx, s.systemId, s.systemDetailId, 'changes'); return url ? `<a href="${esc(url)}" target="_blank" rel="noopener" class="lane-link">${lbl}</a>` : lbl; })()}`;
        // The system's own heat: its changes in the range against the busiest system's.
        g += `<rect x="${left - 46}" y="${y - 9}" width="34" height="18" rx="9" fill="${s.real ? relHeat(s.real, hot) : 'var(--none)'}"><title>${esc(s.source)}: ${s.real} change${s.real === 1 ? '' : 's'} in this range${s.routine ? ` (+${s.routine} routine)` : ''}</title></rect><text x="${left - 29}" y="${y + 4}" font-size="11" font-weight="700" font-family="IBM Plex Sans, Arial" text-anchor="middle" fill="#fff" pointer-events="none">${s.real > 999 ? '999+' : s.real}</text>`;
        s.days.map(d => ({ ...d, real: d.real ?? (d.routine ? 0 : d.n) })).filter(d => !hide || d.real).forEach(d => { const n = hide ? d.real : d.n, r = Math.min(11, 3 + Math.sqrt(n) * 2); g += `<circle class="ch-dot" data-src="${esc(s.source)}" data-day="${esc(d.day)}" tabindex="0" role="button" aria-label="${esc(`${s.source}, ${d.day}: ${d.real} change${d.real === 1 ? '' : 's'}`)}" cx="${x(Date.parse(d.day + 'T12:00:00Z')).toFixed(1)}" cy="${y}" r="${r.toFixed(1)}" fill="${d.routine ? 'var(--none)' : changeHeat(d.real)}" fill-opacity="${d.routine ? 0.6 : 0.92}" stroke="${d.routine ? 'none' : 'var(--surface-card)'}"><title>${esc(s.source)} · ${esc(d.day)} · ${d.real} change${d.real === 1 ? '' : 's'}${d.n > d.real ? ` (+${d.n - d.real} routine)` : ''} (click for details)</title></circle>`; });
      });
      if (!L.length) g += `<text x="${left}" y="${top + 18}" fill="var(--muted)" font-size="13" font-family="Lato, Arial">No changes in this date range.</text>`;
      const svg = $('lanes'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.innerHTML = g;
      list();
    };
    const setRange = (f, t, quick) => {
      from = f < minDay ? minDay : f > maxDay ? maxDay : f; to = t > maxDay ? maxDay : t < minDay ? minDay : t;
      if (from > to) [from, to] = [to, from];
      fromI.value = from; toI.value = to;
      [...$('chRange').children].forEach(b => b.setAttribute('aria-pressed', String(quick != null && +b.dataset.d === quick)));
      draw();
    };
    $('chRange').addEventListener('click', e => { const b = e.target.closest('[data-d]'); if (b) setRange(day(endT - +b.dataset.d * 864e5), maxDay, +b.dataset.d); });
    for (const el of [fromI, toI]) el.addEventListener('change', () => { if (fromI.value && toI.value) setRange(fromI.value, toI.value, null); });
    $('hideRoutine').addEventListener('change', draw);
    // A dot opens that system's changes on that day in the drawer, each with its summary and a link to it in Liongard.
    const openDot = el => {
      const src = el.dataset.src, d = el.dataset.day, hide = $('hideRoutine').checked;
      const list = (m.all || m.feed).filter(f => f.source === src && String(f.at).slice(0, 10) === d && (!hide || !f.routine));
      openDrawer(src, `${fmtDate(d + 'T12:00:00Z', true)} · ${list.length} change${list.length === 1 ? '' : 's'}`,
        list.map(f => ({ t: `${fmtWhen(f.at)}: ${String(f.name).replace(/^[^|:]+[|:]\s*/, '')}`, d: [f.summary && f.summary.text, f.routine ? 'routine' : ''].filter(Boolean).join(' · '),
          url: LG.system(ctx, f.systemId, f.systemDetailId, 'changes'), sev: f.summary && f.summary.tone === 'risk' ? 'bad' : '' })), m);
    };
    $('lanes').addEventListener('click', e => { const c = e.target.closest('.ch-dot'); if (c) openDot(c); });
    $('lanes').addEventListener('keydown', e => { const c = e.target.closest('.ch-dot'); if (c && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openDot(c); } });
    let sys = '', q = '';
    const what = x => [x.added.length && `<div class="dl add">${x.added.map(a => `<span>+ ${esc(a)}</span>`).join('')}</div>`, x.removed.length && `<div class="dl rem">${x.removed.map(a => `<span>− ${esc(a)}</span>`).join('')}</div>`,
      x.changed.length && `<div class="dl chg">${x.changed.map(c => `<span>${esc(c.key)}: <del>${esc(c.from)}</del> → <ins>${esc(c.to)}</ins></span>`).join('')}</div>`, x.more && `<div class="sub" style="margin:2px 0 0">and ${x.more} more in Liongard</div>`].filter(Boolean).join('')
      || (x.before || x.after ? `<div class="diff">${x.before ? `<del>${esc(x.before)}</del>` : ''}${x.before && x.after ? ' → ' : ''}${x.after ? `<ins>${esc(x.after)}</ins>` : ''}</div>` : '');
    const list = () => {
      const rows = m.feed.filter(f => inRange(day(f.at)) && (!sys || f.source === sys) && (!q || JSON.stringify([f.name, f.source, f.added, f.removed, f.changed, f.summary && f.summary.text]).toLowerCase().includes(q)));
      $('chCount').textContent = `${rows.length} change${rows.length === 1 ? '' : 's'}${m.feed.length >= 500 ? ' (latest 500)' : ''}`;
      $('chTable').innerHTML = '<thead><tr><th>When</th><th>System</th><th>Summary</th><th>What changed</th></tr></thead><tbody>' + rows.slice(0, 300).map(f => `<tr><td class="mono" data-csv="${esc(f.at)}">${esc(fmtWhen(f.at))}</td>
        <td class="wrap" style="min-width:170px" data-csv="${esc(f.source)}">${toolIcon(f.inspector)}${lgA(LG.system(ctx, f.systemId, f.systemDetailId, 'changes'), esc(f.source), 'Open this change in Liongard')}<div class="sub" style="margin:0">${esc(f.inspector || '')}</div></td>
        <td class="wrap ch-sum" data-csv="${esc(`${f.summary && f.summary.tone === 'risk' ? 'Worse: ' : f.summary && f.summary.tone === 'better' ? 'Better: ' : ''}${f.summary ? f.summary.text : ''}`)}">${chSummary(f)}</td>
        <td class="wrap"><b>${esc(String(f.name).replace(/^[^|:]+[|:]\s*/, ''))}</b>${what(f)}</td></tr>`).join('') + '</tbody>';
    };
    $('chSys').addEventListener('change', e => { sys = e.target.value; list(); });
    $('chQ').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); list(); });
    setRange(minDay, maxDay, m.windowDays);
  },
  how: m => [
    `GET /api/v1/detections  (Environment/ID = ${m.environment.ID}, CreatedOn >= ${fmtDate(m.since, true)}, newest first)  → change name, system, before/after patch`,
    'Routine churn = the same change on the same system on at least 30% of active days, and at least 10 times.',
    'Rules: src/main/panels/changes.js',
  ].join('\n'),
};
