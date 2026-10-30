// Cyber security view: posture now → what changed → what Liongard can and can't see.
window.VIEWS.cyber = {
  title: 'Cyber security',
  kpiItems: {
    'Exposures now': m => m.posture.filter(p => p.count && (p.sev === 'bad' || p.sev === 'warn')).map(p => ({ t: `${p.title}: ${p.count}`, d: p.detail, sev: p.sev })),   // one row per exposure counted; open a tile below for its items
    'Changes to review, 7 days': (m, c) => (m.recent || []).map(x => ({ t: `${x.system}: ${x.name.replace(/^[^|:]+[|:]\s*/, '')}`, d: `${fmtWhen(x.at)} · ${x.conf}${x.tech.length ? ` · ${x.tech.join(', ')}` : ''}${x.note ? ` · ${x.note}` : ''}`, url: LG.system(c, x.systemId, x.systemDetailId, 'changes'), sev: x.conf === 'Strong' ? 'bad' : 'warn' })),
    'Highest in 90 days': (m, c) => m.clusters.map(w => ({ t: `${w.level}: ${w.title}`, d: `${fmtWhen(w.start)} · ${w.reason}`, sev: w.level === 'High' ? 'bad' : w.level === 'Elevated' ? 'warn' : 'ok' })),
    'Techniques Liongard can’t see': m => m.cover.filter(x => x.status === 'Blind').map(x => ({ t: `${x.t} ${x.name}`, d: `${x.status}: ${x.evidence}`, url: `https://attack.mitre.org/techniques/${x.t.replace('.', '/')}/`, sev: x.status === 'Blind' ? 'bad' : 'warn' })),
    'Noise set aside': (m, c) => m.flipPairs.map(f => ({ t: `${f.system}: ${f.name.replace(/^[^|:]+[|:]\s*/, '')}`, d: `Flipped back and forth ${f.count} times`, url: LG.system(c, f.systemId, f.systemDetailId, 'changes'), sev: 'warn' })),
  },
  intro: 'Where this client is exposed right now, which security-relevant changes landed together (mapped to MITRE ATT&CK Enterprise v20.0), and which attack techniques Liongard can and can’t see. Changes are leads for a human to check, not proof of an attack.',
  render(m, ctx) {
    const SEV = { bad: 'var(--crit)', warn: 'var(--warn)', ok: 'var(--ok)', none: 'var(--none)' };
    const SEV_INK = { bad: 'var(--sev-crit-ink)', warn: 'var(--sev-warn-ink)', ok: 'var(--sev-ok-ink)', none: 'var(--sev-none-ink)' };   // numbers use the ink, edges the edge colour
    const posture = m.posture.map(p => `
      <details class="pt${p.unknown ? ' no-evidence' : ''}" style="--sev:${SEV[p.sev]};--sev-text:${SEV_INK[p.sev]}">
        <summary title="${esc(p.title)}"><span class="pt-n">${p.unknown ? '—' : p.count || '0'}</span>${p.notCovered ? '<span class="chip c-nc" style="margin-left:6px">Not covered</span>' : ''}<span class="pt-t">${esc(p.title)}</span><span class="pt-d">${esc(p.detail)}</span></summary>
        <div class="pt-pop"><p class="pt-full">${esc(p.detail)}</p>
        ${p.items.length ? `<ul class="plain pt-list">${p.items.slice(0, 25).map(i => `<li><span><b>${lgA(lgFor(ctx, i), esc(i.t))}</b> <span class="sub" style="margin:0">${esc(i.sub || '')}</span>${i.list && i.list.length ? `<div class="sub" style="margin:2px 0 0">${i.list.slice(0, 8).map(x => esc(plain(x))).join(' · ')}${i.list.length > 8 ? ` and ${i.list.length - 8} more` : ''}</div>` : ''}</span></li>`).join('')}</ul>
          <div class="linkrow">${pageA(p.page, '', `Open the ${PAGE_NAMES[p.page] || p.page} page →`)}</div>` : ''}</div>
      </details>`).join('');
    const flips = m.flipPairs.length ? `<div class="card flag warn tech"><h3>Data issues: settings flipping back and forth</h3>
      <p class="sub">These settings change and then change back between inspections, ${m.flipPairs.reduce((s, f) => s + f.count, 0)} times in all. That usually means an inspector is reading two different tenants or a sync is failing, not an attack. Fix the inspector first, or real changes will be hidden in the noise.</p>
      <ul class="plain">${groupBy(m.flipPairs, f => f.system).map(([sys, list]) => `<li><span><b>${lgA(LG.system(ctx, list[0].systemId, list[0].systemDetailId, 'changes'), esc(sys))}</b>: ${list.length} setting${list.length > 1 ? 's' : ''} (${esc(list.slice(0, 4).map(f => short(f.name)).join(', '))}${list.length > 4 ? ` and ${list.length - 4} more` : ''})</span></li>`).join('')}</ul></div>` : '';
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <h3>Exposure right now</h3>
      <p class="sub">From every security, identity and device tool this client runs, read from Liongard.<span class="no-print"> Open a tile to see the accounts, devices or systems behind it.</span></p>
      <div class="ptgrid">${posture}</div>
      ${(m.older || []).length ? `<details class="card older"><summary><b>Older evidence, not counted above (${m.older.length})</b> <span class="sub">Findings more than two weeks old, or from inspectors that stopped reporting. Check the inspector before acting on them.</span></summary>
        <ul class="plain">${m.older.map(o => `<li><span>${lgA(lgFor(ctx, o), esc(o.t))}: ${esc(o.sub)} <span class="sub">· ${o.age != null ? `${esc(o.age)} days old` : 'age unknown'}${o.health && o.health !== 'Fresh' ? ` · inspector ${esc(o.health.toLowerCase())}` : ''}</span></span></li>`).join('')}</ul>
        <p class="sub">${pageA('inspectors', '', 'Inspector health →')}</p></details>` : ''}
      ${flips}
      <h3 style="margin-top:22px">What changed</h3>
      <div class="filters">
        <div class="quick" id="cyRange">${[7, 30, 90].map(d => `<button type="button" data-d="${d}" aria-pressed="${d === 90}">${d} days</button>`).join('')}</div>
        <div class="quick" id="cyLevel">${['All', 'High', 'Elevated', 'Low'].map((x, i) => `<button type="button" data-l="${x}" aria-pressed="${i === 0}">${x}</button>`).join('')}</div>
        <label class="toggle"><input type="checkbox" id="cyHideDone"> Hide change windows already reviewed</label>
        <div class="search" style="flex:1;min-width:220px;margin:0"><input id="cyQ" placeholder="Search systems, changes, people" autocomplete="off" aria-label="Search changes"></div>
      </div>
      <div class="card tech"><div class="lane-wrap"><svg id="cyLanes" role="img" aria-label="Security-relevant changes by area over time"></svg></div>
        <div class="legend"><span><i class="tick" style="width:12px;height:12px;background:var(--crit)"></i>Strong match</span><span><i class="tick" style="width:12px;height:12px;background:var(--warn)"></i>Partial</span><span><i class="tick" style="width:12px;height:12px;background:var(--none)"></i>Context</span><span>Shaded bands are correlated windows. Click one to jump to it.</span></div></div>
      <div id="cyWindows"></div>
      <h3 style="margin-top:22px">What Liongard can see for this client</h3>
      ${coverIntro(m)}
      <div class="filters">
        <div class="quick" id="atFilter">${['All', 'Visible', 'Partial', 'Blind'].map((x, i) => `<button type="button" data-ats="${x}" aria-pressed="${i === 0}">${x}</button>`).join('')}</div>
        <select id="atTac" aria-label="Tactic"><option value="">All tactics</option>${(m.coverTactics || []).filter(t => t.n).map(t => `<option value="${t.k}">${esc(t.name)} (${t.n}: ${t.Visible} visible, ${t.Partial} partly, ${t.Blind} blind)</option>`).join('')}</select>
        <div class="search" style="flex:1;min-width:220px;margin:0"><input id="atQ" placeholder="Search techniques, IDs, inspectors" autocomplete="off" aria-label="Search techniques"></div>
      </div>
      <div class="tw"><table id="atTable"></table></div>
      ${(m.coverTactics || []).some(t => !t.n) ? `<p class="sub">No technique mapped for ${esc((m.coverTactics || []).filter(t => !t.n).map(t => t.name).join(' or '))}: these need process, network-traffic or command-and-control telemetry, which Liongard doesn’t collect. Use the EDR or SIEM for them.</p>` : ''}`;
  },
  after(m, ctx) {
    const lvlChip = { High: 'c-crit', Elevated: 'c-warn', Low: 'c-none' };
    const lvlCol = { High: 'var(--crit)', Elevated: 'var(--warn)', Low: 'var(--none)' };
    const confChip = { Strong: 'c-crit', Partial: 'c-warn', Contextual: 'c-none', Defensive: 'c-ok', None: 'c-none' };
    const tUrl = id => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
    const tTag = id => `<a class="chip c-gold mono" style="text-decoration:none" href="${tUrl(id)}" target="_blank" rel="noopener" title="Open on attack.mitre.org">${id}</a>`;
    const tacName = k => (m.tacticsList.find(t => t[0] === k) || [, k])[1];
    const tkey = c => `triage:${ctx.instance}:${ctx.envId}:${c.start}`;
    const getT = c => { try { return JSON.parse(localStorage.getItem(tkey(c)) || 'null') || { s: 'New', n: '' }; } catch { return { s: 'New', n: '' }; } };
    const setT = (c, v) => { try { localStorage.setItem(tkey(c), JSON.stringify(v)); } catch {} };
    const TRI = { New: 'c-none', Investigating: 'c-warn', Expected: 'c-ok', Resolved: 'c-ok' };
    const pageFor = x => /identity/i.test(x.area) ? ['identity', 'Identity'] : /perimeter/i.test(x.area) ? ['network', 'Network'] : /dns|email/i.test(x.area) ? ['email', 'Email'] : ['lookup', 'Lookup'];
    const what = x => {
      const bits = [];
      if (x.added.length) bits.push(`<div class="dl add">${x.added.map(a => `<span>+ ${esc(a)}</span>`).join('')}</div>`);
      if (x.removed.length) bits.push(`<div class="dl rem">${x.removed.map(a => `<span>− ${esc(a)}</span>`).join('')}</div>`);
      if (x.changed.length) bits.push(`<div class="dl chg">${x.changed.map(c => `<span>${esc(c.key)}: <del>${esc(c.from)}</del> → <ins>${esc(c.to)}</ins></span>`).join('')}</div>`);
      if (x.more) bits.push(`<div class="sub" style="margin:2px 0 0">and ${x.more} more item${x.more > 1 ? 's' : ''} in Liongard</div>`);
      return bits.join('');
    };
    const row = x => `<tr><td class="mono" data-csv="${esc(x.at)}">${esc(fmtWhen(x.at))}${x.repeats > 1 ? `<div class="sub" style="margin:0">×${x.repeats} in this window</div>` : ''}</td>
      <td class="wrap" style="min-width:170px" data-csv="${esc(x.system)}">${toolIcon(x.inspector)}${lgA(LG.system(ctx, x.systemId, x.systemDetailId, 'changes'), esc(x.system), 'Open this change in Liongard')}<div class="sub" style="margin:0">${esc(x.area)} · ${pageA(pageFor(x)[0], pageFor(x)[0] === 'lookup' ? x.system.replace(/^.*? - /, '') : '', pageFor(x)[1] + ' page')}</div></td>
      <td class="wrap" data-csv="${esc([short(x.name)].concat(x.added.map(a => '+ ' + a), x.removed.map(a => '- ' + a), x.changed.map(c => `${c.key}: ${c.from} -> ${c.to}`)).join(' | '))}"><b>${esc(short(x.name))}</b>${what(x)}</td>
      <td class="wrap" style="min-width:200px"><div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">${x.tech.map(tTag).join('')}<span class="chip ${confChip[x.conf]}">${x.conf === 'None' ? 'No technique' : x.conf}</span>${x.flipped ? '<span class="chip c-warn" title="This setting keeps flipping back and forth">Flipping</span>' : ''}</div>${x.note ? `<div class="sub" style="margin:4px 0 0">${esc(x.note)}</div>` : ''}</td></tr>`;
    const head = '<thead><tr><th>When</th><th>System</th><th>What changed</th><th>ATT&CK</th></tr></thead>';
    const chain = c => `<div class="tech"><h4 class="mini">ATT&CK tactic chain</h4><div class="chain">${m.tacticsList.map(([k, n]) => `<span class="tac ${c.tactics.strong.includes(k) ? 'on' : c.tactics.weak.includes(k) ? 'weak' : ''}" title="${n}">${n}</span>`).join('')}</div></div>`;

    let days = 90, level = 'All', q = '', hideDone = false;
    const end = new Date(m.pulledOn || Date.now()).getTime();
    const visible = () => m.clusters.filter(c => (end - new Date(c.start)) / 864e5 <= days && (level === 'All' || c.level === level) && (!hideDone || !['Expected', 'Resolved'].includes(getT(c).s))
      && (!q || JSON.stringify([c.title, c.systems, c.key, c.other]).toLowerCase().includes(q)));
    const drawWindows = () => {
      const list = visible();
      $('cyWindows').innerHTML = list.map(c => { const t = getT(c); return `<div class="card win" id="${c.wid}" style="border-left:4px solid ${lvlCol[c.level]}">
        <div class="win-h"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span class="chip ${lvlChip[c.level]}">${c.level}</span><span class="mono sub" style="margin:0">${esc(fmtWhen(c.start))}${c.end.slice(0, 10) !== c.start.slice(0, 10) ? ` – ${esc(fmtWhen(c.end))}` : ''}</span><span class="chip tri ${TRI[t.s]}">${esc(t.s)}</span></div>
          <span class="triage msp"><select data-tri="${c.wid}" aria-label="Triage status">${Object.keys(TRI).map(s => `<option ${s === t.s ? 'selected' : ''}>${s}</option>`).join('')}</select><input data-note="${c.wid}" value="${esc(t.n)}" placeholder="Ticket or note" aria-label="Triage note"></span></div>
        <h3 style="margin:2px 0 0">${esc(c.title)}</h3>
        <p style="margin:0"><b>Why it’s flagged:</b> ${esc(c.reason)}.${t.n ? ` <span class="sub">Note: ${esc(t.n)}</span>` : ''}</p>
        <div class="tw"><table>${head}<tbody>${c.key.map(row).join('')}</tbody></table></div>
        ${c.other.length ? `<details class="tech"><summary class="sub">Show ${c.other.length} other change${c.other.length > 1 ? 's' : ''} in this window (no strong or partial match)</summary><div class="tw"><table>${head}<tbody>${c.other.map(row).join('')}</tbody></table></div></details>` : ''}
        ${chain(c)}
        <div class="two"><div><h4 class="mini">Why it matters</h4><p style="margin:0;font-size:14px">${esc(c.why)}</p></div><div><h4 class="mini">Check this</h4><ul style="margin:0;padding-left:18px;font-size:14px">${c.check.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></div>
      </div>`; }).join('') || `<p class="sub">No correlated windows match these filters${m.clusters.length ? ` (${m.clusters.length} in ${m.windowDays} days)` : ''}.</p>`;
      document.querySelectorAll('[data-tri]').forEach(s => s.addEventListener('change', () => { const c = m.clusters.find(x => x.wid === s.dataset.tri); setT(c, { ...getT(c), s: s.value }); drawWindows(); }));
      document.querySelectorAll('[data-note]').forEach(i => i.addEventListener('change', () => { const c = m.clusters.find(x => x.wid === i.dataset.note); setT(c, { ...getT(c), n: i.value }); drawWindows(); }));
      addCsvButtons($('cyWindows'), `${m.environment.Name}-cyber-window`);
      drawLanes();
    };

    // Swimlane: areas × time, with cluster bands. Bands and dots jump to their window.
    const drawLanes = () => {
      // Drawn at its real width, so the text doesn't scale up on wide screens.
      const W = Math.max(1000, Math.round((($('cyLanes') || {}).parentElement || {}).clientWidth || 1000)), left = 170, right = 16, top = 26, rowH = 36, H = top + m.areas.length * rowH + 8;
      const start = end - days * 864e5, x = t => left + (t - start) / (end - start) * (W - left - right);
      const shown = new Set(visible().map(c => c.wid));
      let g = '';
      m.clusters.filter(c => new Date(c.end).getTime() >= start).forEach(c => { const x0 = Math.max(left, x(new Date(c.start).getTime()) - 5), x1 = x(new Date(c.end).getTime()) + 5; g += `<rect class="band" data-w="${c.wid}" x="${x0}" y="${top - 4}" width="${Math.max(10, x1 - x0)}" height="${m.areas.length * rowH}" rx="4" fill="${lvlCol[c.level]}" fill-opacity="${shown.has(c.wid) ? '.16' : '.05'}" style="cursor:pointer"><title>${fmtDate(c.start)} · ${c.level}: ${esc(c.reason)}</title></rect>`; });
      for (let i = 0; i <= 3; i++) { const t = start + i * (end - start) / 3, xx = x(t); g += `<line x1="${xx}" x2="${xx}" y1="${top - 6}" y2="${H - 6}" stroke="var(--line)"/><text x="${xx}" y="14" fill="var(--muted)" font-size="12" font-family="IBM Plex Sans, Arial" text-anchor="${i === 0 ? 'start' : i === 3 ? 'end' : 'middle'}">${fmtDate(new Date(t).toISOString())}</text>`; }
      m.areas.forEach((a, i) => { const y = top + i * rowH + rowH / 2; g += `<line x1="${left}" x2="${W - right}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${left - 12}" y="${y + 4}" fill="var(--ink)" font-size="13" font-family="IBM Plex Sans, Arial" text-anchor="end">${a}</text>`; });
      const dc = { Strong: 'var(--crit)', Partial: 'var(--warn)' };
      m.dots.filter(d => new Date(d.at).getTime() >= start).forEach(d => { const i = m.areas.indexOf(d.area); if (i < 0) return; const y = top + i * rowH + rowH / 2; g += `<circle ${d.wid ? `data-w="${d.wid}" style="cursor:pointer"` : ''} cx="${x(new Date(d.at).getTime()).toFixed(1)}" cy="${y}" r="${dc[d.conf] ? 6 : 4}" fill="${dc[d.conf] || 'var(--none)'}" stroke="var(--surface)" stroke-width="1.5"><title>${esc(d.label)}</title></circle>`; });
      const svg = $('cyLanes'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.innerHTML = g;
    };
    $('cyLanes').addEventListener('click', e => { const t = e.target.closest('[data-w]'); if (!t) return; const el = $(t.dataset.w); if (el) { el.scrollIntoView({ behavior: SMOOTH(), block: 'start' }); el.classList.add('flash'); setTimeout(() => el.classList.remove('flash'), 1400); } });
    const pick = (id, attr, fn) => $(id).addEventListener('click', e => { const b = e.target.closest(`[${attr}]`); if (!b) return; [...$(id).children].forEach(x => x.setAttribute('aria-pressed', x === b)); fn(b.getAttribute(attr)); drawWindows(); });
    pick('cyRange', 'data-d', v => { days = +v; });
    pick('cyLevel', 'data-l', v => { level = v; });
    $('cyHideDone').addEventListener('change', e => { hideDone = e.target.checked; drawWindows(); });
    $('cyQ').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); drawWindows(); });
    drawWindows();

    // Coverage matrix: grouped by tactic in ATT&CK order. With no tactic picked, a technique that serves several tactics is
    // listed once, under the first; pick a tactic to see every technique that serves it (as ATT&CK counts them).
    const stChip = { Visible: 'c-ok', Partial: 'c-warn', Blind: 'c-crit' };
    const ord = { Blind: 0, Partial: 1, Visible: 2 };
    let st = 'All', tac = '', aq = '';
    const hay = r => [r.t, r.name, r.status, r.evidence, r.finding, (r.by || []).join(' '), r.tactics.map(tacName).join(' '), r.mit.map(x => `${x.id} ${x.name}`).join(' ')].join(' ').toLowerCase();
    const counts = list => ['Visible', 'Partial', 'Blind'].map(s => [s, list.filter(r => r.status === s).length]);
    const cell = r => `<tr><td class="wrap" data-csv="${esc(`${r.t} ${r.name}`)}"><a class="chip c-gold mono" style="text-decoration:none" href="${tUrl(r.t)}" target="_blank" rel="noopener" title="Open ${esc(r.t)} on attack.mitre.org">${r.t}</a><div style="margin-top:4px">${esc(r.name)}</div></td>
      <td class="wrap" style="font-size:12.5px" data-csv="${esc(r.tactics.map(tacName).join('; '))}">${r.tactics.map(tacName).map(esc).join(', ')}</td>
      <td data-csv="${r.status}"><span class="chip ${stChip[r.status]}">${r.status}</span>${r.changes ? `<div style="margin-top:4px"><span class="chip c-warn" title="Changes in the last ${m.windowDays} days classified as this technique (strong or partial match)">${r.changes} change${r.changes > 1 ? 's' : ''}</span></div>` : r.detects && r.status !== 'Blind' ? '<div class="sub" style="margin:4px 0 0">Changes watched</div>' : ''}</td>
      <td class="wrap" data-csv="${esc(r.evidence)}">${esc(r.evidence)}</td><td class="wrap">${esc(r.finding)}</td>
      <td class="wrap" data-csv="${esc(r.mit.map(x => `${x.id} ${x.name}`).join('; '))}">${r.mit.map(x => `<a class="chip c-none mono" style="text-decoration:none" href="https://attack.mitre.org/mitigations/${x.id}/" target="_blank" rel="noopener" title="${esc(x.name)}">${x.id}</a>`).join(' ')}</td></tr>`;
    const draw = () => {
      const base = m.cover.filter(r => (!tac || r.tactics.includes(tac)) && (!aq || hay(r).includes(aq)));
      [...$('atFilter').children].forEach(b => { const s = b.dataset.ats; b.textContent = `${s} (${s === 'All' ? base.length : base.filter(r => r.status === s).length})`; });
      const shown = base.filter(r => st === 'All' || r.status === st);
      const groups = m.tacticsList.map(([k, n, tid]) => [k, n, tid, shown.filter(r => tac ? k === tac : r.tactic === k)]).filter(g => g[3].length);
      // one tbody per tactic, headed by a row-group header, so screen readers tie each technique to its tactic.
      $('atTable').innerHTML = '<caption class="sr-only">ATT&amp;CK techniques by tactic for this client</caption><thead><tr><th>Technique</th><th>Tactics</th><th>For this client</th><th>Liongard evidence</th><th>What we see</th><th>Mitigations</th></tr></thead>' +
        (groups.map(([k, n, tid, rows]) => `<tbody><tr class="tac-h csv-skip"><th scope="rowgroup" colspan="6"><b>${esc(n)}</b> <span class="mono sub" style="margin:0">${tid}</span> <span class="sub" style="margin:0">· ${counts(rows).filter(c => c[1]).map(([s, c]) => `${c} ${s.toLowerCase()}`).join(', ')}</span></th></tr>` +
          rows.sort((a, b) => ord[a.status] - ord[b.status] || a.t.localeCompare(b.t)).map(cell).join('') + '</tbody>').join('') || `<tbody><tr><td colspan="6">No techniques match.</td></tr></tbody>`);
    };
    draw();
    $('atFilter').addEventListener('click', e => { const b = e.target.closest('[data-ats]'); if (!b) return; st = b.dataset.ats; [...$('atFilter').children].forEach(x => x.setAttribute('aria-pressed', x === b)); draw(); });
    $('atTac').addEventListener('change', e => { tac = e.target.value; draw(); });
    $('atQ').addEventListener('input', e => { aq = e.target.value.trim().toLowerCase(); draw(); });
  },
  how: m => [
    'Exposure right now: Liongard metric values for every inspector (POST /api/v2/metrics/evaluate/systems), identity inventory, Stack coverage, open alerts (GET /api/v1/tasks) and inspector health',
    `What changed: GET /api/v1/detections  (Environment/ID = ${m.environment.ID}, last ${m.windowDays} days). Each change is read for what was added, removed or changed, then classified against ATT&CK with a confidence level`,
    'Set aside as noise: counters and countdowns, timestamp-only GPO churn on 4+ days, and settings that flip back and forth (strong matches are never hidden)',
    'Correlated windows: changes within 24 hours that touch 2+ systems with strong or partial matches, or include a strong match',
    `Coverage: ${(m.coverSummary || {}).n} ATT&CK techniques that Liongard data can speak to. Visible, partly visible or blind depends on which inspectors this client runs (all 117 Liongard inspectors are mapped by capability). Techniques that need endpoint, network-traffic or log telemetry aren’t listed`,
    'ATT&CK Enterprise v20.0 IDs, names and tactics: src/main/catalog.js (tested against MITRE’s STIX data) · rules: src/main/panels/cyber.js',
  ].join('\n'),
};
// "Liongard evidences X of Y mapped techniques; Z in ATT&CK Enterprise v20.0".
function coverIntro(m) {
  const c = m.coverSummary;
  if (!c) return '';
  return `<p class="sub" id="atSummary">Liongard evidences <b>${c.evidenced} of ${c.n}</b> mapped techniques for this client: ${c.Visible} visible, ${c.Partial} partly visible, ${c.Blind} blind. ${c.attackTotal} techniques and sub-techniques in ATT&CK Enterprise v${esc(c.version)}; the ones not listed need endpoint, network-traffic or log telemetry Liongard doesn’t collect.<span class="no-print"> <b>Visible</b>: Liongard data shows the exposure or the change itself. <b>Partly</b>: settings and posture, without sign-in or event logs. <b>Blind</b>: this client runs no inspector that can see it.</span></p>`;
}
const PAGE_NAMES = { stack: 'Customer stack', identity: 'Identity', coverage: 'Stack coverage', wallboard: 'Wallboard', inspectors: 'Inspector health', network: 'Network', email: 'Email', lookup: 'Lookup' };
// Metric list items come as strings, arrays or objects; show them as readable text.
function plain(x) {
  if (x == null) return '';
  if (Array.isArray(x)) return x.map(plain).filter(Boolean).join(', ');
  if (typeof x === 'object') return Object.entries(x).map(([k, v]) => `${k}: ${plain(v)}`).join(', ');
  return String(x);
}
function short(n) { return String(n).replace(/^[^|:]+[|:]\s*/, '').replace(/\s*\|\s*/g, ': '); }
function groupBy(list, f) { const m = new Map(); for (const x of list) (m.get(f(x)) || m.set(f(x), []).get(f(x))).push(x); return [...m]; }
