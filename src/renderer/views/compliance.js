// Compliance at a glance view: the client's profile and in-scope frameworks, a posture score with its trend, the checks
// behind every score (with where the evidence came from and what the MSP marked), policy questions Liongard can't
// answer, and two reports: the evidence pack per framework and a quarterly review for the client.
window.VIEWS.compliance = {
  title: 'Compliance at a glance',
  kpiItems: {
    'Checks passing': m => m.checks.filter(x => x.status !== 'none').map(x => ({ t: x.name, d: x.evidence, page: x.page, q: '', sev: x.status === 'pass' ? 'ok' : x.status === 'partial' ? 'warn' : 'bad' })),
    'No evidence': m => m.checks.filter(x => x.status === 'none').map(x => ({ t: x.name, d: `${x.evidence}${x.fix ? `. ${x.fix}` : ''}`, page: x.page, q: '', sev: 'warn' })),
    'Least covered': m => m.frameworks.filter(f => f.scope !== 'out').sort((a, b) => a.evidenced / a.total - b.evidenced / b.total).map(f => ({ t: `${f.name}: ${f.evidenced} of ${f.total} ${f.unit} evidenced`, d: `${f.pass} pass · ${f.part} in part · ${f.fail} fail · ${f.attested + f.recorded} recorded by you · ${f.awaiting + f.expired + f.na} to answer` })),
    // Distinct failing checks: one MFA gap is one failing check, however many frameworks cite it.
    'Checks failing': m => m.checks.filter(x => x.status === 'fail').map(x => ({ t: x.name, d: `${x.evidence}${Object.keys(x.refs || {}).filter(k => (x.refs[k] || []).length).length ? ` · cited by ${Object.keys(x.refs).filter(k => (x.refs[k] || []).length).length} frameworks` : ''}`, page: x.page, q: '', sev: x.mark && x.mark.state === 'exception' ? 'warn' : 'bad' })),
  },
  intro: 'Technical-control evidence from Liongard, mapped to the frameworks that apply to this client. It covers the technical controls Liongard can see, over the assets that reported. Policies, people and process are answered on this page or by an assessor.',
  exports: [
    { label: 'PDF: evidence pack for the selected framework', mode: 'review', title: 'Compliance evidence pack', kicker: 'Control-by-control evidence' },
    { label: 'PDF: quarterly security review for the client', run: async () => { document.body.classList.add('print-qbr'); try { await exportPdf('review', 'Quarterly security review', 'Security review'); } finally { document.body.classList.remove('print-qbr'); } } },
  ],
  render(m) {
    const col = v => v == null ? 'var(--none)' : v >= 80 ? 'var(--ok)' : v >= 50 ? 'var(--warn)' : 'var(--crit)';
    const col10 = v => col(v == null ? null : v * 10);
    const delta = (now, then, unit = '') => now == null || then == null || now === then ? '' : `<span class="cp-delta ${now > then ? 'up' : 'down'}">${now > then ? '▲' : '▼'} ${Math.abs(Math.round((now - then) * 10) / 10)}${unit}</span>`;
    const p = m.profile || {}, base = m.base;
    const inScope = m.frameworks.filter(f => f.scope !== 'out'), outScope = m.frameworks.filter(f => f.scope === 'out');
    const opt = (list, v) => `<option value="">Choose…</option>` + list.map(x => `<option${x === v ? ' selected' : ''}>${esc(x)}</option>`).join('');
    const profileLine = m.profile ? [p.industry, p.region, p.cards && 'takes card payments', p.insurance && 'has cyber insurance', p.iso && 'ISO 27001', `target ${m.target}`].filter(Boolean).join(' · ') : 'Not set: every framework is shown';
    // Trend chart: posture over the saved snapshots (last 24).
    const H = m.history.filter(h => h.posture != null).slice(-24);
    const trend = (() => {
      if (H.length < 2) return '<p class="sub">The trend starts after the next data pull. A snapshot is saved every time this client’s data is pulled from Liongard.</p>';
      const W = 520, Ht = 150, L = 30, R = 12, T = 12, B = 26, t0 = +new Date(H[0].at), t1 = +new Date(H[H.length - 1].at) || t0 + 1;
      const x = t => L + (t1 === t0 ? 0 : (+new Date(t) - t0) / (t1 - t0) * (W - L - R)), y = v => T + (10 - v) / 10 * (Ht - T - B);
      const pts = H.map(h => `${x(h.at).toFixed(1)},${y(h.posture).toFixed(1)}`).join(' ');
      return `<svg viewBox="0 0 ${W} ${Ht}" class="cp-trend" role="img" aria-label="Posture score from ${H[0].posture} to ${H[H.length - 1].posture}">
        ${[0, 5, 10].map(v => `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="gl"/><text x="4" y="${y(v) + 4}" class="ax">${v}</text>`).join('')}
        <text x="${L}" y="${Ht - 6}" class="ax">${esc(fmtDate(H[0].at, true))}</text><text x="${W - R}" y="${Ht - 6}" class="ax" text-anchor="end">${esc(fmtDate(H[H.length - 1].at, true))}</text>
        <polyline points="${pts}" class="ln"/>${H.map(h => `<circle cx="${x(h.at).toFixed(1)}" cy="${y(h.posture).toFixed(1)}" r="3.5" class="pt"><title>${esc(fmtDate(h.at, true))}: ${h.posture}</title></circle>`).join('')}
      </svg>`;
    })();
    const heatBand = v => v < 2 ? 'h0' : v < 4 ? 'h1' : v < 6 ? 'h2' : v < 7 ? 'h3' : v < 8.5 ? 'h4' : 'h5';
    // Radar: every area with data, current against the client's target.
    const RA = m.areas.filter(a => a.score != null), under = RA.filter(a => a.score < m.target).sort((a, b) => a.score - b.score);
    const radar = (() => {
      if (RA.length < 3) return '<p class="sub">The radar needs at least three areas with data.</p>';
      const cx = 230, cy = 190, R = 130, n = RA.length;
      const pt = (i, v) => { const a = -Math.PI / 2 + i * 2 * Math.PI / n; return [cx + Math.cos(a) * R * v / 10, cy + Math.sin(a) * R * v / 10]; };
      const poly = vals => vals.map((v, i) => pt(i, v).map(x => x.toFixed(1)).join(',')).join(' ');
      return `<svg class="cp-radar" viewBox="0 0 460 380" role="group" aria-label="Area scores against the target of ${m.target}">
        ${[2, 4, 6, 8, 10].map(r => `<polygon class="gr" points="${poly(RA.map(() => r))}"/><text class="vl" x="${cx + 4}" y="${cy - R * r / 10 + 4}">${r}</text>`).join('')}
        ${RA.map((a, i) => { const [x, y] = pt(i, 10); return `<line class="sp" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/>`; }).join('')}
        <polygon class="tg" points="${poly(RA.map(() => m.target))}"/><polygon class="cu" points="${poly(RA.map(a => a.score))}"/>
        ${RA.map((a, i) => { const [x, y] = pt(i, a.score); return `<circle class="dt${a.score < m.target ? ' under' : ''}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5"><title>${esc(a.name)}: ${a.score}</title></circle>`; }).join('')}
        ${RA.map((a, i) => { const [x, y] = pt(i, 11.8); const an = Math.abs(x - cx) < 10 ? 'middle' : x > cx ? 'start' : 'end'; return `<text class="lb" data-area="${esc(a.name)}" x="${x.toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="${an}" tabindex="0" role="button">${esc(a.name)} <tspan class="vl">${a.score.toFixed(1)}</tspan></text>`; }).join('')}
      </svg>`;
    })();
    // Area strip: each area across the saved snapshots (the last 12).
    const SH = m.history.filter(h => h.areas).slice(-12);
    const strip = SH.length < 2 ? '<p class="sub">This fills in as data pulls are saved: one column per pull.</p>'
      : `<div class="tw"><div class="cp-strip" style="grid-template-columns:90px repeat(${SH.length}, minmax(38px,1fr))"><div></div>${SH.map(h => `<div class="sub" style="margin:0;text-align:center;font-size:11px">${esc(fmtDate(h.at))}</div>`).join('')}
        ${m.areas.map(a => `<button type="button" class="rl" data-area="${esc(a.name)}">${esc(a.name)} ›</button>` + SH.map(h => { const v = h.areas[a.name]; return v == null ? '<div class="c na">–</div>' : `<div class="c ${heatBand(v)}" title="${esc(a.name)}, ${esc(fmtDate(h.at, true))}: ${v}">${v.toFixed(1)}</div>`; }).join('')).join('')}</div></div>`;
    const qOf = fw => m.questions.filter(q => !fw || (q.refs[fw] || []).length);
    return `
      <details class="card cp-profile no-print"${m.profile && !m.profile.fromDefaults ? '' : ' open'}>
        <summary><span class="cp-plabel">Client profile</span> <b>${esc(profileLine)}</b> <span class="sub" style="margin:0">· ${m.profile && !m.profile.fromDefaults ? 'Edit' : 'Set the profile to show only the frameworks that apply'}</span></summary>
        ${m.profile && !m.profile.fromDefaults ? '' : `<p class="cp-ask"><b>Which of these apply to ${esc(m.environment.Name)}?</b> Until you answer, every framework is shown and the launcher asks for the profile instead of adding failures up across frameworks.</p>`}
        <form id="cpForm" class="cp-form">
          <label>Industry<select name="industry">${opt(m.options.industries, p.industry)}</select></label>
          <label>Region<select name="region">${opt(m.options.regions, p.region)}</select></label>
          <label class="ck"><input type="checkbox" name="cards"${p.cards ? ' checked' : ''}> Takes card payments</label>
          <label class="ck"><input type="checkbox" name="insurance"${p.insurance ? ' checked' : ''}> Has cyber insurance</label>
          <label class="ck"><input type="checkbox" name="iso"${p.iso ? ' checked' : ''}> Holds or wants ISO 27001</label>
          <label>Target score (out of 10)<input type="number" name="target" min="1" max="10" step="0.5" value="${m.target}" style="width:110px"></label>
          <div class="row-actions"><button class="btn" type="submit">Save profile</button>${m.profile ? '<button class="btn ghost" type="button" id="cpClear">Clear profile</button>' : ''}</div>
        </form>
        <p class="sub cp-brand" style="margin:8px 0 0">Branding: <b id="cpBrandName">${esc(((typeof SETTINGS !== 'undefined' && SETTINGS && SETTINGS.branding) || {}).name || 'Your MSP')}</b> (<a href="settings.html#msp">change in Settings</a>). One name and logo for every report.</p>
      </details>

      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>


      <h3>Security posture</h3>
      <div class="cp-two">
        <div class="card cp-score">
          <div class="cp-ring" style="--p:${(m.posture || 0) * 10};--c:${col10(m.posture)}"><div><b>${m.posture == null ? '—' : m.posture.toFixed(1)}</b><small>out of 10</small>${base ? delta(m.posture, base.posture) : ''}</div></div>
          <div class="cp-areas">${m.areas.map(a => `<div class="cp-area"><button type="button" class="linkish cp-alink" data-area="${esc(a.name)}">${esc(a.name)}</button>
            <div class="cp-track" title="${a.score == null ? 'No evidence' : `${a.score} out of 10`}"><i style="width:${(a.score || 0) * 10}%;background:${col10(a.score)}"></i>${base && base.areas && base.areas[a.name] != null ? `<em style="left:${base.areas[a.name] * 10}%" title="${esc(fmtDate(base.at, true))}: ${base.areas[a.name]}"></em>` : ''}</div>
            <b>${a.score == null ? '<span class="sub" style="margin:0" title="No evidence">No data</span>' : a.score.toFixed(1)}</b></div>`).join('')}
            <span class="sub" style="margin:0">${base ? `Tick = score on ${esc(fmtDate(base.at, true))}, the snapshot nearest a quarter ago.` : 'Pass = 1, partial = 0.5, fail = 0, over the checks with data.'}</span></div>
        </div>
        <div class="card"><b>Score by area against the target</b>${radar}
          <div class="cp-rleg"><span class="c">Current score</span><span class="t">Target ${m.target}</span></div>
          <p class="sub" style="margin:0">${under.length ? `Below target: ${under.map(a => `<b>${esc(a.name)}</b> ${a.score.toFixed(1)} (−${(m.target - a.score).toFixed(1)})`).join(' · ')}` : `Every area with data meets the target of ${m.target}.`} Click an area to see what’s behind it.</p></div>
      </div>

      <h3>Where the gaps are</h3>
      <p class="sub">Each framework’s score in each area, out of 10, from the same checks. A dashed outline is below the client’s target (${m.target}). Click a cell to see the checks, then the people, devices and network gear behind them.</p>
      <div class="card"><div class="tw"><div class="cp-heat" id="cpHeat" style="grid-template-columns:minmax(150px,1.4fr) repeat(${m.areas.length}, minmax(64px,1fr))">
        <div></div>${m.areas.map(a => `<div class="ch">${esc(a.name)}</div>`).join('')}
        ${m.heat.map(f => `<div class="rh">${esc(f.key === 'INS' ? 'Cyber insurance' : f.name.replace(/ \(.*\)$/, '').replace(/ v[\d.]+$/, ''))}</div>` + f.cells.filter(c => m.areas.some(a => a.name === c.area)).map(c => c.score == null
          ? `<div class="cp-cell na" title="${esc(f.name)} has no ${esc(c.area)} checks with data">–</div>`
          : `<button type="button" class="cp-cell ${heatBand(c.score)}${c.score < m.target ? ' under' : ''}" data-area="${esc(c.area)}" data-fw="${f.key}" title="${esc(f.name)} · ${esc(c.area)}: ${c.score.toFixed(1)}">${c.score.toFixed(1)}</button>`).join('')).join('')}
      </div></div>
      <div class="cp-hleg">Score: ${[['h0', '0–2'], ['h1', '2–4'], ['h2', '4–6'], ['h3', '6–7'], ['h4', '7–8.5'], ['h5', '8.5–10']].map(([c, l]) => `<i class="cp-cell ${c}"></i>${l}`).join(' ')} <i class="cp-cell na"></i>no checks with data</div></div>

      <h3>Over time</h3>
      <div class="cp-two">
        <div class="card"><b>Posture score</b>${trend}</div>
        <div class="card"><b>Each area at every data pull</b>${strip}</div>
      </div>

      <h3>Frameworks${m.profile ? ' in scope' : ''}</h3>
      <p class="sub no-print">Pick a framework to see only its checks, references and questions, and to export its evidence pack.</p>
      <div class="cards" style="grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr))" id="fwCards">${inScope.map(f => `
        <div class="card fwcard" data-fw="${f.key}" role="button" tabindex="0" style="text-align:left;cursor:pointer">
          <div class="cp-fwh"><b>${esc(f.name)}</b>${m.profile ? `<button type="button" class="cp-x no-print" data-hide="${f.key}" title="Take ${esc(f.name)} out of scope" aria-label="Take ${esc(f.name)} out of scope">×</button>` : ''}</div>
          <span><span style="font:700 30px/1 var(--f-display)">${f.evidenced}</span> <span class="sub" style="margin:0">of ${f.total} ${esc(f.unit)} evidenced by Liongard</span></span>
          <div class="cp-stk" aria-hidden="true">${[['pass', f.pass, 'var(--ok)'], ['part', f.part, 'var(--warn)'], ['fail', f.fail, 'var(--crit)'], ['rec', f.attested + f.recorded, 'var(--blue)'], ['todo', f.awaiting + f.expired + f.na, 'var(--line)']].map(([k, n, c]) => n ? `<i style="width:${n / f.total * 100}%;background:${c}" title="${n}"></i>` : '').join('')}</div>
          <span class="sub" style="margin:0"><b style="color:var(--ok-ink)">${f.pass} pass</b> · <b style="color:var(--warn-ink)">${f.part} in part</b> · <b style="color:var(--crit)">${f.fail} fail</b>${f.risk ? ` (${f.risk} accepted risk)` : ''}</span>
          <span class="sub" style="margin:0">${f.attested + f.recorded} recorded by you · ${f.awaiting + f.expired + f.na} to answer${f.expired ? ` (<b class="cp-stale">${f.expired} expired</b>)` : ''}${f.provisional ? ` · <b>${f.unread} source${f.unread === 1 ? '' : 's'} couldn’t be read</b>` : ''}</span>
          ${f.policy.total ? `<span class="sub" style="margin:0">Policy questions: ${f.policy.answered ? `${f.policy.yes} of ${f.policy.total} yes${f.policy.answered < f.policy.total ? `, ${f.policy.total - f.policy.answered} unanswered` : ''}` : `${f.policy.total} unanswered`}</span>` : ''}
          <span class="sub" style="margin:0">${esc(f.why || f.note)}</span>
        </div>`).join('')}</div>
      ${outScope.length ? `<div class="cp-out no-print"><span class="sub" style="margin:0">Not in scope for this profile:</span> ${outScope.map(f => `<button type="button" class="chip-btn" data-add="${f.key}" title="Add ${esc(f.name)} to this client’s scope">+ ${esc(f.name)}</button>`).join('')}</div>` : ''}
      <h3 style="margin-top:22px">Fix once, improve many</h3>
      <p class="sub">Every check against every framework in scope. A row with red across many columns is the most valuable fix; “If fixed” is the framework points it would add. Click a row to see what’s affected.</p>
      <div class="card"><div class="tw"><div class="cp-mx" style="grid-template-columns:minmax(230px,2fr) repeat(${inScope.length}, minmax(58px,1fr)) 86px">
        <div></div>${inScope.map(f => `<div class="ch">${esc(f.key === 'INS' ? 'Insurance' : f.key)}</div>`).join('')}<div class="ch">If fixed</div>
        ${[...m.checks].sort((a, b) => (b.gain || 0) - (a.gain || 0) || ({ fail: 0, partial: 1, none: 2, pass: 3 }[a.status] - { fail: 0, partial: 1, none: 2, pass: 3 }[b.status])).map(c => `<button type="button" class="rh" data-check="${c.key}"><span class="n">${esc(c.name)}</span>${(c.items || []).length ? `<span class="sub" style="margin:0">${c.items.length} affected ›</span>` : ''}</button>` +
          inScope.map(f => (c.refs[f.key] || []).length ? `<div class="sq s-${c.unread ? 'none' : c.status}" title="${esc(c.name)} · ${esc(f.name)}: ${esc(c.refs[f.key].join(', '))}">${{ pass: '✓', partial: '!', fail: '✕', none: '–' }[c.unread ? 'none' : c.status]}</div>` : '<div class="sq s-blank" title="Not in this framework"></div>').join('') +
          `<div class="gn">${c.gain ? `+${c.gain} pts` : ''}</div>`).join('')}
      </div></div>
      <div class="cp-hleg"><span class="sq s-pass">✓</span>Pass <span class="sq s-partial">!</span>Partial <span class="sq s-fail">✕</span>Fail <span class="sq s-none">–</span>No evidence <span class="sq s-blank"></span>Not in this framework</div></div>

      <h3 style="margin-top:22px">Remediation list</h3>
      <p class="sub">People, devices, domains and network gear added from the drill-downs on this page. It’s also on the Action plan. An item is <b>verified fixed</b> only when Liongard’s data no longer finds it.</p>
      <div class="card cp-prog">${m.progress.map(g => `<button type="button" class="pr" data-sev="${g.sev}"${g.total ? '' : ' disabled'}><b>${g.sev}</b>
        <span class="stk" title="${g.verified} verified, ${g.done} marked done, ${g.progress} in progress, ${g.open} open">${g.total ? [['pv', g.verified], ['pd', g.done], ['pp', g.progress], ['po', g.open]].map(([k, n]) => n ? `<i class="${k}" style="width:${n / g.total * 100}%"></i>` : '').join('') : ''}</span>
        <span class="sub" style="margin:0">${g.total ? `<b style="color:var(--text)">${Math.round(g.verified / g.total * 100)}%</b> verified · ${g.open} open` : 'Nothing added'}</span></button>`).join('')}
        <div class="cp-hleg" style="margin:0"><i class="pv"></i>Verified fixed <i class="pd"></i>Marked done <i class="pp"></i>In progress <i class="po"></i>Open</div></div>
      <div id="cpRem"></div>

      <h3 style="margin-top:22px" id="ckTitle">Checks and evidence</h3>
      <div class="quick no-print" id="ckF">${[['all', 'All'], ['fail', 'Failing'], ['partial', 'Partial'], ['none', 'No evidence'], ['pass', 'Passing'], ['marked', 'Marked']].map(([k, l], i) => `<button type="button" data-s="${k}" aria-pressed="${i === 0}">${l}</button>`).join('')}</div>
      <div class="tw"><table id="ckTable"></table></div>
      <p class="sub">Frameworks show how many of their controls Liongard evidences, and the results over those; a control fails if any check behind it fails. The posture and heat-map scores are an internal trend (pass 1, partial 0.5, fail 0, over checks with data). Attestations and your own evidence are shown beside the results and never count as a pass. <b>Marked done</b> becomes <b>Verified fixed</b> only when Liongard’s next data agrees, and <b>Reopened</b> if it doesn’t.</p>

      <h3 style="margin-top:22px" id="qTitle">Questions Liongard can’t answer</h3>
      <p class="sub" id="qSub"></p>
      <div class="tw"><table id="qTable"></table></div>

      <h3 style="margin-top:22px" id="evTitle">Evidence pack</h3>
      <p class="sub">Every control in the framework’s own numbering: what Liongard tested, what it can’t see, who and what is affected, and what you’ve recorded. Controls Liongard can’t assess are listed too, so you can record your own evidence or an attestation. Export it from <b>Export › PDF: evidence pack</b>.</p>
      <div class="filters no-print cp-evbar">
        <label class="fld-inline">Framework <select id="evFw" aria-label="Framework for the evidence pack"></select></label>
        <span class="seg msp" id="evPeople" role="group" aria-label="How people are shown"><button type="button" data-v="counts" aria-pressed="true">Counts + restricted appendix</button><button type="button" data-v="names" aria-pressed="false">Names</button><button type="button" data-v="pseudo" aria-pressed="false">Pseudonyms</button></span>
        <span class="seg" id="evShow" role="group" aria-label="Which controls"><button type="button" data-v="all" aria-pressed="true">All</button><button type="button" data-v="ev" aria-pressed="false">Evidenced</button><button type="button" data-v="todo" aria-pressed="false">To answer</button><button type="button" data-v="mine" aria-pressed="false">Recorded by you</button></span>
        <button type="button" class="btn ghost sm" id="evOpen">Expand all</button>
      </div>
      <div id="evView"></div>
      <div class="review-only" id="evPack"></div>
      <dialog id="ctlDlg" class="cp-dlg"><form method="dialog" id="ctlForm">
        <h3 id="ctlTitle"></h3><p class="sub" id="ctlSub"></p>
        <label id="ctlResL">Result<select name="result"><option value="met">Met</option><option value="partly">Partly met</option><option value="notmet">Not met</option><option value="na">Not applicable</option></select></label>
        <label><span id="ctlNoteL">Statement</span><textarea name="note" rows="4" maxlength="1000" required></textarea></label>
        <label><span id="ctlByL">Who confirms it (name and role)</span><input name="by" type="text" maxlength="120" required></label>
        <label><span id="ctlRefL">Evidence (document name and where it’s kept)</span><input name="ref" type="text" maxlength="200"></label>
        <label><span id="ctlUntilL">Expires</span><input name="until" type="date" required></label>
        <div class="row-actions"><button class="btn" value="save">Save</button><button class="btn ghost" value="cancel" formnovalidate>Cancel</button></div>
      </form></dialog>
      <div class="review-only" id="qbrPack"></div>
      <dialog id="mkDlg" class="cp-dlg"><form method="dialog" id="mkForm">
        <h3 id="mkTitle"></h3><p class="sub" id="mkSub"></p>
        <label>Note<textarea name="note" rows="3" maxlength="300"></textarea></label>
        <label>Recorded by<input name="by" type="text" maxlength="80"></label>
        <label id="mkUntilL">Accepted until<input name="until" type="date"></label>
        <div class="row-actions"><button class="btn" value="save">Save</button><button class="btn ghost" value="cancel" formnovalidate>Cancel</button></div>
      </form></dialog>`;
  },
  after(m, ctx) {
    const st = { pass: '<i class="tick t-ok">✓</i>', partial: '<i class="tick t-warn">!</i>', fail: '<i class="tick t-bad">✕</i>', none: '<i class="tick t-none">–</i>' };
    const lab = { pass: 'Pass', partial: 'Partial', fail: 'Fail', none: 'No evidence' };
    const STATE = { verified: ['ok', 'Verified fixed'], reopened: ['bad', 'Reopened'], awaiting: ['warn', 'Marked done'], attested: ['info', 'Attested'], exception: ['none', 'Exception'], expired: ['warn', 'Expired'], superseded: ['none', 'Evidence wins'] };
    const STATE_WHY = {
      verified: c => `Marked done ${fmtDate(c.mark.at, true)} · Liongard’s data confirms it`, reopened: c => `Marked done ${fmtDate(c.mark.at, true)} · Liongard’s newer data still shows it ${c.status === 'partial' ? 'partly' : 'failing'}`,
      awaiting: c => `Marked done ${fmtDate(c.mark.at, true)} · waiting for the next data pull`, attested: c => `Attested ${fmtDate(c.mark.at, true)}, renew by ${fmtDate(new Date(+new Date(c.mark.at) + 365 * 864e5).toISOString(), true)}`,
      exception: c => `Risk accepted until ${c.mark.until ? fmtDate(c.mark.until, true) : 'further notice'}`, expired: c => c.mark.state === 'attested' ? `Attestation from ${fmtDate(c.mark.at, true)} is over 12 months old` : `Exception ended ${fmtDate(c.mark.until, true)}`,
      superseded: c => `${c.mark.state === 'attested' ? 'Attested' : 'Exception recorded'} ${fmtDate(c.mark.at, true)}, but Liongard now has data for this check`,
    };
    const PAGE_NAME = { identity: 'Identity & access', coverage: 'Stack coverage', network: 'Network & firmware', email: 'Email & domain security', licences: 'Licence reconciliation', stack: 'Customer stack', inspectors: 'Inspector health' };
    const ANS = { yes: ['ok', 'Yes'], partly: ['warn', 'Partly'], no: ['bad', 'No'] };
    const reload = () => (typeof load === 'function' ? load(false) : location.reload());
    const srcText = c => !c.sources ? '' : `<div class="cp-src">${c.sources.tools.map(t => toolName(t)).join(' ')} · ${c.sources.days == null ? 'no data yet' : c.sources.days === 0 ? 'read today' : `oldest read ${agoText(c.sources.days)}`}${c.sources.stale ? ` · <b class="cp-stale">${c.sources.stale} of ${c.sources.of} stale or failing</b>` : ''}</div>`;
    const stateTag = c => c.state ? `<div><span class="cp-tag t-${STATE[c.state][0]}">${STATE[c.state][1]}</span></div><div class="sub" style="margin:2px 0 0">${esc(STATE_WHY[c.state](c))}${c.mark.note ? ` · “${esc(c.mark.note)}”` : ''}${c.mark.by ? ` · ${esc(c.mark.by)}` : ''}</div>` : '';
    const actions = c => c.unread ? '' : `<div class="cp-acts no-print">${
      c.mark ? `<button type="button" class="btn ghost sm" data-mk="clear" data-k="${c.key}">Clear mark</button>`
      : c.status === 'none' ? '<span class="sub" style="margin:0">Record your own evidence on the controls in the evidence pack below</span>'
      : c.status === 'pass' ? '' : `<button type="button" class="btn ghost sm" data-mk="done" data-k="${c.key}">Mark done</button><button type="button" class="btn ghost sm" data-mk="exception" data-k="${c.key}">Accept risk</button>`}</div>`;
    // With no framework picked, references are listed for the frameworks in scope only.
    const scoped = new Set(m.frameworks.filter(f => f.scope !== 'out').map(f => f.key));
    const refList = refs => Object.entries(refs).filter(([k, v]) => v.length && scoped.has(k)).map(([k, v]) => `${k === 'INS' ? 'Insurance' : k} ${v.join(', ')}`).map(esc).join('<br>') || '<span class="sub" style="margin:0">Not in a framework in scope</span>';
    let fw = '', s = 'all';
    const draw = () => {
      const f = m.frameworks.find(x => x.key === fw);
      const rows = m.checks.filter(c => (!fw || (c.refs[fw] || []).length) && (s === 'all' || (s === 'marked' ? !!c.mark : c.status === s)));
      $('ckTitle').textContent = f ? `${f.name}: checks and evidence` : 'Checks and evidence';
      $('ckTable').innerHTML = `<thead><tr><th>Check</th><th>Result</th><th>Evidence from Liongard</th><th>What to do</th><th>${f ? esc(f.key) : 'Frameworks'}</th></tr></thead><tbody>` + (rows.map(c => `<tr>
        <td class="wrap" style="min-width:180px"><b>${esc(c.name)}</b>${c.page ? `<div class="sub" style="margin:0">${pageA(c.page, '', `${PAGE_NAME[c.page] || c.page} →`)}</div>` : ''}</td>
        <td data-csv="${lab[c.status]}${c.state ? ` (${STATE[c.state][1]})` : ''}" style="min-width:150px"><span style="white-space:nowrap">${st[c.status]} ${lab[c.status]}</span>${stateTag(c)}</td>
        <td class="wrap">${esc(c.evidence)}${(c.items || []).length ? ` <button type="button" class="linkish no-print" data-affected="${c.key}">See ${c.items.length} affected ›</button>` : ''}${srcText(c)}</td><td class="wrap">${esc(c.fix)}${actions(c)}</td>
        <td class="wrap mono" style="font-size:11.5px">${f ? esc((c.refs[fw] || []).join(', ')) : refList(c.refs)}</td></tr>`).join('') || '<tr><td colspan="5">No checks match.</td></tr>') + '</tbody>';
      document.querySelectorAll('.fwcard').forEach(b => b.classList.toggle('picked', b.dataset.fw === fw));
      // Policy questions for the chosen framework (or all of them).
      const qs = m.questions.filter(q => fw ? (q.refs[fw] || []).length : Object.entries(q.refs).some(([k, v]) => v.length && scoped.has(k)));
      const auto = m.checks.filter(c => (!fw || (c.refs[fw] || []).length) && c.status !== 'none').length;
      $('qTitle').textContent = f ? `${f.name}: questions Liongard can’t answer` : 'Questions Liongard can’t answer';
      $('qSub').innerHTML = `<b>${auto}</b> technical question${auto === 1 ? ' is' : 's are'} answered from Liongard evidence (the checks above). These ${qs.length} are about policy and process, so someone at the client or the MSP answers them. They’re shown next to the score, not in it.`;
      $('qTable').innerHTML = `<thead><tr><th>Question</th><th>Answer</th><th>${f ? esc(f.key) : 'Frameworks'}</th></tr></thead><tbody>` + (qs.map(q => `<tr>
        <td class="wrap"><b>${esc(q.name)}</b>${q.answer && q.answer.note ? `<div class="sub" style="margin:0">“${esc(q.answer.note)}”${q.answer.by ? ` · ${esc(q.answer.by)}` : ''} · ${esc(fmtDate(q.answer.at, true))}</div>` : q.answer ? `<div class="sub" style="margin:0">${q.answer.by ? `${esc(q.answer.by)} · ` : ''}${esc(fmtDate(q.answer.at, true))}</div>` : ''}</td>
        <td data-csv="${q.answer ? ANS[q.answer.state][1] : 'Unanswered'}" style="white-space:nowrap"><span class="cp-ans no-print">${Object.entries(ANS).map(([k, [, l]]) => `<button type="button" data-q="${q.key}" data-a="${k}" aria-pressed="${q.answer && q.answer.state === k}">${l}</button>`).join('')}</span>${q.answer ? ` <button type="button" class="linkish no-print" data-q="${q.key}" data-a="clear">Clear</button>` : ''}</td>
        <td class="wrap mono" style="font-size:11.5px">${f ? esc((q.refs[fw] || []).join(', ')) : refList(q.refs)}</td></tr>`).join('') || '<tr><td colspan="3">No policy questions for this framework.</td></tr>') + '</tbody>';
      if (f && $('evFw').value !== f.key) { $('evFw').value = f.key; drawEv(); }   // picking a framework card also picks it for the evidence pack
    };
    // Quarterly review for the client: before and after, what improved, what's next. Printed from Export.
    // ---------- Evidence pack: every control of one framework, as the specialist specified ----------
    // On screen with buttons to record your own evidence; the same pack, fully open, goes into the PDF.
    const PST = { pass: ['Pass', 'c-ok', 'var(--ok)'], partial: ['Partial', 'c-warn', 'var(--warn)'], inpart: ['Evidenced in part', 'c-warn', 'var(--warn)'], fail: ['Fail', 'c-crit', 'var(--crit)'],
      risk: ['Accepted risk', 'c-crit', 'var(--crit)'], attested: ['Attested', 'c-blue', 'var(--blue)'], recorded: ['Recorded by you', 'c-blue', 'var(--blue)'], awaiting: ['Awaiting attestation', 'c-none', 'var(--line)'],
      expired: ['Record expired', 'c-warn', 'var(--warn)'], na: ['Not assessed', 'c-none', 'var(--line)'] };
    const RES = { met: 'Met', partly: 'Partly met', notmet: 'Not met', na: 'Not applicable' };
    const PERSON = new Set(['User', 'Admin']);
    const NAMED_HOST = /^[A-Za-z]{3,}-(LT|PC|DT|MBP|LAPTOP|DESKTOP)\d*$/i;   // a hostname built from a person's name
    const remBy = Object.fromEntries((m.remediation || []).map(r => [r.id, r]));
    let evPeople = 'counts', evShow = 'all', evOpen = false;
    const inScopeFw = m.frameworks.filter(x => x.scope !== 'out');
    $('evFw').innerHTML = (inScopeFw.length ? inScopeFw : m.frameworks).map(x => `<option value="${x.key}">${esc(x.name)} (${x.total})</option>`).join('');
    function packHtml(fwKey, screen) {
      const f = m.frameworks.find(x => x.key === fwKey); if (!f) return '';
      const pseudo = new Map(), nick = (k, base) => { if (!pseudo.has(k)) pseudo.set(k, `${base} ${[...pseudo.values()].filter(v => v.startsWith(base)).length + 1}`); return pseudo.get(k); };
      const who = (it, mode) => PERSON.has(it.kind) ? (mode === 'names' ? esc(it.t) : mode === 'pseudo' ? `${nick(it.t, 'User')}${it.kind === 'Admin' ? ' (admin account)' : ''}` : '<span class="sub" style="margin:0">Person: see the restricted appendix</span>')
        : mode !== 'names' && NAMED_HOST.test(it.t) ? `${nick(it.t, 'Device')} <span class="sub" style="margin:0">(hostname names a person)</span>` : esc(it.t);
      const shown = f.controls.filter(c => evShow === 'all' || (evShow === 'ev' && ['pass', 'partial', 'inpart', 'fail', 'risk'].includes(c.status)) || (evShow === 'todo' && ['awaiting', 'na', 'expired'].includes(c.status)) || (evShow === 'mine' && c.mark));
      const appendix = [];
      const block = c => {
        const [label, chip, colr] = PST[c.status], res = c.checks.map(k => m.checks.find(x => x.key === k)).filter(Boolean);
        const liongard = ['full', 'partial'].includes(c.rating) && res.length;
        const items = liongard ? res.flatMap(x => (x.items || []).map(it => ({ ...it, check: x.key }))) : [];
        items.filter(it => PERSON.has(it.kind)).forEach(it => appendix.push({ ctl: c.id, it }));
        const mk = c.mark;
        const pop = liongard ? res.filter(x => x.pop).map(x => `<div><span class="sub" style="margin:0">${esc(x.name)} · ${esc(x.pop.unit)}</span><div class="cp-pop"><span>in scope <b>${x.pop.inScope}</b></span><span>evaluated <b>${x.pop.evaluated}</b></span><span>passing <b>${x.pop.passing}</b></span></div>${x.pop.evaluated < x.pop.inScope ? `<div class="sub" style="margin:0">${x.pop.inScope - x.pop.evaluated} not reporting: not counted as passing</div>` : ''}</div>`).join('') : '';
        const srcs = liongard ? res.filter(x => x.sources).map(x => `<div>${esc(x.sources.tools.join(', '))} · ${x.sources.days == null ? 'no data yet' : x.sources.days === 0 ? 'read on the day of the pull' : `oldest read ${x.sources.days} day${x.sources.days === 1 ? '' : 's'} before the pull`}${x.sources.stale ? ` <b class="cp-stale">· provisional: ${x.sources.stale} of ${x.sources.of} stale or failing</b>` : ''}</div>`).join('') : '';
        const exRows = items.slice(0, 60).map(it => { const r = remBy[`${it.check}|${it.t}`.slice(0, 300)]; return `<tr><td>${who(it, evPeople)}</td><td>${esc(it.d || '')}</td><td>${r ? `${esc(r.owner || 'No owner')}${r.due ? ` · due ${esc(fmtDate(r.due, true))}` : ''} · ${esc((REM_STATE[r.state] || [r.state])[0])}` : '<span class="sub" style="margin:0">Not on the remediation list</span>'}</td></tr>`; }).join('');
        const recordBox = mk ? `<div class="cp-rec${mk.state === 'exception' ? ' risk' : ''}"><h4>${mk.state === 'exception' ? `Accepted risk${mk.until ? ` until ${esc(fmtDate(mk.until, true))}` : ''}` : mk.state === 'recorded' ? `Recorded by you: ${esc(RES[mk.result] || '')}` : 'Attestation'}</h4>
            <p>${mk.state === 'attested' ? '“' : ''}${esc(mk.note || '')}${mk.state === 'attested' ? '”' : ''}</p>
            <p class="sub" style="margin:2px 0 0">${esc(mk.by || '')} · ${esc(fmtDate(mk.at, true))}${mk.ref ? ` · ${mk.state === 'exception' ? 'compensating controls' : 'evidence'}: ${esc(mk.ref)}` : ''} · ${mk.expired ? `<b class="cp-stale">expired ${esc(fmtDate(mk.until, true))}: renew it</b>` : mk.until ? `${mk.state === 'exception' ? 'until' : 'expires'} ${esc(fmtDate(mk.until, true))}` : ''}${mk.state !== 'exception' ? ' · not verified by Liongard' : ''}</p></div>` : '';
        const btns = !screen ? '' : `<div class="cp-acts no-print">${mk ? `<button type="button" class="btn ghost sm" data-ctl="${esc(c.key)}" data-act="${mk.state}">${mk.expired ? 'Renew' : 'Edit'}</button><button type="button" class="btn ghost sm" data-ctl="${esc(c.key)}" data-act="clear">Clear</button>`
          : c.status === 'awaiting' ? `<button type="button" class="btn sm" data-ctl="${esc(c.key)}" data-act="attested">Attest</button>`
          : c.status === 'na' ? `<button type="button" class="btn sm" data-ctl="${esc(c.key)}" data-act="recorded">Record your evidence</button>`
          : ['fail', 'partial'].includes(c.status) ? `<button type="button" class="btn ghost sm" data-ctl="${esc(c.key)}" data-act="exception">Accept risk</button>` : ''}</div>`;
        return `<details class="cp-ctl" style="--st:${colr}"${evOpen || !screen ? ' open' : ''}><summary><span class="cp-id">${esc(c.id)}${c.ra ? ` <span class="sub" style="margin:0">(${c.ra === 'R' ? 'required' : 'addressable'})</span>` : ''}</span><span class="cp-nm">${esc(c.name)}<span class="sub">${esc(c.summary)}</span></span><span class="chip ${chip}">${label}${c.status === 'recorded' && mk ? `: ${esc(RES[mk.result] || '')}` : ''}</span></summary>
          <div class="cp-cb">
            <div><h4>What Liongard tested</h4><p>${esc(c.tested || 'Nothing: this control is outside what Liongard can see.')}</p>${c.strict ? '<p class="sub" style="margin:4px 0 0">This framework requires it on every account, so anything short of all of them fails.</p>' : ''}${c.why ? `<p class="sub" style="margin:4px 0 0">${esc(c.why)}</p>` : ''}</div>
            <div><h4>What isn’t covered</h4><p>${esc(c.gap || '—')}</p></div>
            ${pop ? `<div><h4>Population</h4>${pop}</div>` : ''}${srcs ? `<div><h4>Sources and read dates</h4>${srcs}</div>` : ''}
            ${items.length ? `<div class="f"><h4>Exceptions (${items.length})</h4><table class="review"><thead><tr><th>Item</th><th>Reason</th><th>Remediation</th></tr></thead><tbody>${exRows}</tbody></table>${items.length > 60 ? `<p class="sub">And ${items.length - 60} more, in the CSV of the checks table.</p>` : ''}</div>` : ''}
            ${recordBox ? `<div class="f">${recordBox}</div>` : ''}${btns ? `<div class="f">${btns}</div>` : ''}
            <div class="f cp-cite">Source: ${esc(c.source)}</div>
          </div></details>`;
      };
      const groups = [...new Set(shown.map(c => c.group || ''))];
      const b = (SETTINGS && SETTINGS.branding) || {}, msp = b.name || 'the MSP', sc = m.scope || {};
      const range = sc.from && sc.to ? `${fmtDate(sc.from, true)} and ${fmtDate(sc.to, true)}` : fmtDate(m.pulledOn, true);
      const cnt = (n, w) => n == null ? '' : `${n} ${w}${n === 1 ? '' : 's'}`;
      const body = groups.map(g => { const list = shown.filter(c => (c.group || '') === g); return `<h3 class="cp-grp"><span>${esc(f.groups[g] || g || f.name)}</span><span class="sub" style="margin:0">${list.length} ${esc(f.unit)} · ${list.filter(c => c.status === 'pass').length} pass · ${list.filter(c => ['fail', 'risk'].includes(c.status)).length} fail</span></h3>${list.map(block).join('')}`; }).join('') || '<p class="sub">Nothing to show for this filter.</p>';
      const people = [...new Map(appendix.map(a => [`${a.it.t}|${a.it.d}`, a])).values()];
      const stk = [['Pass', f.pass, 'var(--ok)'], ['In part', f.part, 'var(--warn)'], ['Fail', f.fail, 'var(--crit)'], ['Recorded by you', f.attested + f.recorded, 'var(--blue)'], ['To answer', f.awaiting + f.expired, 'var(--line)'], ['Not assessed', f.na, 'var(--surface-sunken)']];
      return `<div class="cp-cover"><div><div class="sub" style="margin:0;text-transform:uppercase;letter-spacing:.08em;font-weight:700">Evidence pack</div><h2 style="margin:2px 0 4px">${esc(m.environment.Name)} · ${esc(f.name)}</h2>
          <div class="sub" style="margin:0">Prepared by ${esc(msp)} · data read between ${esc(range)} · generated ${esc(fmtDate(new Date().toISOString(), true))}</div>
          <div class="sub" style="margin:0">Data controller: ${esc(m.environment.Name)} · processor: ${esc(msp)}</div></div>${b.logo ? `<img src="${esc(b.logo)}" alt="" class="qbr-logo">` : ''}</div>
        <div class="cp-evcov">
          <div class="card"><b>Coverage</b><div class="cp-big">${f.evidenced} <span class="sub" style="margin:0">of ${f.total} ${esc(f.unit)} evidenced by Liongard</span></div>
            <div class="cp-stk">${stk.map(([, n, c]) => n ? `<i style="width:${n / f.total * 100}%;background:${c}"></i>` : '').join('')}</div>
            <div class="cp-hleg" style="margin:4px 0 0">${stk.map(([l, n, c]) => `<span><i style="background:${c};border:1px solid var(--line)"></i>${l} ${n}</span>`).join('')}</div></div>
          <div class="card"><b>Of those evidenced</b><div class="cp-big" style="color:var(--ok-ink)">${f.pass} <span class="sub" style="margin:0">pass</span></div><div class="sub" style="margin:0">${f.part} in part · <b style="color:var(--crit)">${f.fail} fail</b>${f.risk ? ` (${f.risk} accepted risk)` : ''}</div></div>
          <div class="card"><b>Recorded by you</b><div class="cp-big" style="color:var(--blue)">${f.attested + f.recorded}</div><div class="sub" style="margin:0">${f.attested} attested · ${f.recorded} your own evidence${f.expired ? ` · <b class="cp-stale">${f.expired} expired</b>` : ''}</div></div>
          <div class="card"><b>Still to answer</b><div class="cp-big" style="color:var(--text-muted)">${f.awaiting + f.na}</div><div class="sub" style="margin:0">${f.awaiting} awaiting attestation · ${f.na} not assessed</div></div>
        </div>
        <div class="cp-scope"><p><b>Scope and limitations.</b> This evidence pack was produced by ${esc(msp)} from configuration data collected by Liongard for ${esc(m.environment.Name)} between ${esc(range)}. It covers technical controls that Liongard can observe, over the systems that reported to Liongard during that period: ${[cnt(sc.endpoints, 'endpoint'), cnt(sc.identity, 'identity system'), cnt(sc.network, 'network device'), cnt(sc.domains, 'domain'), cnt(sc.cloud, 'cloud service')].filter(Boolean).join(', ')}. Systems, devices and cloud services that are not connected to Liongard are not covered, and this pack cannot confirm that the list above is complete.</p>
          <p>A control marked “Pass” means the conditions described under “What Liongard tested” were met on the date shown; it does not confirm that the control as a whole is in place. Policies, processes, physical security and personnel controls are shown as “Attested” or “Recorded by you” from the statements recorded, which ${esc(msp)} has not independently verified. Controls marked “Not assessed” were not tested. This pack is not a certification, audit opinion or attestation of compliance with ${esc(f.name)}. It is evidence to support an assessment by the client’s ${esc(f.assessor)}.</p>
          ${f.extra ? `<p>${esc(f.extra)}</p>` : ''}${f.lead ? `<p class="sub" style="margin:0">${esc(f.lead)}</p>` : ''}
          <p class="sub" style="margin:6px 0 0">Status rule: a control fails if any check behind it fails; it is “Evidenced in part” when Liongard tests only part of it, and “Not assessed” when no check has data. Attestations and your own records are shown separately and never count as a technical pass.</p></div>
        ${body}
        ${evPeople !== 'names' && people.length ? `<div class="cp-restricted"><h3 style="margin-top:0">Restricted: contains personal data</h3><p class="sub">Named exceptions for the controls above: account identifiers and reasons only. Share with the client and their assessor; leave it out of copies for insurers.</p>
          <table class="review"><thead><tr><th>Control</th><th>Account</th><th>Reason</th></tr></thead><tbody>${people.map(a => `<tr><td class="mono">${esc(a.ctl)}</td><td>${evPeople === 'pseudo' ? `${esc(pseudo.get(a.it.t) || '')} = ` : ''}${esc(a.it.t)}</td><td>${esc(a.it.d || '')}</td></tr>`).join('')}</tbody></table></div>` : ''}
        <div class="signoff"><div>Prepared by: ____________________________</div><div>Reviewed by (client): ____________________________</div><div>Date: ______________</div></div>`;
    }
    function drawEv() {
      const k = $('evFw').value;
      const f = m.frameworks.find(x => x.key === k);
      $('evTitle').textContent = f ? `Evidence pack: ${f.name}` : 'Evidence pack';
      $('evView').innerHTML = packHtml(k, true);
      $('evPack').innerHTML = packHtml(k, false);
    }
    $('evFw').addEventListener('change', drawEv);
    const evSeg = (id, fn) => $(id).addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; $(id).querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); fn(b.dataset.v); drawEv(); });
    evSeg('evPeople', v => { evPeople = v; }); evSeg('evShow', v => { evShow = v; });
    $('evOpen').addEventListener('click', e => { evOpen = !evOpen; e.target.textContent = evOpen ? 'Collapse all' : 'Expand all'; drawEv(); });
    // Recording your own details on a control: an attestation, your own evidence, or an accepted risk.
    const CTL_FORM = {
      attested: ['Attest', 'Record who confirms this control and how. It’s shown in the pack as an attestation, apart from Liongard’s results, and never counts as a pass.', 'Statement', 'Who confirms it (name and role)', 'Evidence (document name and where it’s kept)', 'Expires'],
      recorded: ['Record your evidence', 'Liongard can’t assess this control. Record what you found and how. It’s shown in the pack as recorded by you, apart from Liongard’s results.', 'What you checked and found', 'Who checked it (name and role)', 'Evidence (document name and where it’s kept)', 'Review by'],
      exception: ['Accept risk', 'The control keeps its result. The pack shows the accepted risk beside it until the date you set.', 'Reason the risk is accepted', 'Approved by at the client (name and role)', 'Compensating controls', 'Accepted until'],
    };
    const ctlDlg = $('ctlDlg');
    const openCtl = (key, act) => {
      const f = m.frameworks.find(x => x.key === $('evFw').value), c = f && f.controls.find(x => x.key === key); if (!c) return;
      const [t, sub, nl, bl, rl, ul] = CTL_FORM[act];
      $('ctlTitle').textContent = `${t}: ${c.id} ${c.name}`; $('ctlSub').textContent = sub;
      $('ctlNoteL').textContent = nl; $('ctlByL').textContent = bl; $('ctlRefL').textContent = rl; $('ctlUntilL').textContent = ul;
      $('ctlResL').hidden = act !== 'recorded';
      const fm = $('ctlForm'); fm.reset();
      const mk = c.mark && c.mark.state === act ? c.mark : null;
      fm.elements.note.value = mk ? mk.note || '' : ''; fm.elements.by.value = mk ? mk.by || '' : ''; fm.elements.ref.value = mk ? mk.ref || '' : '';
      fm.elements.result.value = mk && mk.result ? mk.result : 'met';
      fm.elements.until.value = mk && mk.until && !mk.expired ? mk.until : new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10);   // 12 months by default
      ctlDlg.returnValue = '';
      ctlDlg.onclose = async () => {
        if (ctlDlg.returnValue !== 'save') return;
        const d = new FormData(fm);
        try { await window.portal.setComplianceMark({ key, state: act, note: d.get('note'), by: d.get('by'), ref: d.get('ref'), until: d.get('until') || null, result: act === 'recorded' ? d.get('result') : undefined }); reload(); }
        catch (err) { $('statusLine').textContent = `Couldn’t save: ${cleanErr(err)}`; }
      };
      ctlDlg.showModal();
    };
    $('evView').addEventListener('click', async e => {
      const b = e.target.closest('[data-ctl]'); if (!b) return;
      e.preventDefault();
      if (b.dataset.act === 'clear') { try { await window.portal.setComplianceMark({ key: b.dataset.ctl, state: 'clear' }); reload(); } catch (err) { $('statusLine').textContent = `Couldn’t save: ${cleanErr(err)}`; } return; }
      openCtl(b.dataset.ctl, b.dataset.act);
    });
    const brand = () => ({ ...((SETTINGS && SETTINGS.branding) || {}) });   // Settings › Your MSP: one logo and name for every report
    const drawQbr = () => {
      const b = brand(), base = m.base, fwIn = m.frameworks.filter(x => x.scope !== 'out');
      const ba = (label, then, now, unit = '') => `<div><span>${esc(label)}</span><b>${then == null ? '' : `${then}${unit} → `}${now == null ? '—' : `${now}${unit}`}</b></div>`;
      const verified = m.checks.filter(c => c.state === 'verified').map(c => c.name);
      const fixed = [...new Set([...m.improved, ...verified])];
      const next = m.gains.length ? m.gains.slice(0, 4).map(g => `${g.name}${g.fix ? `: ${g.fix}` : ''}`) : m.checks.filter(c => c.status === 'fail').slice(0, 4).map(c => `${c.name}${c.fix ? `: ${c.fix}` : ''}`);
      const li = a => a.length ? `<ul>${a.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p class="sub">None recorded.</p>';
      $('qbrPack').innerHTML = `<div class="qbr-hd"><div><h2 style="margin:0">${esc(m.environment.Name)}: security review</h2><p style="margin:4px 0 0">${base ? `${esc(fmtDate(base.at, true))} to ` : ''}${esc(fmtDate(m.pulledOn, true))}${b.name ? ` · prepared by ${esc(b.name)}` : ''}</p></div>${b.logo ? `<img src="${esc(b.logo)}" alt="" class="qbr-logo">` : ''}</div>
        <div class="qbr-ba">${ba('Security posture (out of 10)', base ? base.posture : null, m.posture)}</div>
        <h3>Frameworks</h3><table class="review"><thead><tr><th>Framework</th><th>Evidenced by Liongard</th><th>Pass</th><th>In part</th><th>Fail</th><th>Recorded by you</th></tr></thead><tbody>${fwIn.map(x => `<tr><td>${esc(x.name)}</td><td>${x.evidenced} of ${x.total} ${esc(x.unit)}</td><td>${x.pass}</td><td>${x.part}</td><td>${x.fail}</td><td>${x.attested + x.recorded}</td></tr>`).join('')}</tbody></table>
        ${base ? '' : '<p class="sub">This is the first review with a saved score, so there is no earlier score to compare yet.</p>'}
        <h3>What improved</h3>${li(fixed)}
        ${m.worse.length ? `<h3>What got worse</h3>${li(m.worse)}` : ''}
        <h3>Next priorities</h3>${li(next)}
        ${m.checks.some(c => c.state === 'exception') ? `<h3>Accepted risks</h3>${li(m.checks.filter(c => c.state === 'exception').map(c => `${c.name}${c.mark.until ? ` (until ${fmtDate(c.mark.until, true)})` : ''}${c.mark.note ? `: ${c.mark.note}` : ''}`))}` : ''}
        <h3>Security posture by area</h3><table class="review"><thead><tr><th>Area</th><th>Then</th><th>Now</th></tr></thead><tbody>${m.areas.map(a => `<tr><td>${esc(a.name)}</td><td>${base && base.areas && base.areas[a.name] != null ? base.areas[a.name] : '—'}</td><td>${a.score == null ? 'No evidence' : a.score}</td></tr>`).join('')}</tbody></table>
        <p class="sub" style="margin-top:14px">Scores are built from live Liongard evidence over the systems that reported. Policy and process controls are answered separately and aren’t in the score.</p>`;
    };
    drawQbr();   // branding (name and logo) is set once, in Settings › Your MSP
    // Profile form.
    const prof = m.profile || {};
    const saveProfile = async p => { await window.portal.setComplianceProfile(p); reload(); };
    $('cpForm').addEventListener('submit', e => { e.preventDefault(); const d = new FormData(e.target); saveProfile({ ...prof, industry: d.get('industry'), region: d.get('region'), cards: !!d.get('cards'), insurance: !!d.get('insurance'), iso: !!d.get('iso'), target: +d.get('target') || 8 }); });
    if ($('cpClear')) $('cpClear').addEventListener('click', () => saveProfile(null));
    // Framework cards: pick one to filter; × takes it out of scope; "+ name" adds one.
    $('fwCards').addEventListener('click', e => {
      const x = e.target.closest('[data-hide]');
      if (x) { e.stopPropagation(); saveProfile({ ...prof, hidden: [...new Set([...(prof.hidden || []), x.dataset.hide])], extra: (prof.extra || []).filter(k => k !== x.dataset.hide) }); return; }
      const b = e.target.closest('[data-fw]'); if (!b) return; fw = fw === b.dataset.fw ? '' : b.dataset.fw; draw();
    });
    $('fwCards').addEventListener('keydown', e => { if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('[data-fw]')) { e.preventDefault(); e.target.click(); } });
    document.querySelectorAll('[data-add]').forEach(b => b.addEventListener('click', () => {
      const k = b.dataset.add;
      if (!m.profile) return;
      saveProfile({ ...prof, extra: [...new Set([...(prof.extra || []), k])], hidden: (prof.hidden || []).filter(x => x !== k) });
    }));
    $('ckF').addEventListener('click', e => { const b = e.target.closest('[data-s]'); if (!b) return; [...$('ckF').children].forEach(x => x.setAttribute('aria-pressed', x === b)); s = b.dataset.s; draw(); });
    // Marks: Mark done / Attest / Accept risk open a short form; Clear removes the mark.
    const dlg = $('mkDlg');
    const TITLES = { done: ['Mark done', 'It shows as “Marked done” until Liongard’s next data pull confirms it, then “Verified fixed”. If the data still fails, it reopens.'],
      attested: ['Attest', 'Liongard has no evidence for this check. Record who confirmed it and how. Attestations count as a pass for 12 months, and Liongard evidence replaces them when it appears.'],
      exception: ['Accept risk', 'The check keeps its result and score. The exception is shown in reports with your reason until the date you set.'] };
    const openMark = (key, state, isQ) => {
      const c = isQ ? m.questions.find(q => q.key === key) : m.checks.find(x => x.key === key);
      $('mkTitle').textContent = isQ ? `${ANS[state][1]}: ${c.name}` : `${TITLES[state][0]}: ${c.name}`;
      $('mkSub').textContent = isQ ? 'Add how you know (for example where the document is kept). The answer is shown in the evidence pack.' : TITLES[state][1];
      $('mkUntilL').hidden = state !== 'exception';
      $('mkForm').reset(); dlg.returnValue = '';
      dlg.onclose = async () => {
        if (dlg.returnValue !== 'save') return;
        const d = new FormData($('mkForm'));
        try { await window.portal.setComplianceMark({ key: isQ ? `q:${key}` : key, state, note: d.get('note'), by: d.get('by'), until: state === 'exception' ? d.get('until') || null : null }); reload(); }
        catch (err) { $('statusLine').textContent = `Couldn’t save: ${cleanErr(err)}`; }
      };
      dlg.showModal();
    };
    $('panelBody').addEventListener('click', async e => {
      const b = e.target.closest('[data-mk],[data-q]'); if (!b) return;
      const isQ = !!b.dataset.q, key = b.dataset.q || b.dataset.k, state = b.dataset.a || b.dataset.mk;
      if (state === 'clear') { try { await window.portal.setComplianceMark({ key: isQ ? `q:${key}` : key, state: 'clear' }); reload(); } catch (err) { $('statusLine').textContent = `Couldn’t save: ${cleanErr(err)}`; } return; }
      openMark(key, state, isQ);
    });
    // ---------- Drill-down: area (or framework × area) → checks → the people, devices and network gear behind them ----------
    const AREA_KEYS = Object.fromEntries(m.areas.map(a => [a.name, a.keys]));
    const PAGE_FOR = { User: 'identity', Admin: 'identity', Device: 'coverage', Server: 'coverage', Domain: 'email', Firewall: 'network', Switch: 'network', 'Access point': 'network', Network: 'network', Inspector: 'inspectors', System: 'stack' };
    const onList = new Set((m.remediation || []).map(r => r.id));
    const rid = (c, it) => `${c}|${it.t}`.slice(0, 300);
    let crumbs = [], dirty = false;
    const closeDr = () => { const d = document.getElementById('cpDr'); if (d) { d.remove(); if (typeof modalOff === 'function') modalOff(); } document.removeEventListener('keydown', escDr); if (dirty) { dirty = false; reload(); } };
    const escDr = e => { if (e.key === 'Escape') closeDr(); };
    const dr = (title, sub, body, foot = '') => {
      const old = document.getElementById('cpDr'); if (old) old.remove();
      document.body.insertAdjacentHTML('beforeend', `<div id="cpDr"><div class="dr-back"></div><aside class="cp-dr" role="dialog" aria-modal="true" aria-label="${esc(title)}">
        <div class="cp-dr-h"><button type="button" class="cp-dr-x" aria-label="Close">×</button>
          ${crumbs.length > 1 ? `<div class="cp-crumbs">${crumbs.slice(0, -1).map((c, i) => `<button type="button" data-crumb="${i}">${esc(c.label)}</button><span>›</span>`).join('')}</div>` : ''}
          <h3>${esc(title)}</h3><div class="sub" style="margin:0">${sub}</div></div>
        <div class="cp-dr-b">${body}</div>${foot ? `<div class="cp-dr-f">${foot}</div>` : ''}</aside></div>`);
      const root = document.getElementById('cpDr');
      if (typeof modalOn === 'function') modalOn(root);   // page behind is inert; focus returns to the cell or row that opened it
      root.querySelector('.dr-back').onclick = closeDr; root.querySelector('.cp-dr-x').onclick = closeDr;
      root.querySelectorAll('[data-crumb]').forEach(b => b.onclick = () => { const i = +b.dataset.crumb, c = crumbs[i]; crumbs = crumbs.slice(0, i); c.open(); });
      document.removeEventListener('keydown', escDr); document.addEventListener('keydown', escDr);
      root.querySelector('.cp-dr-x').focus();
      return root;
    };
    const tagOf = c => `<span class="cp-tag t-${c.unread || c.status === 'none' ? 'none' : c.status === 'pass' ? 'ok' : c.status === 'partial' ? 'warn' : 'bad'}">${c.unread ? 'Not read' : lab[c.status]}</span>`;
    const openArea = (area, fwKey) => {
      const f = fwKey && m.frameworks.find(x => x.key === fwKey);
      const list = m.checks.filter(c => (AREA_KEYS[area] || []).includes(c.key) && (!f || (c.refs[fwKey] || []).length));
      const cell = f ? (m.heat.find(h => h.key === fwKey) || { cells: [] }).cells.find(c => c.area === area) : m.areas.find(a => a.name === area);
      const v = cell && cell.score;
      crumbs = [{ label: f ? `${f.key === 'INS' ? 'Insurance' : f.key} · ${area}` : area, open: () => openArea(area, fwKey) }];
      const items = list.flatMap(c => (c.items || []).map(it => [c, it]));
      const root = dr(`${f ? `${f.name} · ` : ''}${area}: ${v == null ? 'no data' : `${v.toFixed(1)} out of 10`}`,
        `${v != null && v < m.target ? `<span class="cp-tag t-bad">below target ${m.target}</span> · ` : ''}${list.length} check${list.length === 1 ? '' : 's'}${items.length ? ` · ${items.length} affected` : ''}. Pick a check to see what’s affected.`,
        list.map(c => `<button type="button" class="cp-li" data-check="${c.key}"${(c.items || []).length ? '' : ' data-empty="1"'}>${tagOf(c)}<span><b>${esc(c.name)}</b><span class="sub" style="margin:0;display:block">${(c.items || []).length ? `${c.items.length} affected · ${esc(c.fix || '')}` : esc(c.evidence)}</span></span><span class="sub" style="margin:0">${(c.items || []).length ? 'Open ›' : ''}</span></button>`).join('') || '<p class="sub">No checks in this area.</p>',
        items.length ? `<button type="button" class="btn ghost msp" id="cpAddArea">Add all ${items.length} affected to the remediation list</button>` : '');
      root.querySelectorAll('[data-check]').forEach(b => b.onclick = () => { if (!b.dataset.empty) openCheck(b.dataset.check); });
      const all = root.querySelector('#cpAddArea'); if (all) all.onclick = () => addRem(items, () => openArea(area, fwKey));
    };
    const openCheck = key => {
      const c = m.checks.find(x => x.key === key); if (!c) return;
      const items = c.items || [];
      crumbs = [...crumbs.filter(x => x.key !== key), { key, label: c.name, open: () => openCheck(key) }];
      const fws = m.frameworks.filter(f => f.scope !== 'out' && (c.refs[f.key] || []).length).map(f => f.key === 'INS' ? 'Insurance' : f.key).join(', ');
      const root = dr(c.name, `${tagOf(c)} · ${items.length} affected${fws ? ` · counts toward ${esc(fws)}` : ''}${c.gain ? ` · fixing it adds ${c.gain} framework points` : ''}`,
        `${c.fix ? `<div class="cp-fixbox"><b>How to fix:</b> ${esc(c.fix)}</div>` : ''}<p class="sub" style="margin:0 0 6px">${esc(c.evidence)}</p>` +
        (items.map((it, i) => `<div class="cp-li static"><span class="cp-kind">${esc(it.kind)}</span>
          <span><b>${it.link ? lgA(lgFor(ctx, it.link), esc(it.t)) : esc(it.t)}</b><span class="sub" style="margin:0;display:block">${esc(it.d)}</span>
          <span class="sub" style="margin:0;display:block">${it.tool ? `${toolName(it.tool)} · ` : ''}${pageA(PAGE_FOR[it.kind] || c.page, it.t, `${{ identity: 'Identity & access', coverage: 'Stack coverage', email: 'Email & domain security', network: 'Network & firmware', inspectors: 'Inspector health', stack: 'Customer stack' }[PAGE_FOR[it.kind] || c.page] || 'Details'} →`)}</span></span>
          ${onList.has(rid(key, it)) ? '<span class="cp-tag t-ok">On the list</span>' : `<button type="button" class="btn ghost sm msp" data-add="${i}">+ Remediation list</button>`}</div>`).join('') || '<p class="sub">Nothing listed for this check.</p>') +
        (c.items && c.items.length >= 500 ? '<p class="sub">Showing the first 500.</p>' : ''),
        items.some(it => !onList.has(rid(key, it))) ? `<button type="button" class="btn" id="cpAddAll">Add all ${items.filter(it => !onList.has(rid(key, it))).length} to the remediation list</button><span class="sub" style="margin:0">Severity: ${esc(m.severities[key] || 'Medium')} (you can change it on the list)</span>` : items.length ? '<span class="sub" style="margin:0">Everything here is on the remediation list.</span>' : '');
      root.querySelectorAll('[data-add]').forEach(b => b.onclick = () => addRem([[c, items[+b.dataset.add]]], () => openCheck(key)));
      const all = root.querySelector('#cpAddAll'); if (all) all.onclick = () => addRem(items.map(it => [c, it]), () => openCheck(key));
    };
    const addRem = async (pairs, then) => {
      const todo = pairs.filter(([c, it]) => !onList.has(rid(c.key, it)));
      if (!todo.length) return then();
      try {
        await window.portal.addRemediation(todo.map(([c, it]) => ({ check: c.key, checkName: c.name, kind: it.kind, t: it.t, d: it.d, tool: it.tool, link: it.link, sev: m.severities[c.key] || 'Medium' })));
        todo.forEach(([c, it]) => onList.add(rid(c.key, it))); dirty = true;
        $('statusLine').textContent = `Added ${todo.length} to the remediation list`;
      } catch (err) { $('statusLine').textContent = `Couldn’t add: ${cleanErr(err)}`; }
      then();
    };
    const openRem = sev => {
      crumbs = [];
      const list = (m.remediation || []).filter(r => !sev || r.sev === sev);
      const root = dr(`Remediation list${sev ? `: ${sev}` : ''}`, `${list.length} item${list.length === 1 ? '' : 's'}. Changes save straight away.`, remTableHtml(list, ctx));
      root.querySelector('.cp-dr').classList.add('wide');
      wireRemTable(root, () => { dirty = true; });
    };
    // Every widget opens the drill-down.
    $('panelBody').addEventListener('click', e => {
      if (e.target.closest('#cpDr')) return;
      const cell = e.target.closest('.cp-cell[data-area]'), area = !cell && e.target.closest('[data-area]'), row = e.target.closest('.cp-mx [data-check]'), pr = e.target.closest('.cp-prog [data-sev]'), aff = e.target.closest('[data-affected]');
      if (cell) openArea(cell.dataset.area, cell.dataset.fw);
      else if (area) openArea(area.dataset.area);
      else if (row) { crumbs = []; openCheck(row.dataset.check); }
      else if (pr) openRem(pr.dataset.sev);
      else if (aff) { crumbs = []; openCheck(aff.dataset.affected); }
    });
    $('panelBody').addEventListener('keydown', e => { const t = e.target.closest('.cp-radar [data-area]'); if (t && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openArea(t.dataset.area); } });
    $('cpRem').innerHTML = remTableHtml(m.remediation || [], ctx);
    wireRemTable($('cpRem'), () => reload());
    draw(); drawEv(); paintBrand();
  },
  how: m => [
    'Built from the same data and rules as Stack coverage, Identity & access, Email & domain security, Network & firmware, Inspector health and Licence reconciliation, with the same coverage policy and shared Liongard metrics, so every page agrees.',
    'Framework references, the client profile rules, posture areas and scoring: src/main/panels/compliance.js',
    'Kept on this computer: the client profile (settings.json), marks and answers (compliance-status.json) and a score snapshot per data pull (compliance-history.json).',
    `Snapshots saved for this client: ${m.history.length}.`,
  ].join('\n'),
};
