// Action plan: everything to fix for this client, ranked by risk, with what it affects, how to fix it, who owns it and the
// effort. Quick wins = critical or high risk that take minutes. Copy any item as ticket text; export a client remediation plan.
// Risk chips come from the one scale in shared.js (RISK_CHIP / riskChip); this only spells the label.
const acRisk = r => (r ? r[0].toUpperCase() + r.slice(1) : '');
const AC_PAGE = { cyber: 'Cyber security', identity: 'Identity & access', coverage: 'Stack coverage', email: 'Email & domain security', network: 'Network & firmware', lifecycle: 'Lifecycle & renewals', licences: 'Licence reconciliation', inspectors: 'Inspector health', wallboard: 'Wallboard' };
const AC_STATUS = { open: 'Open', progress: 'In progress', ticketed: 'Ticketed', done: 'Done', accepted: 'Risk accepted', na: 'Not applicable' };
const acOpen = a => a.status === 'open' || a.status === 'progress' || a.status === 'ticketed';
// What a client sees in Present: a ticket in the MSP's PSA is simply "In progress" (the PSA and its number are internal).
const acClientStatus = a => (a.status === 'ticketed' ? 'In progress' : AC_STATUS[a.status] || a.status);
// A stable reference for the PSA: searchable, so a second tech can see it's already ticketed.
const acRef = (m, a) => `OPS-${m.environment && m.environment.ID}-${a.key}`;
const acSince = () => new Date(Date.now() - 90 * 864e5).toISOString().slice(0, 10);
const acRow = a => ({ t: `${acRisk(a.risk)}: ${a.title}`, d: `${a.why} · ${a.owner} · ${a.effortLabel}`, page: a.page, sev: a.risk === 'critical' ? 'bad' : a.risk === 'high' ? 'warn' : '' });

window.VIEWS.actions = {
  title: 'Action plan',
  intro: 'Everything to fix for this client, ranked by risk, from the same rules and data as the other pages. Each item says what it affects, how to fix it, who usually owns it and how much work it is.',
  // Tiles count open work only (open or in progress); Completed lists done, accepted and not-applicable items.
  kpiItems: {
    'Open actions': m => m.actions.filter(acOpen).map(acRow),
    'Critical': m => m.actions.filter(a => acOpen(a) && a.risk === 'critical').map(acRow),
    'High': m => m.actions.filter(a => acOpen(a) && a.risk === 'high').map(acRow),
    'Quick wins': m => m.actions.filter(a => acOpen(a) && a.quickWin).map(acRow),
    'Completed': m => m.actions.filter(a => !acOpen(a)).map(a => ({ ...acRow(a), d: `${AC_STATUS[a.status]}${a.statusAt ? ` on ${fmtDate(a.statusAt, true)}` : ''} · ${a.owner}`, sev: '' })),
  },
  exports: [{ label: 'PDF: client remediation plan', mode: 'review', title: 'Remediation plan', kicker: 'For client agreement' }],
  render(m) {
    const cats = [...new Set(m.actions.map(a => a.cat))].sort(), owners = [...new Set(m.actions.map(a => a.owner))].sort();
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <h3>Actions</h3>
      <div class="filters no-print">
        <div class="quick" id="acView">${[['all', 'All'], ['quick', 'Quick wins'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']].map(([k, l], i) => `<button type="button" data-v="${k}" aria-pressed="${i === 0}">${l}</button>`).join('')}</div>
        <select id="acCat" aria-label="Category"><option value="">Any category</option>${cats.map(c => `<option>${esc(c)}</option>`).join('')}</select>
        <select id="acOwner" class="msp" aria-label="Owner"><option value="">Any owner</option>${owners.map(o => `<option>${esc(o)}</option>`).join('')}</select>
        <div class="search" style="flex:1;min-width:200px;margin:0"><input id="acQ" placeholder="Search actions, people, devices" autocomplete="off" aria-label="Search actions"></div>
        <label class="toggle"><input type="checkbox" id="acShowDone"> Show completed</label>
      </div>
      <p class="sub" id="acCount"></p>
      <div class="tw"><table id="acTable"></table></div>
      <p class="sub">Risk combines how serious the problem is and how much it affects; items from data that may be out of date are marked and ranked lower. Framework references show which controls each item fails (technical evidence only).</p>
      <h3 style="margin-top:22px">Work done</h3>
      <p class="sub">Items marked done that Liongard no longer finds, confirmed by data pulled after they were marked. Pick the date of the last review to show what’s been fixed since.</p>
      <div class="filters"><label class="fld-inline">Fixed since <input type="date" id="acSince" aria-label="Show work fixed since this date"></label></div>
      <div id="acFixed"></div>
      <h3 class="msp" style="margin-top:22px">Remediation list</h3>
      <p class="sub msp">People, devices, domains and network gear added from Compliance at a glance. “Liongard says” is checked on every data pull: an item is verified fixed only when Liongard no longer finds it.</p>
      <div id="acRem" class="msp">${remTableHtml(m.remediation || [], null)}</div>
      <div class="review-only" id="acPlan"></div>`;
  },
  after(m, ctx) {
    let view = 'all', cat = '', owner = '', q = '', showDone = false;
    const refs = a => Object.entries(a.refs || {}).map(([k, v]) => `${k} ${v.join(', ')}`).join(' · ');
    const affected = a => a.affected.length ? `<details><summary class="sub">${a.count} affected · show</summary><ul class="plain ac-aff">${a.affected.slice(0, 50).map(x => `<li><span>${x.link ? lgA(lgFor(ctx, x.link), esc(x.t)) : esc(x.t)}${x.d ? ` <span class="sub" style="margin:0">${esc(x.d)}</span>` : ''}</span></li>`).join('')}${a.affected.length > 50 ? `<li class="sub">and ${a.affected.length - 50} more</li>` : ''}</ul></details>` : `<span class="sub">${a.count}</span>`;
    const ticket = a => [`[${acRisk(a.risk)}] ${a.title} (${m.environment.Name})`, `Ref: ${acRef(m, a)}`, '', a.why, '', a.affected.length ? `Affected (${a.count}):\n${a.affected.slice(0, 30).map(x => `- ${x.t}${x.d ? ` (${x.d})` : ''}`).join('\n')}${a.affected.length > 30 ? `\n- and ${a.affected.length - 30} more` : ''}` : '', '', `How to fix:\n${a.fix.map((f, i) => `${i + 1}. ${f}`).join('\n')}`, '', `Owner: ${a.owner} · Effort: ${a.effortLabel}`, refs(a) ? `Controls: ${refs(a)}` : '', `Source: Liongard Ops Portal, ${AC_PAGE[a.page] || a.page}`].filter(x => x !== '').join('\n').replace(/\n{3,}/g, '\n\n');
    const match = a => (showDone || acOpen(a)) && (view === 'all' || (view === 'quick' ? a.quickWin : a.risk === view)) && (!cat || a.cat === cat) && (!owner || a.owner === owner)
      && (!q || [a.title, a.why, a.cat, a.owner, ...a.affected.map(x => `${x.t} ${x.d}`)].join(' ').toLowerCase().includes(q));
    const draw = () => {
      const rows = m.actions.filter(match);
      const closed = m.actions.filter(a => !acOpen(a)).length;
      $('acCount').textContent = `${rows.length} of ${m.actions.length} actions${!showDone && closed ? ` · ${closed} completed hidden` : ''}`;
      $('acTable').innerHTML = `<thead><tr><th class="no-print">Status</th><th>Risk</th><th>Action</th><th>Affected</th><th class="msp">How to fix</th><th class="msp">Owner · effort</th><th class="no-print msp"></th></tr></thead><tbody>${rows.map(a => { const i = m.actions.indexOf(a); return `<tr class="${acOpen(a) ? '' : 'ac-closed'}">
        <td class="no-print ac-st" data-csv="${AC_STATUS[a.status]}"><span class="present-only">${esc(acClientStatus(a))}</span><span class="msp"><label class="ac-done" title="Mark as done"><input type="checkbox" data-done="${i}" ${a.status === 'done' ? 'checked' : ''}> Done</label>
          <select data-st="${i}" aria-label="Status for ${esc(a.title)}">${Object.entries(AC_STATUS).map(([k, l]) => `<option value="${k}" ${a.status === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
          ${a.status === 'ticketed' ? `<input type="text" class="ac-tk" data-tk="${i}" value="${esc(a.ticket || '')}" maxlength="40" placeholder="PSA ticket #" aria-label="PSA ticket number for ${esc(a.title)}">` : ''}
          ${a.verify === 'still' ? '<div class="sub" style="margin:2px 0 0" title="Marked done before the latest data pull, and Liongard still finds it">Still found after it was marked done</div>' : ''}
          </span>${a.statusAt && !acOpen(a) ? `<div class="sub" style="margin:2px 0 0">${fmtDate(a.statusAt, true)}</div>` : ''}${a.reopened ? `<div class="sub ac-reopen msp" style="margin:2px 0 0" title="${esc(a.reopened)}">Reopened: got worse</div>` : ''}</td>
        <td data-csv="${acRisk(a.risk)}">${riskChip(a.risk)}${a.quickWin ? '<div class="msp"><span class="chip c-ok" style="margin-top:4px">Quick win</span></div>' : ''}</td>
        <td class="wrap" style="min-width:260px" data-csv="${esc(a.title)}"><b>${esc(a.title)}</b>${a.older ? ' <span class="chip c-none" title="From data that may be out of date">Check first</span>' : ''}<div class="sub" style="margin:2px 0 0">${esc(a.why)}</div>${refs(a) ? `<div class="sub mono ac-refs" style="margin:2px 0 0" title="${esc(refs(a))}">${esc(refs(a))}</div>` : ''}</td>
        <td class="wrap" style="min-width:150px" data-csv="${esc(`${a.count}: ${a.affected.map(x => x.t).join(', ')}`)}"><span class="msp">${affected(a)}</span><span class="present-only">${a.count}</span></td>
        <td class="wrap msp" style="min-width:240px" data-csv="${esc(a.fix.join(' '))}"><ol class="ac-fix">${a.fix.map(f => `<li>${esc(f)}</li>`).join('')}</ol></td>
        <td class="msp" data-csv="${esc(`${a.owner} · ${a.effortLabel}`)}">${esc(a.owner)}<div class="sub" style="margin:0">${esc(a.effortLabel)}</div></td>
        <td class="no-print msp" style="white-space:nowrap"><button type="button" class="linkbtn" data-ticket="${i}">Copy ticket text</button><div>${pageA(a.page, '', `${AC_PAGE[a.page] || a.page} →`)}</div></td></tr>`; }).join('') || `<tr><td colspan="7">${m.actions.length ? 'Nothing open matches. Tick “Show completed” to see finished items.' : 'Nothing matches.'}</td></tr>`}</tbody>`;
      // Client remediation plan (printed from Export): the filtered list, with columns to agree owner and date.
      $('acPlan').innerHTML = `<p>These are the changes we recommend for ${esc(m.environment.Name)}, ranked by risk, from technical evidence Liongard collected (data pulled ${esc(fmtWhen(m.pulledOn))}). Please agree an owner and target date for each, and tick the ones you approve.</p>
        <table class="review"><thead><tr><th>Risk</th><th>Change</th><th>Why</th><th>Affected</th><th>Owner</th><th>Target date</th><th>Approve</th></tr></thead><tbody>${rows.filter(acOpen).map(a => `<tr><td>${acRisk(a.risk)}</td><td>${esc(a.title)}</td><td>${esc(a.why)}</td><td>${a.count}</td><td>${esc(a.owner)}</td><td></td><td class="box">☐</td></tr>`).join('')}</tbody></table>
        <div class="signoff"><div>Agreed by: ____________________________</div><div>Date: ______________</div><div>Signature: ____________________________</div></div>`;
    };
    $('acView').addEventListener('click', e => { const b = e.target.closest('[data-v]'); if (!b) return; [...$('acView').children].forEach(x => x.setAttribute('aria-pressed', x === b)); view = b.dataset.v; draw(); });
    $('acCat').addEventListener('change', e => { cat = e.target.value; draw(); });
    $('acOwner').addEventListener('change', e => { owner = e.target.value; draw(); });
    $('acQ').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); draw(); });
    $('acShowDone').addEventListener('change', e => { showDone = e.target.checked; draw(); });
    // Status: saved on this computer straight away; tiles update in place (no reload, so the page doesn't jump).
    const tiles = () => {
      const open = m.actions.filter(acOpen), set = (k, v) => { const el = document.querySelector(`.kpi[data-k="${k}"] .v`); if (el) el.textContent = v; };
      set('Open actions', open.length); set('Critical', open.filter(a => a.risk === 'critical').length); set('High', open.filter(a => a.risk === 'high').length);
      set('Quick wins', open.filter(a => a.quickWin).length); set('Completed', m.actions.length - open.length);
    };
    const setStatus = async (i, status) => {
      const a = m.actions[i];
      try { const r = await window.portal.setActionStatus({ key: a.key, status, count: a.count, title: a.title, ...(status === 'ticketed' ? { ticket: a.ticket || '' } : {}) }); a.status = r.status; a.statusAt = r.at || null; a.ticket = r.ticket || ''; a.reopened = null; a.verify = null; }
      catch (err) { $('statusLine').textContent = `Couldn’t save the status: ${cleanErr(err)}`; }
      tiles(); draw();
    };
    $('acTable').addEventListener('change', e => {
      const cb = e.target.closest('[data-done]'), sel = e.target.closest('[data-st]'), tk = e.target.closest('[data-tk]');
      if (tk) { m.actions[+tk.dataset.tk].ticket = tk.value.trim(); setStatus(+tk.dataset.tk, 'ticketed'); return; }
      if (cb) setStatus(+cb.dataset.done, cb.checked ? 'done' : 'open');
      if (sel) setStatus(+sel.dataset.st, sel.value);
    });
    $('acTable').addEventListener('click', e => {
      const b = e.target.closest('[data-ticket]'); if (!b) return;
      navigator.clipboard.writeText(ticket(m.actions[+b.dataset.ticket])).then(() => { b.textContent = 'Copied'; setTimeout(() => (b.textContent = 'Copy ticket text'), 1500); });
    });
    // Work done since a date: confirmed by Liongard only; items awaiting the next pull are internal.
    const drawFixed = () => {
      const since = $('acSince').value || acSince();
      const ok = (m.fixed || []).filter(f => f.confirmedAt && String(f.markedAt).slice(0, 10) >= since), wait = (m.fixed || []).filter(f => !f.confirmedAt);
      $('acFixed').innerHTML = (ok.length ? `<ul class="plain">${ok.map(f => `<li><span><span class="cp-tag t-ok">Fixed, confirmed by Liongard</span> <b>${esc(f.title)}</b> <span class="sub" style="margin:0">marked done ${esc(fmtDate(f.markedAt, true))} · no longer found in data pulled ${esc(fmtDate(f.confirmedAt, true))}</span></span></li>`).join('')}</ul>`
        : `<p class="sub">Nothing confirmed fixed since ${esc(fmtDate(since, true))}.</p>`)
        + (wait.length ? `<p class="sub msp">${wait.length} more marked done, waiting for the next data pull to confirm: ${wait.map(f => esc(f.title)).join('; ')}.</p>` : '');
    };
    $('acSince').value = acSince();
    $('acSince').addEventListener('change', drawFixed);
    drawFixed();
    // Remediation list: Liongard links need the page context, so it's redrawn here with it.
    $('acRem').innerHTML = remTableHtml(m.remediation || [], ctx);
    wireRemTable($('acRem'));
    draw();
  },
  how: m => [
    'Built from the other pages’ own rules and data: Cyber security, Identity & access, Stack coverage, Email & domain security, Network & firmware, Lifecycle & renewals, Licence reconciliation and Inspector health. Nothing extra is pulled from Liongard.',
    'Risk: critical, high, medium or low by problem type; within each, more affected items and quick fixes rank higher. Items from stale inspector data are marked "Check first" and ranked lower.',
    'Rules: src/main/panels/actions.js',
  ].join('\n'),
};
