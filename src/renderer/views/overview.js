// Overview view: where to start for this client. "Start here" (the top open problems across every area), then one card
// per area, worst first, each with its state, worst problem and a way into the page and the Action plan.
// Area states: Not covered is neutral dashed slate, never amber; Couldn't read is crimson. Risk chips use riskChip.
const OV_STATE = { act: ['c-crit', 'Act now', 'var(--crit)', ''], review: ['c-warn', 'Review', 'var(--warn)', ''], ok: ['c-ok', 'Looks fine', 'var(--ok)', ''], none: ['c-nc', 'Not covered', 'var(--none)', 'st-none'], unknown: ['c-blind', 'Couldn’t read', 'var(--blind)', 'st-blind'] };
const OV_PAGE = { cyber: 'Cyber security', identity: 'Identity & access', coverage: 'Stack coverage', email: 'Email & domain security', network: 'Network & firmware', lifecycle: 'Lifecycle & renewals', licences: 'Licence reconciliation', inspectors: 'Inspector health', wallboard: 'Wallboard' };
const ovArea = s => m => m.areas.filter(a => a.state === s).map(a => ({ t: a.t, d: a.headline, page: a.page, sev: s === 'act' ? 'bad' : s === 'review' ? 'warn' : '' }));

window.VIEWS.overview = {
  title: 'Overview',
  intro: 'The areas that need attention for this client right now, worst first, from the same rules and data as the Action plan. A quiet area only counts as fine when a tool actually checks it.',
  kpiItems: { 'Act now': ovArea('act'), 'To review': ovArea('review'), 'Not covered': ovArea('none'), 'Looks fine': ovArea('ok') },
  render(m) {
    const first = m.first.length ? `<ol class="ov-first">${m.first.map(x => `<li><span class="ov-chips">${riskChip(x.risk)}${x.quickWin ? '<span class="chip c-ok msp">Quick win</span>' : ''}</span>
        <div><b>${esc(x.title)}</b><div class="sub" style="margin:2px 0 0">${esc(x.area)}<span class="msp"> · ${esc(x.owner)} · ${esc(x.effort)}</span></div></div>
        ${pageA(x.page, '', `${esc(OV_PAGE[x.page] || x.page)} →`, `Open ${OV_PAGE[x.page] || x.page}`)}</li>`).join('')}</ol>
        <p class="sub" style="margin:8px 0 0">${pageA('actions', '', 'Everything to fix, with owners, effort and ticket text: Action plan →')}</p>`
      : '<p class="sub" style="margin:0">Nothing open. Every problem Liongard found for this client is fixed, accepted or not applicable.</p>';
    const card = a => { const [chip, label, col, st] = OV_STATE[a.state];
      return `<div class="card ov-card ${st}" id="ov-${esc(a.key)}" style="--ov:${col}">
        <div class="ov-h"><h3>${esc(a.t)}</h3><span class="chip ${chip}">${label}</span></div>
        ${a.count ? `<p class="ov-n">${a.critical ? `<b class="crit">${a.critical} critical</b>` : ''}${a.critical && a.high ? ' · ' : ''}${a.high ? `<b class="warn">${a.high} high</b>` : ''}${(a.critical || a.high) && a.count - a.critical - a.high ? ' · ' : ''}${a.count - a.critical - a.high ? `${a.count - a.critical - a.high} ${a.critical || a.high ? 'more' : 'medium or low'}` : ''}</p>` : ''}
        <p class="ov-head">${esc(a.headline)}</p>
        ${a.top.length > 1 ? `<ul class="plain ov-top">${a.top.slice(1).map(x => `<li><span>${riskChip(x.risk)} ${esc(x.title)}</span></li>`).join('')}</ul>` : ''}
        <div class="ov-go">${pageA(a.page, '', `${esc(OV_PAGE[a.page] || a.page)} →`, `Open ${OV_PAGE[a.page] || a.page}`)}${a.count ? pageA('actions', a.cats[0], `${a.count} in the Action plan →`, 'Open the Action plan, filtered to this area') : ''}</div>
      </div>`; };
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(x => `<li><span>${esc(x)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <div class="card"><h3>Start here</h3>${first}</div>
      <h3 style="margin-top:22px">By area</h3>
      <div class="ov-grid">${m.areas.map(card).join('')}</div>
      ${m.missing.length ? `<p class="sub">Not included because the data couldn’t be read: ${esc(m.missing.join(', '))}.</p>` : ''}`;
  },
  how: () => [
    'Built from the Action plan (the same open problems, statuses and risk) and Cyber security’s coverage (which areas have a tool).',
    'Area state: Act now = a critical or high open problem; Review = only medium or low; Not covered = no tool of that kind; Couldn’t read = its data failed; Looks fine = checked and clear.',
    'Rules: src/main/panels/overview.js',
  ].join('\n'),
};
