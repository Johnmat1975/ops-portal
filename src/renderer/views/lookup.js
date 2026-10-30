// Lookup view: search or pick a person, device or domain.
window.VIEWS.lookup = {
  title: 'Lookup',
  kpiItems: Object.fromEntries([['Accounts', 'Person'], ['Devices', 'Device'], ['Domains', 'Domain']].map(([k, kind]) => [k, (m, c) => m.items.filter(i => i.kind === kind).map(i => ({ t: i.label, d: i.answer, url: i.link && lgFor(c, i.link), page: 'lookup', q: i.key, sev: i.risk ? 'warn' : '' }))])),
  handlesQuery: true,
  intro: 'Search, or pick a person, device or domain from the list, to see every system that knows about it in one view.',
  render(m) {
    return `
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <div class="lk-controls">
        <div class="lk-field lk-search"><label for="lkQ">Search</label><div class="combo"><input id="lkQ" placeholder="Name, email, hostname or domain" autocomplete="off" role="combobox" aria-expanded="false" aria-controls="lkSugg"><ul class="sugg" id="lkSugg" role="listbox" hidden></ul></div></div>
        ${['Person', 'Device', 'Domain'].map(k => `<div class="lk-field"><label for="lk${k}">${k === 'Person' ? 'People' : k + 's'}</label><select id="lk${k}" data-kind="${k}"><option value="">Choose…</option>${m.items.filter(i => i.kind === k).map(i => `<option value="${esc(i.key)}">${esc(i.label)}${i.risk ? ' ⚑' : ''}</option>`).join('')}</select></div>`).join('')}
      </div>
      <div id="lkOut"><p class="sub">Pick something to see its profile. Items marked ⚑ need attention.</p></div>`;
  },
  after(m, ctx) {
    const show = it => {
      if (!it) return;
      const PN = { identity: 'Identity & access', coverage: 'Stack coverage', email: 'Email & domain security' };
      $('lkOut').innerHTML = `<div class="answer"><b>${esc(it.kind)}:</b> ${esc(it.answer)}<div class="linkrow" style="margin-top:6px">${it.link ? lgA(lgFor(ctx, it.link), 'Open in Liongard') : ''}${it.page ? pageA(it.page, it.key, `Open on ${PN[it.page] || it.page} →`) : ''}</div></div>
        <div class="profile" style="margin-top:12px">${it.sections.map(s => `<div class="src"><h4>${esc(s.h)}</h4><dl class="kv">${s.kv.map(([k, v, tools]) => `<dt>${esc(k)}</dt><dd>${tools ? `<span class="tis">${tools.map(toolIcon).join('')}</span>` : ''}${esc(v)}</dd>`).join('')}</dl></div>`).join('')}</div>`;
      $('lkQ').value = it.label; $('lkSugg').hidden = true; $('lkQ').setAttribute('aria-expanded', 'false');
      try { location.hash = encodeURIComponent(it.key); } catch {}
    };
    let sel = -1, list = [];
    const suggest = () => {
      const q = $('lkQ').value.trim().toLowerCase();
      list = q ? m.items.filter(i => `${i.label} ${i.sub} ${i.key}`.toLowerCase().includes(q)).slice(0, 12) : [];
      sel = -1;
      $('lkSugg').innerHTML = list.map((i, k) => `<li role="option" data-k="${k}" aria-selected="false"><span>${esc(i.label)}</span><small>${esc(i.kind)}${i.sub ? ' · ' + esc(i.sub) : ''}</small></li>`).join('') || (q ? '<li class="none">No matches</li>' : '');
      $('lkSugg').hidden = !q; $('lkQ').setAttribute('aria-expanded', String(!!q));
    };
    $('lkQ').addEventListener('input', suggest);
    $('lkQ').addEventListener('keydown', e => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, Math.min(list.length - 1, sel + (e.key === 'ArrowDown' ? 1 : -1))); [...$('lkSugg').children].forEach((li, k) => li.setAttribute('aria-selected', String(k === sel))); }
      else if (e.key === 'Enter') { e.preventDefault(); show(list[sel >= 0 ? sel : 0]); }
      else if (e.key === 'Escape') { $('lkSugg').hidden = true; }
    });
    $('lkSugg').addEventListener('mousedown', e => { const li = e.target.closest('[data-k]'); if (li) { e.preventDefault(); show(list[+li.dataset.k]); } });
    document.querySelectorAll('select[data-kind]').forEach(s => s.addEventListener('change', () => { const it = m.items.find(i => i.kind === s.dataset.kind && i.key === s.value); show(it); }));
    const h = decodeURIComponent((location.hash || '').slice(1)); if (h) show(m.items.find(i => i.key === h));
    // ?q= from another page: open the best match (exact name first).
    const q = (new URLSearchParams(location.search).get('q') || '').toLowerCase();
    if (q && !h) show(m.items.find(i => i.label.toLowerCase() === q || String(i.key).toLowerCase().endsWith(q)) || m.items.find(i => `${i.label} ${i.sub} ${i.key}`.toLowerCase().includes(q)));
  },
  how: m => [
    `POST /api/v2/inventory/identities/query and /device-profiles/query  (Environment ${m.environment.ID})`,
    'Plus the Stack coverage, Email & domain security, AI usage and Identity data, so each card agrees with those pages.',
    'Rules: src/main/panels/lookup.js',
  ].join('\n'),
};
