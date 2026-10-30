// AI usage view.
window.VIEWS.ai = {
  title: 'AI usage',
  kpiItems: {
    'Biggest AI users': m => m.rows.filter(r => r.code && r.code.cost > 0).sort((a, b) => b.code.cost - a.code.cost).map(r => ({ t: r.name, d: `${fmtMoney(r.code.cost, 'USD')} Claude Code · ${r.code.sessions} sessions`, page: 'identity', q: r.email })),
    'AI users': m => m.rows.map(r => ({ t: r.name, d: [r.email, ...Object.entries(r.platforms || {}).map(([k, v]) => `${k === 'anthropic' ? 'Claude' : 'OpenAI'}: ${v.role}`)].join(' · '), page: 'identity', q: r.email || r.name, sev: r.risk ? 'bad' : '' })),
    'Active API keys': m => m.keys.map(k => ({ t: k.name, d: `${k.owner}${k.workspace ? ` · ${k.workspace}` : ''} · ${k.age} days old${k.expires ? '' : ', never expires'}`, sev: k.age > 90 && !k.expires ? 'warn' : '' })),
    'Spend': m => m.cost.map(x => ({ t: fmtDate(x.d, true), d: fmtMoney(x.usd, 'USD') })),
    'Users without MFA or Duo': m => m.rows.filter(r => r.risk).map(r => ({ t: r.name, d: r.notes.join('. '), page: 'identity', q: r.email || r.name, sev: 'bad' })),
  },
  intro: 'Who uses Claude and ChatGPT, what it costs, how old the API keys are, and whether those people are protected by MFA and Duo.',
  render(m, ctx) {
    const tick = v => v === 'YES' || v === 'enrolled' ? '<i class="tick t-ok">✓</i>' : v === 'NO' || v === 'not-enrolled' ? '<i class="tick t-bad">✕</i>' : '<i class="tick t-none">–</i>';
    if (!m.platforms.length) return '<div class="card"><h3>No AI inspectors</h3><p class="sub">This environment has no Anthropic or OpenAI launchpoint. Add one in Liongard to see AI usage, cost and keys here.</p></div>';
    const max = Math.max(1, ...m.cost.map(c => c.usd));
    const W = 420, H = 130, l = 40, r = 8, t = 10, b = 24, bw = (W - l - r) / Math.max(1, m.cost.length);
    let spark = ''; [0, .5, 1].forEach(f => { const v = max * f, y = t + (H - t - b) * (1 - f); spark += `<line x1="${l}" x2="${W - r}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${l - 6}" y="${y + 4}" font-size="10.5" fill="var(--muted)" text-anchor="end" font-family="IBM Plex Mono, monospace">$${v.toFixed(0)}</text>`; });
    m.cost.forEach((c, i) => { const h = (H - t - b) * c.usd / max, x = l + i * bw + bw * .18; spark += `<rect x="${x}" y="${H - b - h}" width="${bw * .64}" height="${Math.max(h, .5)}" rx="2" fill="var(--gold)"><title>${esc(c.d)}: US$${c.usd.toFixed(2)}</title></rect><text x="${x + bw * .32}" y="${H - 8}" font-size="10.5" fill="var(--muted)" text-anchor="middle" font-family="IBM Plex Sans, Arial">${c.d.slice(8)}</text>`; });
    const plat = m.platforms.map(p => p.key);
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(x => `<li><span>${esc(x)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      ${m.platforms.filter(p => p.note).map(p => `<div class="card missing"><h3>${esc(p.label)}</h3><p class="sub" style="margin:0">${esc(p.note)}.</p></div>`).join('')}
      <div class="two">
        <div class="card"><h3>Claude spend by day</h3>${m.cost.length ? `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Daily Claude spend">${spark}</svg><p class="sub" style="margin:0">Total ${esc(fmtMoney(m.total, 'USD'))} across the days the inspector reports. Anthropic’s cost report covers a rolling window, so this isn’t a monthly bill.${m.usage && m.usage.length ? ` Tokens over the same days: ${(m.usage.reduce((t, u) => t + u.inTok, 0) / 1e6).toFixed(2)}M in, ${(m.usage.reduce((t, u) => t + u.outTok, 0) / 1e6).toFixed(2)}M out.` : ''}</p>` : '<p class="sub">No cost data reported.</p>'}</div>
        <div class="card"><h3>API keys</h3><p class="sub" style="margin:0">${m.keys.length} active, ${m.oldKeys} older than 90 days with no expiry. Keys that never expire should be rotated on a schedule.</p>
          <div class="tw"><table><thead><tr><th>Key</th><th>Owner</th><th>Workspace</th><th class="c">Age</th></tr></thead><tbody>${m.keys.map(k => `<tr><td class="mono" style="font-size:12.5px">${esc(k.name)}</td><td>${esc(k.owner)}</td><td>${esc(k.workspace)}</td><td class="c"><span class="chip ${k.age > 90 ? 'c-warn' : 'c-none'}">${k.age} d</span></td></tr>`).join('')}</tbody></table></div></div>
      </div>
      ${(() => {   // only when Anthropic reports spend per person (Claude Code); otherwise there's nothing to rank
        const ranked = m.rows.filter(r => r.code && r.code.cost > 0).sort((a, b) => b.code.cost - a.code.cost);
        if (!ranked.length) return '';
        const max = ranked[0].code.cost;
        return `<div class="card" id="topUsers"><h3>Biggest AI users</h3><p class="sub" style="margin:0">By Anthropic\u2019s estimated Claude Code cost over ${m.codeDays} day${m.codeDays === 1 ? '' : 's'}${m.total ? `. API spend (US$${m.total.toFixed(2)}) isn\u2019t reported per person, so it isn\u2019t included` : ''}.</p>
          <div class="bars">${ranked.slice(0, 10).map(r => `<div class="bar"><span>${pageA('identity', r.email, esc(r.name))}</span><div class="track"><div class="fill" style="width:${r.code.cost / max * 100}%"></div></div><span class="mono">US$${r.code.cost.toFixed(2)}</span></div>`).join('')}</div>
          ${ranked.length > 3 ? `<p class="sub" style="margin:0">The top 3 account for ${Math.round(ranked.slice(0, 3).reduce((t, r) => t + r.code.cost, 0) / Math.max(0.01, m.codeCost) * 100)}% of Claude Code cost${ranked.length > 10 ? ` (showing 10 of ${ranked.length})` : ''}.</p>` : ''}</div>`;
      })()}
      <h3>Usage and cost per person</h3>
      <p class="sub">${m.hasCode ? `Claude Code costs are Anthropic\u2019s own per-person estimates (${m.codeDays} day${m.codeDays === 1 ? '' : 's'} reported).` : 'No Claude Code usage reported for this organisation.'} API spend (US$${m.total.toFixed(2)} over ${m.cost.length} days) is reported by Anthropic for the whole organisation, not per person, so it isn\u2019t split here.<span class="no-print"> Add a monthly seat price per role to include seat costs. Prices are saved on this computer only.</span></p>
      <div class="filters no-print msp" id="seatPrices">${[...new Set(m.rows.map(r => (r.platforms.anthropic || {}).role).filter(Boolean))].map(r => `<label class="fld" style="min-width:150px">${esc(r)} seat / month (US$) <input class="seat" data-role="${esc(r)}" inputmode="decimal" placeholder="0.00"></label>`).join('')}</div>
      <div class="tw"><table id="perUser"></table></div>
      <h3 style="margin-top:22px">People</h3>
      <div class="tw"><table><thead><tr><th>Person</th>${plat.includes('anthropic') ? '<th>Claude role</th><th class="c">Claude keys</th>' : ''}${plat.includes('openai') ? '<th>OpenAI role</th><th class="c">OpenAI keys</th>' : ''}<th class="c">M365 MFA</th><th class="c">Duo</th><th>Notes</th></tr></thead><tbody>
        ${m.rows.map(r => `<tr><td data-csv="${esc(r.name)}"><b>${pageA('identity', r.email || r.name, esc(r.name), 'Open on the Identity page')}</b> ${pageA('lookup', r.email || r.name, '↗', 'Everything about this person (Lookup)')}<div class="sub mono" style="margin:0">${esc(r.email)}</div></td>${plat.includes('anthropic') ? `<td>${esc((r.platforms.anthropic || {}).role || '—')}</td><td class="c mono">${r.platforms.anthropic ? r.platforms.anthropic.keys : '—'}</td>` : ''}${plat.includes('openai') ? `<td>${esc((r.platforms.openai || {}).role || '—')}</td><td class="c mono">${r.platforms.openai ? r.platforms.openai.keys : '—'}</td>` : ''}<td class="c">${tick(r.mfa)}</td><td class="c">${tick(r.duo)}</td><td class="wrap">${esc(r.notes.join('. '))}</td></tr>`).join('')}
      </tbody></table></div>
      ${m.pendingInvites.length ? `<p class="sub">Pending invitations: ${m.pendingInvites.map(i => `${esc(i.email)} (${esc(i.role)})`).join(', ')}.</p>` : ''}`;
  },
  after(m) {
    if (!$('perUser')) return;
    const store = `aiSeats:${m.instance}`;
    let seats = {}; try { seats = JSON.parse(localStorage.getItem(store) || '{}'); } catch {}
    const money = v => fmtMoney(v, 'USD');   // Anthropic bills in US dollars; seat prices here are entered in US dollars too
    const draw = () => {
      const rows = m.rows.map(r => {
        const role = (r.platforms.anthropic || {}).role || '';
        const seat = parseFloat(seats[role]); const code = r.code ? r.code.cost : 0;
        return { r, role, seat: isNaN(seat) ? null : seat, code, total: (isNaN(seat) ? 0 : seat) + code };
      }).sort((a, b) => b.total - a.total || a.r.name.localeCompare(b.r.name));
      const any = rows.some(x => x.seat != null);
      $('perUser').innerHTML = `<thead><tr><th>Person</th><th>Role</th><th>Workspaces</th><th class="c">API keys</th>${m.hasCode ? '<th class="c">Claude Code sessions</th><th class="c">Lines added / removed</th><th class="c">Commits / PRs</th><th class="c">Claude Code cost</th>' : ''}${any ? '<th class="c">Seat / month</th><th class="c">Total</th>' : ''}</tr></thead><tbody>` +
        rows.map(({ r, role, seat, code, total }) => `<tr><td data-csv="${esc(r.name)} <${esc(r.email)}>"><b>${pageA('identity', r.email || r.name, esc(r.name), 'Open on the Identity page')}</b><div class="sub mono" style="margin:0">${esc(r.email)}</div></td>
          <td>${esc(role || '—')}</td><td class="wrap">${esc((r.workspaces || []).map(w => `${w.n}${w.r ? ` (${String(w.r).replace(/^workspace_/, '')})` : ''}`).join(', ') || '—')}</td>
          <td class="c mono">${r.platforms.anthropic ? r.platforms.anthropic.keys : '—'}</td>
          ${m.hasCode ? `<td class="c mono">${r.code ? r.code.sessions : '—'}</td><td class="c mono">${r.code ? `${r.code.added} / ${r.code.removed}` : '—'}</td><td class="c mono">${r.code ? `${r.code.commits} / ${r.code.prs}` : '—'}</td>
          <td class="c mono">${r.code ? money(code) : '—'}</td>` : ''}${any ? `<td class="c mono">${seat == null ? '—' : money(seat)}</td><td class="c mono"><b>${money(total)}</b></td>` : ''}</tr>`).join('') +
        `<tr><td colspan="${m.hasCode ? 7 : 4}"><b>Total</b></td>${m.hasCode ? `<td class="c mono"><b>${money(rows.reduce((t, x) => t + x.code, 0))}</b></td>` : ''}${any ? `<td class="c mono"><b>${money(rows.reduce((t, x) => t + (x.seat || 0), 0))}</b></td><td class="c mono"><b>${money(rows.reduce((t, x) => t + x.total, 0))}</b></td>` : ''}</tr></tbody>`;
    };
    document.querySelectorAll('input.seat').forEach(i => {
      if (seats[i.dataset.role] != null) i.value = seats[i.dataset.role];
      i.addEventListener('input', () => { const v = i.value.trim(); if (v === '') delete seats[i.dataset.role]; else seats[i.dataset.role] = v; try { localStorage.setItem(store, JSON.stringify(seats)); } catch {} draw(); });
    });
    draw();
  },
  how: m => [
    ...m.platforms.map(p => `POST /api/v2/dataprints/evaluate/${p.systemDetailId}  ${p.label}: Users, APIKeys, Workspaces, WorkspaceMembers, OrgCostReport, MessagesUsage, ClaudeCodeUsage, Invites`),
    'Per person: Claude Code analytics (sessions, lines, commits, estimated cost per user). API spend and tokens are organisation totals in Liongard, so they aren\u2019t split per person.',
    `POST /api/v2/inventory/identities/query  (Environment ${m.environment.ID})  → MFA status for each AI user`,
    'POST /api/v2/dataprints/evaluate/…  Duo Security: Users (enrolment)',
    'Rules: src/main/panels/ai.js. Partial key hints are never shown.',
  ].join('\n'),
};
