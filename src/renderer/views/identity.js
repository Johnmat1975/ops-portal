// Admin rights grouped: local admin rights on many Windows machines become one line.
function adminLines(admin, html) {
  const local = admin.filter(a => /^(Windows Workstation|Windows Server|macOS|Linux)$/.test(a.inspector));
  const other = admin.filter(a => !local.includes(a));
  const lines = other.map(a => html ? `${esc(a.inspector)}${a.role ? ` <span class="sub">${esc(a.role)}</span>` : ''}` : `${a.inspector}${a.role ? ` (${a.role})` : ''}`);
  if (local.length) lines.push(html ? `<span title="${esc(local.map(a => a.system).join(', '))}">Local admin on ${local.length} device${local.length > 1 ? 's' : ''}</span>` : `Local admin on ${local.length} device${local.length > 1 ? 's' : ''} (${local.map(a => a.system).join('; ')})`);
  return lines;
}
// Identity & access view: what needs attention, who can administer what, every account with its systems, and a
// user access review the client can sign.
// Counts a tool reports without naming anyone: listed under the people, never added to the number.
const mfaTools = (m, c, admin) => ((m.mfa || {}).tools || []).filter(f => f.admin === admin).map(f => ({ t: `${f.inspector}’s own count: ${f.n}`, d: `${f.label}, from ${f.system}. Counts every kind of account, so it isn’t added to the number`, url: LG.system(c, f.systemId, f.systemDetailId), sev: 'info' }));

// ---------- People & devices ----------
// Which person uses which device, from every tool that records it. "Owner" = the tool records the device's owner or primary
// user (MDM, Intune, phones); "Last sign-in" = who last signed in (RMM, EDR), which isn't proof of ownership.
const UD_STRENGTH = { assigned: ['c-ok', 'Owner'], last: ['c-none', 'Last sign-in'] };
function udSection(m) {
  const u = m.userDevices; if (!u) return '';
  const src = u.sources.map(x => `${x.inspector} (${x.n})`).join(', ');
  const ex = u.exceptions;
  return `<h3 style="margin-top:22px" id="udTitle">People & devices</h3>
    <p class="sub">${u.devices.length ? `${u.linked} of ${u.devices.length} devices with a recorded user are linked to a person, from ${esc(src)}.` : 'None of this client’s tools record who uses each device.'}
      <b>Owner</b> means a tool records the device’s owner or primary user; <b>Last sign-in</b> means who last signed in, which isn’t proof of ownership.</p>
    ${u.devices.length ? `<div class="quick no-print" id="udF">${[['person', 'By person'], ['device', 'By device'], ['ex', `Exceptions (${ex.leavers.length + ex.noDevice.length + ex.disagree.length})`]].map(([k, l], i) => `<button type="button" data-v="${k}" aria-pressed="${i === 0}">${l}</button>`).join('')}
      <div class="search" style="flex:1;min-width:200px;margin:0"><input id="udQ" placeholder="Search people and devices" autocomplete="off" aria-label="Search people and devices"></div></div>
      <div class="tw"><table id="udTable"></table></div>` : ''}`;
}
function udWire(m, ctx) {
  const u = m.userDevices; if (!u || !u.devices.length || !$('udTable')) return;
  const byId = new Map(m.rows.map(r => [r.id, r]));
  const who = id => { const r = byId.get(id); return r ? lgA(LG.identity(ctx, r.id), esc(r.name), 'Open this person in Liongard') : '—'; };
  const dev = (host, id) => id ? lgA(LG.device(ctx, id), esc(host), 'Open this device in Liongard') : esc(host);
  const chip = k => `<span class="chip ${UD_STRENGTH[k][0]}">${UD_STRENGTH[k][1]}</span>`;
  const seen = v => v ? fmtDate(v, true) : '—';
  let view = 'person', q = '';
  const hit = (...xs) => !q || xs.join(' ').toLowerCase().includes(q);
  const draw = () => {
    let html = '';
    if (view === 'person') {
      const rows = m.rows.filter(r => r.devices.length && hit(r.name, r.email, r.devices.map(d => d.host).join(' ')));
      html = `<thead><tr><th>Person</th><th>Devices</th><th>Last seen</th></tr></thead><tbody>${rows.map(r => `<tr>
        <td class="wrap" data-csv="${esc(r.name)}"><b>${who(r.id)}</b>${r.enabled ? '' : ' <span class="chip c-crit">Disabled</span>'}<div class="sub mono" style="margin:0">${esc(r.email || r.username || '')}</div></td>
        <td class="wrap" data-csv="${esc(r.devices.map(d => `${d.host} (${UD_STRENGTH[d.strength][1]}${d.shared ? ', shared' : ''}: ${d.sources.join(', ')})`).join('; '))}">${r.devices.map(d => `<div style="margin:2px 0">${dev(d.host, d.deviceId)} ${chip(d.strength)}${d.shared ? ' <span class="chip c-none" title="Several people sign in here">Shared</span>' : ''} <span class="tis">${d.sources.map(toolIcon).join('')}</span><span class="sub" style="margin:0">${esc(d.sources.join(', '))}</span></div>`).join('')}</td>
        <td class="num">${seen(r.devices.map(d => d.seen).filter(Boolean).sort().pop())}</td></tr>`).join('') || '<tr><td colspan="3">No matches.</td></tr>'}</tbody>`;
    } else if (view === 'device') {
      const rows = u.devices.filter(d => hit(d.host, d.links.map(l => l.user).join(' '), d.likely ? d.likely.name : ''));
      html = `<thead><tr><th>Device</th><th>Likely user</th><th>Everyone recorded</th><th>Last seen</th></tr></thead><tbody>${rows.map(d => `<tr>
        <td class="mono" data-csv="${esc(d.host)}">${dev(d.host, d.deviceId)}${d.os ? `<div class="sub" style="margin:0">${esc(d.os)}</div>` : ''}</td>
        <td class="wrap" data-csv="${esc(d.likely ? `${d.likely.name} (${UD_STRENGTH[d.likely.strength][1]}, ${d.likely.source})` : '—')}">${d.likely ? `${who(d.likely.personId)} ${chip(d.likely.strength)}<div class="sub" style="margin:0">${toolIcon(d.likely.source)}${esc(d.likely.source)}</div>` : '<span class="sub">No person</span>'}${d.shared ? ' <span class="chip c-none">Shared</span>' : ''}${d.disagree ? ' <span class="chip c-warn" title="Tools name different people">Tools disagree</span>' : ''}</td>
        <td class="wrap" style="font-size:12.5px" data-csv="${esc(d.links.map(l => `${l.user} (${l.source})`).join('; '))}">${d.links.map(l => `<div>${toolIcon(l.source)}${l.personId ? who(l.personId) : esc(l.user)} <span class="sub" style="margin:0">· ${esc(l.source)}${l.kind === 'builtin' ? ' · built-in account' : l.kind === 'account' ? ' · admin or service account' : l.kind === 'unknown' ? ' · not in identity data' : ''}</span></div>`).join('')}</td>
        <td class="num">${seen(d.lastSeen)}</td></tr>`).join('') || '<tr><td colspan="4">No matches.</td></tr>'}</tbody>`;
    } else {
      const ex = u.exceptions;
      const grp = (title, why, items) => items.length ? `<tr><th colspan="2" style="text-align:left">${esc(title)} (${items.length}) <span class="sub" style="margin:0;font-weight:400">${esc(why)}</span></th></tr>${items.join('')}` : '';
      const pRow = (id, d) => hit(byId.get(id) && byId.get(id).name) ? `<tr><td class="wrap">${who(id)}</td><td class="wrap">${d}</td></tr>` : '';
      const dRow = (host, d) => { const x = u.devices.find(y => y.host === host); return hit(host) ? `<tr><td class="mono">${dev(host, x && x.deviceId)}</td><td class="wrap">${d}</td></tr>` : ''; };
      html = `<thead><tr><th>Who or what</th><th>Detail</th></tr></thead><tbody>` +
        grp('Disabled, but still on a device', 'Leavers whose device is still in use or still assigned to them.', ex.leavers.map(id => pRow(id, esc(byId.get(id).devices.map(d => `${d.host} (${UD_STRENGTH[d.strength][1]})`).join(', '))))) +
        grp('Tools disagree on who uses the device', 'Different tools name different people as the last user.', ex.disagree.map(h => dRow(h, esc(u.devices.find(d => d.host === h).links.filter(l => l.personId).map(l => `${byId.get(l.personId).name} (${l.source})`).join(', '))))) +
        grp('Licensed people with no device linked', 'No tool links them to a device: they may use one no tool manages, or only sign in on the web.', ex.noDevice.map(id => pRow(id, esc((byId.get(id).licences || []).join(', ') || 'Licensed')))) +
        grp('Devices with no person linked', 'Only built-in or admin accounts sign in, or the user isn’t in the identity data.', ex.noPerson.map(h => { const d = u.devices.find(y => y.host === h); return dRow(h, esc([...d.adminUsers.map(a => `${a} (admin account)`), ...d.unknownUsers.map(x => `${x} (not in identity data)`), ...(d.links.some(l => l.kind === 'builtin') ? ['built-in accounts only'] : [])].join(', ') || 'No user recorded')); })) +
        '</tbody>';
      if (!/<tr><td/.test(html)) html = '<tbody><tr><td>No exceptions.</td></tr></tbody>';
    }
    $('udTable').innerHTML = html;
  };
  $('udF').addEventListener('click', e => { const b = e.target.closest('[data-v]'); if (!b) return; [...$('udF').querySelectorAll('[data-v]')].forEach(x => x.setAttribute('aria-pressed', x === b)); view = b.dataset.v; draw(); });
  $('udQ').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); draw(); });
  draw();
}

window.VIEWS.identity = {
  title: 'Identity & access',
  kpiItems: {
    'People': (m, c) => m.rows.filter(r => r.enabled && (r.kind === 'Person' || r.kind === 'Admin account')).map(r => ({ t: r.name, d: [r.email, r.kind !== 'Person' && r.kind, r.sources.join(', ')].filter(Boolean).join(' · '), url: LG.identity(c, r.id) })),
    'MFA everywhere': (m, c) => m.rows.filter(r => [...(m.mfa.admins || []), ...(m.mfa.users || [])].includes(r.id)).map(r => ({ t: r.name, d: r.mfaMissingIn.length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : ({ NO: 'No MFA', PARTIAL: 'MFA in some systems only' }[r.mfa] || 'MFA not reported'), url: LG.identity(c, r.id), sev: r.mfa === 'NO' || m.mfa.admins.includes(r.id) ? 'bad' : 'warn' })),
    'Admins without MFA': (m, c) => ((m.groups.find(g => g.key === 'adminmfa') || {}).items || []).map(i => ({ t: i.t, d: `${i.d}${i.admin ? ` · admin in ${i.admin}` : ''}`, url: LG.identity(c, i.identityId), sev: 'bad' }))
      .concat(mfaTools(m, c, true)),
    'Users without MFA': (m, c) => m.rows.filter(r => (m.mfa.users || []).includes(r.id)).map(r => ({ t: r.name, d: r.mfaMissingIn.length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : 'No MFA', url: LG.identity(c, r.id), sev: 'warn' }))
      .concat(mfaTools(m, c, false)),
    'Leavers with access': (m, c) => m.rows.filter(r => r.otherAccess.length).map(r => ({ t: r.name, d: `Disabled, still in ${r.otherAccess.join(', ')}`, url: LG.identity(c, r.id), sev: 'bad' })),
    'Stale accounts': (m, c) => m.rows.filter(r => r.stale).map(r => ({ t: r.name, d: r.lastLogin ? `Last sign-in ${fmtDate(r.lastLogin, true)}` : 'Never signed in', url: LG.identity(c, r.id), sev: 'warn' })),
    'Duo bypass codes': m => m.bypass.map(b => ({ t: b.u || b.e, d: `${b.daysLeft == null ? 'No expiry' : `Valid for ${b.daysLeft} more days`}${b.by ? ` · created by ${b.by}` : ''}`, sev: b.daysLeft == null || b.daysLeft > 30 ? 'warn' : 'ok' })),
  },
  intro: 'Every account Liongard reconciles across this client’s identity sources, sorted into people, admin accounts, service accounts, shared mailboxes and guests, with what each system reports about them: admin rights, MFA, leavers, stale accounts and licences.',
  exports: [{ label: 'PDF: user access review (for client sign-off)', mode: 'review', title: 'User access review', kicker: 'For client sign-off' }],
  handlesQuery: false,
  render(m, ctx) {
    const MFA = { yes: 'c-ok', partial: 'c-warn', no: 'c-crit' };
    const who = i => i.identityId ? lgA(LG.identity(ctx, i.identityId), esc(i.t), 'Open this person in Liongard') : esc(i.t);
    const groups = m.groups.map(g => `<details class="ag" ${g.sev === 'bad' ? 'open' : ''} style="--sev:${g.sev === 'bad' ? 'var(--crit)' : 'var(--warn)'};--sev-text:${g.sev === 'bad' ? 'var(--sev-crit-ink)' : 'var(--sev-warn-ink)'}"><summary><span class="pt-n">${g.items.length}</span><span><b>${esc(g.title)}</b>${g.why ? `<span class="sub" style="display:block;margin:0">${esc(g.why)}</span>` : ''}</span></summary>
      <ul class="plain">${g.items.slice(0, 30).map(i => `<li><span><b>${who(i)}</b> <span class="sub" style="margin:0">${esc(i.d)}</span>${g.key === 'licence' && i.q ? ` ${pageA('licences', i.q, 'Licences →')}` : ''}</span></li>`).join('')}${g.items.length > 30 ? `<li class="sub">and ${g.items.length - 30} more (filter the accounts table)</li>` : ''}</ul></details>`).join('');
    const admins = m.admins.map(a => `<tr><td class="wrap" style="min-width:160px">${toolIcon(a.inspector)}${lgA(LG.system(ctx, a.systemId, a.systemDetailId), esc(a.system), 'Open this system in Liongard')}<div class="sub" style="margin:0">${esc(a.inspector)}</div></td>
      <td class="wrap" data-csv="${esc(a.admins.map(x => `${x.label}${x.role ? ` (${x.role})` : ''}`).join(', '))}">${a.admins.map(x => `<span class="chip ${MFA[x.mfa] || 'c-none'}" title="${esc([x.role && `Role: ${x.role}`, x.mfa && `MFA: ${x.mfa}`, x.enabled === false && 'Disabled', x.msp && 'MSP account'].filter(Boolean).join(' · ') || 'Not matched to a person in Liongard')}">${x.personId ? lgA(LG.identity(ctx, x.personId), esc(x.label)) : esc(x.label)}${x.role ? ` <small>${esc(x.role)}</small>` : ''}${x.msp ? ' <small>MSP</small>' : ''}</span>`).join(' ')}</td><td class="c mono">${a.admins.length}</td></tr>`).join('');
    const review = m.rows.filter(r => r.enabled && ['Person', 'Admin account', 'Shared', 'Guest'].includes(r.kind)).sort((a, b) => (b.privileged - a.privileged) || a.name.localeCompare(b.name));
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <p class="sub xref">“Stale” here means no sign-in for ${esc(m.staleDays)}+ days. Unused licences (no Microsoft 365 sign-in for 30+ days) are counted on ${pageA('licences', '', 'Licence reconciliation →')}</p>
      <h3>Needs attention</h3>
      <div class="ags">${groups || '<p class="sub">Nothing needs attention.</p>'}</div>
      ${udSection(m)}
      <h3 style="margin-top:22px">Who can administer what</h3>
      <p class="sub">Admins in every system whose Liongard data lists them: Microsoft 365 roles, directory admins, Duo owners, firewall and network admins, SQL sysadmins and local admins. Colour shows MFA for that person: <span class="chip c-ok">MFA</span> <span class="chip c-warn">partial</span> <span class="chip c-crit">none</span> <span class="chip c-none">not matched to a person</span></p>
      ${m.tenant.length ? `<p class="sub">${m.tenant.map(t => `${esc(t.t)}: <b>${esc(t.v)}</b> (${lgA(LG.system(ctx, t.systemId, t.systemDetailId), esc(t.system))})`).join(' · ')}</p>` : ''}
      ${m.admins.length ? `<div class="tw"><table><thead><tr><th>System</th><th>Admins</th><th class="c">Count</th></tr></thead><tbody>${admins}</tbody></table></div>` : '<p class="sub">No admin lists in this client’s Liongard metrics.</p>'}
      <div class="two" style="margin-top:16px">
        <div class="card no-print msp"><h3>Your MSP’s accounts</h3><p class="sub" style="margin:0">Accounts matching these are tagged MSP everywhere, so you can see your own access at every client.</p>
          <label class="fld">Email domains <input id="mspDomains" value="${esc((m.msp.domains || []).join(', '))}" placeholder="yourmsp.com, yourmsp.co.uk"></label>
          <label class="fld">Name contains <input id="mspNames" value="${esc((m.msp.names || []).join(', '))}" placeholder="YourMSP, msp-admin"></label>
          <div><button type="button" class="btn sm" id="mspSave">Save</button> <span class="sub" id="mspNote">Applies to every client.</span></div></div>
        <div class="card"><h3>Accounts by type</h3><div class="bars">${m.kindsCount.map(k => `<div class="bar"><span>${esc(k.w[1].replace(/^./, c => c.toUpperCase()))}</span><div class="track"><div class="fill" style="width:${k.n / Math.max(...m.kindsCount.map(x => x.n)) * 100}%"></div></div><span class="mono">${k.n}</span></div>`).join('')}</div>
          <p class="sub">MFA coverage counts people and admin accounts only, so service accounts, mailboxes and guests don’t skew it.</p></div>
      </div>
      <h3 style="margin-top:22px">Accounts</h3>
      <div class="filters">
        <div class="quick" id="idKind">${['All', ...m.kindsCount.map(k => k.k)].map((k, i) => `<button type="button" data-k="${k}" aria-pressed="${i === 0}">${k === 'All' ? 'All' : esc(m.kindsCount.find(x => x.k === k).w[1].replace(/^./, c => c.toUpperCase()))} <span class="sub">${k === 'All' ? m.rows.length : m.kindsCount.find(x => x.k === k).n}</span></button>`).join('')}</div>
        <select id="idStatus" aria-label="Show"><option value="">Any status</option><option value="priv">Admin rights</option><option value="nomfa">No MFA</option><option value="gap">MFA gap in a system</option><option value="stale">Stale (${m.staleDays}+ days)</option><option value="disabled">Disabled</option><option value="leaver">Disabled, still in other tools</option><option value="msp">MSP accounts</option><option value="lic">Licensed</option><option value="risk">Dark web or training</option></select>
        <select id="idSys" aria-label="System"><option value="">Any system</option>${[...new Set(m.rows.flatMap(r => r.sources))].sort().map(s => `<option>${esc(s)}</option>`).join('')}</select>
        <div class="search" style="flex:1;min-width:200px;margin:0"><input id="idFilter" placeholder="Search name, email, system or licence" autocomplete="off" aria-label="Search accounts"></div>
        <button type="button" class="btn ghost sm" id="reviewCsv">Access review CSV</button>
      </div>
      <p class="sub" id="idCount"></p>
      <div class="tw tech"><table id="idTable"></table></div>
      <div class="review-only">
        <p>Please review each account below. Tick <b>Keep</b> if the person still needs this access, or <b>Remove</b> if it should be taken away, and return the signed copy to us.</p>
        <table class="review"><thead><tr><th>Account</th><th>Systems</th><th>Admin rights</th><th>MFA</th><th>Last sign-in</th><th>Keep</th><th>Remove</th><th>Notes</th></tr></thead><tbody>
          ${review.map(r => `<tr><td><b>${esc(r.name)}</b><div class="sub" style="margin:0">${esc(r.email || '')}${r.kind !== 'Person' ? ` · ${esc(r.kind)}` : ''}${r.msp ? ' · MSP' : ''}</div></td><td>${esc(r.sources.join(', '))}</td><td>${esc(adminLines(r.admin, false).join('; ') || (r.privileged ? 'Privileged' : '—'))}</td><td>${esc(r.mfa === 'YES' ? 'Yes' : r.mfa === 'NO' ? 'No' : r.mfa === 'PARTIAL' ? 'Partial' : '—')}${r.mfaMissingIn.length ? `, none in ${esc(r.mfaMissingIn.join(', '))}` : ''}</td><td>${r.lastLogin ? fmtDate(r.lastLogin, true) : '—'}</td><td class="box">☐</td><td class="box">☐</td><td></td></tr>`).join('')}
        </tbody></table>
        <div class="signoff"><div>Reviewed by (client): ____________________________</div><div>Date: ______________</div><div>Signature: ____________________________</div></div>
      </div>`;
  },
  after(m, ctx) {
    udWire(m, ctx);
    const MFA_T = { YES: '<i class="tick t-ok" title="MFA">✓</i>', NO: '<i class="tick t-bad" title="No MFA">✕</i>', PARTIAL: '<i class="tick t-warn" title="Partial">!</i>' };
    let kind = 'All', status = '', sys = '', q = '';
    const match = r => (kind === 'All' || r.kind === kind) && (!sys || r.sources.includes(sys))
      && (!status || (status === 'priv' && r.privileged) || (status === 'nomfa' && r.mfa === 'NO') || (status === 'gap' && r.mfaMissingIn.length) || (status === 'stale' && r.stale) || (status === 'disabled' && !r.enabled)
        || (status === 'leaver' && r.otherAccess.length) || (status === 'msp' && r.msp) || (status === 'lic' && r.licences.length) || (status === 'risk' && (r.darkweb.length || r.training.length)))
      && (!q || [r.name, r.email, r.username, r.kind, ...r.sources, ...r.licences, ...r.admin.map(a => a.system)].join(' ').toLowerCase().includes(q));
    const draw = () => {
      const rows = m.rows.filter(match);
      $('idCount').textContent = `${rows.length} account${rows.length === 1 ? '' : 's'}`;
      $('idTable').innerHTML = `<thead><tr><th>Account</th><th>Systems</th><th class="c">MFA</th><th>Admin rights</th><th>Last sign-in</th><th>Licences</th><th>Risk</th></tr></thead><tbody>` + (rows.map(r => `<tr class="${r.enabled ? '' : 'dim'}">
        <td class="wrap" style="min-width:170px" data-csv="${esc(r.name)} <${esc(r.email || '')}>"><b>${lgA(LG.identity(ctx, r.id), esc(r.name), 'Open this person in Liongard')}</b> ${pageA('lookup', r.email || r.name, '↗', 'Everything about this person (Lookup)')}
          <div class="sub mono" style="margin:0">${esc(r.email || r.username || '')}</div>
          <div>${r.kind !== 'Person' ? `<span class="chip c-none">${esc(r.kind)}</span> ` : ''}${r.msp ? '<span class="chip c-gold">MSP</span> ' : ''}${r.enabled ? '' : '<span class="chip c-none">Disabled</span> '}${r.state === 'Discovery' ? '<span class="chip c-none" title="Still in Discovery in Liongard">Not reviewed</span>' : ''}</div></td>
        <td class="wrap" style="min-width:200px" data-csv="${esc(r.sources.join(', '))}">${(r.sourceRefs || []).map(s => { const gap = r.mfaMissingIn.includes(s.alias), adm = r.admin.find(a => a.inspector === s.alias); return `<span class="chip ${gap ? 'c-crit' : 'c-none'}" title="${esc([gap && 'No MFA here', adm && `Admin${adm.role ? `: ${adm.role}` : ''}`].filter(Boolean).join(' · ') || s.alias)}">${lgA(LG.system(ctx, s.systemId, s.systemDetailId), esc(s.alias))}${adm ? ' <small>admin</small>' : ''}</span>`; }).join(' ')}</td>
        <td class="c" data-csv="${esc(r.mfa)}${r.mfaMissingIn.length ? ` (none in ${esc(r.mfaMissingIn.join(', '))})` : ''}">${MFA_T[r.mfa] || '<i class="tick t-none">–</i>'}${r.mfaMissingIn.length ? `<div class="sub" style="margin:0;white-space:normal">None in ${esc(r.mfaMissingIn.join(', '))}</div>` : ''}</td>
        <td class="wrap" style="min-width:140px" data-csv="${esc(adminLines(r.admin, false).join('; '))}">${adminLines(r.admin, true).join('<br>') || (r.privileged ? 'Privileged' : '')}</td>
        <td data-csv="${esc(r.lastLogin || '')}">${r.lastLogin ? `${fmtDate(r.lastLogin, true)}${r.stale ? ' <span class="chip c-warn">Stale</span>' : ''}` : '<span class="sub">Never</span>'}${r.staleConflict ? `<div class="sub" style="margin:0">${esc(r.staleIn.join(', '))} says stale</div>` : ''}</td>
        <td class="wrap" style="min-width:140px" data-csv="${esc(r.licences.join(', '))}">${r.licences.map(l => `<span class="prod">${pageA('licences', r.email, esc(l), 'Open Licence reconciliation')}</span>`).join(' ')}</td>
        <td class="wrap" style="min-width:140px">${[r.darkweb.length && `Dark web: ${esc(r.darkweb[0])}`, r.training.length && `${r.training.length} overdue training`, r.neverExpires && 'Password never expires', r.stalePwd && 'Stale admin password', r.otherAccess.length && `Disabled, still in ${esc(r.otherAccess.join(', '))}`].filter(Boolean).join('<br>')}${r.devices.length ? `<div class="sub" style="margin:0">Uses ${r.devices.slice(0, 3).map(d => lgA(LG.device(ctx, d.id), esc(d.host))).join(', ')}</div>` : ''}</td></tr>`).join('') || '<tr><td colspan="7">No accounts match.</td></tr>') + '</tbody>';
    };
    const pick = (id, attr, fn) => $(id).addEventListener('click', e => { const b = e.target.closest(`[${attr}]`); if (!b) return; [...$(id).children].forEach(x => x.setAttribute('aria-pressed', x === b)); fn(b.getAttribute(attr)); draw(); });
    pick('idKind', 'data-k', v => { kind = v; });
    $('idStatus').addEventListener('change', e => { status = e.target.value; draw(); });
    $('idSys').addEventListener('change', e => { sys = e.target.value; draw(); });
    $('idFilter').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); draw(); });
    draw();
    // ?q= from another page.
    const q0 = new URLSearchParams(location.search).get('q'); if (q0) { $('idFilter').value = q0; q = q0.toLowerCase(); draw(); }
    $('mspSave').addEventListener('click', async () => {
      const split = v => v.split(/[,\n]/).map(x => x.trim()).filter(Boolean);
      await window.portal.setMsp({ domains: split($('mspDomains').value), names: split($('mspNames').value) });
      location.reload();
    });
    $('reviewCsv').addEventListener('click', async () => {
      const rows = m.rows.filter(r => r.enabled && ['Person', 'Admin account', 'Shared', 'Guest'].includes(r.kind));
      const csv = ['Account,Email,Type,MSP,Systems,Admin rights,MFA,No MFA in,Last sign-in,Licences,Keep or remove,Notes', ...rows.map(r => [r.name, r.email, r.kind, r.msp ? 'Yes' : '', r.sources.join('; '), adminLines(r.admin, false).join('; '), r.mfa, r.mfaMissingIn.join('; '), r.lastLogin || '', r.licences.join('; '), '', ''].map(csvCell).join(','))].join('\n');
      const saved = await window.portal.exportCsv({ name: `${m.environment.Name}-user-access-review`.replace(/[^\w-]+/g, '-'), csv });
      if (saved) $('statusLine').textContent = `Saved ${saved}`;
    });
  },
  how: m => [
    `POST /api/v2/inventory/identities/query  (Environment ${m.environment.ID})  → reconciled accounts: MFA, privileged, licences, activity, the systems each is in`,
    'POST /api/v2/metrics/evaluate/systems  → admin lists (M365 roles, AD, Duo, firewalls, SQL, local admins), no-MFA lists per system, disabled and stale lists, password hygiene, dark web and training',
    m.duoSys ? `POST /api/v2/dataprints/evaluate/${m.duoSys.systemDetailId}  Duo Security: enrolment, bypass codes, admins` : 'No Duo inspector in this environment',
    'POST /api/v2/inventory/device-profiles/query  → the devices each person last signed in to',
    'Rules: src/main/panels/identity.js',
  ].join('\n'),
};
