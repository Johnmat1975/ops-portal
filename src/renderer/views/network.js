// Network & firmware view.
window.VIEWS.network = {
  title: 'Network & firmware',
  kpiItems: {
    'Network devices': (m, c) => m.cards.map(x => ({ t: `${x.name}: ${x.site}`, d: x.rows.slice(0, 3).map(r => `${r[0]}: ${r[1]}`).join(' · '), url: LG.system(c, x.systemId, x.systemDetailId), sev: x.flag === 'crit' ? 'bad' : x.flag })),
    'With issues': (m, c) => m.cards.filter(x => x.flag === 'crit').map(x => ({ t: `${x.name}: ${x.site}`, d: x.rows.filter(r => r[2] === 'bad').map(r => `${r[0]}: ${r[1]}`).join(' · '), url: LG.system(c, x.systemId, x.systemDetailId), sev: 'bad' })),
    'Models with firmware drift': m => m.firmware.filter(f => f.status === 'Drift').map(f => ({ t: f.model, d: `${f.versions.join(' · ')} on ${f.devices.join(', ')}`, sev: 'warn' })),
    'Network admins without MFA': m => m.admins.filter(a => a.mfa === 'NO' && a.access !== 'None').map(a => ({ t: a.name, d: `${a.where} · ${a.access}`, page: 'identity', q: a.login || a.name, sev: 'bad' })),
  },
  intro: 'Firewall health, security services and high availability, firmware drift across identical devices, and who can administer the network.',
  render(m, ctx) {
    const chip = { ok: 'c-ok', bad: 'c-crit', warn: 'c-warn', none: '' };
    // Cards show their 5 most important rows (flagged first); "Show all" opens the rest.
    const SHOW = 5, RANK = { bad: 0, warn: 1 };
    const top = rows => rows.length <= SHOW ? rows : [...rows].map((r, i) => [r, i]).sort((a, b) => ((RANK[a[0][2]] ?? 2) - (RANK[b[0][2]] ?? 2)) || a[1] - b[1]).slice(0, SHOW).sort((a, b) => a[1] - b[1]).map(x => x[0]);
    const val = (v, s) => { v = v == null || v === 'null' || v === '' ? '—' : v; return s && s !== 'none' ? `<span class="chip ${chip[s]}">${esc(v)}</span>` : esc(v); };
    const tick = v => v === 'YES' ? '<i class="tick t-ok">✓</i>' : v === 'NO' ? '<i class="tick t-bad">✕</i>' : '<i class="tick t-none">–</i>';
    const fwChip = { Drift: 'c-warn', Consistent: 'c-ok', 'Single device': 'c-none' };
    const kinds = [...new Set(m.cards.map(c => /firewall/i.test(c.role) ? 'Firewalls' : /switch|wi-fi|wifi|routing/i.test(c.role) ? 'Switching & Wi-Fi' : 'Other'))];
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(x => `<li><span>${esc(x)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <h3>Network devices</h3>
      <div class="quick no-print" id="nwF">${['All', ...kinds, 'With issues'].map((k, i) => `<button type="button" data-k="${k}" aria-pressed="${i === 0}">${k}</button>`).join('')}</div>
      <div class="two" id="nwCards">${m.cards.map(c => `<div class="card nwcard" data-kind="${/firewall/i.test(c.role) ? 'Firewalls' : /switch|wi-fi|wifi|routing/i.test(c.role) ? 'Switching & Wi-Fi' : 'Other'}" data-flag="${c.flag}" style="border-left:4px solid var(--${c.flag === 'crit' ? 'crit' : c.flag === 'warn' ? 'warn' : 'ok'})">
        <div><h3 title="${esc(c.name)}">${toolIcon(c.name)}${esc(c.name)}</h3><p class="sub" style="margin:2px 0 0" title="${esc(`${c.site}${c.role ? ` · ${c.role}` : ''}`)}">${c.systemDetailId ? lgA(LG.system(ctx, c.systemId, c.systemDetailId), esc(c.site), 'Open in Liongard') : esc(c.site)}${c.role ? ` · ${esc(c.role)}` : ''}${c.generic ? ' · from Liongard metrics' : ''}</p></div>
        <dl class="kv">${top(c.rows).map(r => `<dt title="${esc(r[0])}">${esc(r[0])}</dt><dd title="${esc(r[1] ?? '')}">${val(r[1], r[2])}</dd>`).join('')}</dl><button type="button" class="linkbtn nw-more no-print" data-i="${m.cards.indexOf(c)}">${c.rows.length > SHOW ? `Show all ${c.rows.length} details` : 'Show details'} →</button></div>`).join('') || '<p class="sub">No network inspectors for this client.</p>'}</div>
      <h3>Firmware by model</h3>
      <div class="tw"><table><thead><tr><th>Model</th><th>Firmware seen</th><th>Devices</th><th>Status</th></tr></thead><tbody>
        ${m.firmware.map(f => `<tr><td>${esc(f.model)}</td><td class="mono wrap">${f.versions.map(esc).join(' · ')}</td><td class="wrap">${esc(f.devices.join(', '))}</td><td><span class="chip ${fwChip[f.status]}">${f.status}</span></td></tr>`).join('') || '<tr><td colspan="4">No firmware reported.</td></tr>'}
      </tbody></table></div>
      <h3>Network admin accounts</h3>
      <p class="sub">Admins on the firewalls with detailed checks. ${pageA('identity', '', 'Who can administer what')} on the Identity page covers every system.</p>
      <div class="tw"><table><thead><tr><th>Account</th><th>Where</th><th>Access</th><th class="c">MFA</th><th>Note</th></tr></thead><tbody>
        ${m.admins.map(a => `<tr><td>${esc(a.name)}${a.login && a.login !== a.name ? `<div class="sub mono" style="margin:0">${esc(a.login)}</div>` : ''}</td><td>${esc(a.where)}</td><td>${esc(a.access)}</td><td class="c">${tick(a.mfa)}</td><td class="wrap">${esc(a.notes)}</td></tr>`).join('') || '<tr><td colspan="5">No admin data reported.</td></tr>'}
      </tbody></table></div>`;
  },
  after(m, ctx) {
    // "Show all" on a card opens every row in the side drawer, so the cards stay the same size.
    $('nwCards') && $('nwCards').addEventListener('click', e => {
      const b = e.target.closest('.nw-more'); if (!b) return;
      const c = m.cards[+b.dataset.i];
      openDrawer(c.name, `${c.site}${c.role ? ` · ${c.role}` : ''}`, c.rows.map(r => ({ t: r[0], d: r[1] == null || r[1] === '' ? '—' : String(r[1]), sev: r[2] === 'bad' ? 'bad' : r[2] === 'warn' ? 'warn' : r[2] === 'ok' ? 'ok' : '' })), m);
    });
    $('nwF') && $('nwF').addEventListener('click', e => { const b = e.target.closest('[data-k]'); if (!b) return; [...$('nwF').children].forEach(x => x.setAttribute('aria-pressed', x === b));
      document.querySelectorAll('.nwcard').forEach(c => { c.hidden = !(b.dataset.k === 'All' || (b.dataset.k === 'With issues' ? c.dataset.flag !== 'ok' : c.dataset.kind === b.dataset.k)); }); });
  },
  how: m => [
    'POST /api/v2/dataprints/evaluate/…  SonicWall: SystemInfo, HighAvailabilityStatus, GatewayAntivirus.Enable, LicenseStatus',
    'POST /api/v2/dataprints/evaluate/…  Barracuda: SystemInfo, Health, SecuritySubscriptions, Admins · Meraki: LicensingOverview, Users',
    `POST /api/v2/inventory/device-profiles/query  (Environment ${m.environment.ID})  → Model, Firmware, WarrantyExpiration for drift and Meraki MX`,
    `POST /api/v2/inventory/identities/query  (Environment ${m.environment.ID})  → is each network admin in the client’s directory?`,
    'POST /api/v2/metrics/evaluate/systems  → a card for every other network device (any vendor): firmware, licences, HA, offline devices, findings and renewals',
    'Rules: src/main/panels/network.js',
  ].join('\n'),
};
