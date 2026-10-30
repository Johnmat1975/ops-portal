// Lifecycle & renewals view: timeline for the next 12 months plus a filterable table.
window.VIEWS.lifecycle = {
  title: 'Lifecycle & renewals',
  kpiItems: Object.fromEntries(['Expired', 'Next 90 days', 'Next 12 months', 'Later'].map(b => [b, (m, c) => m.rows.filter(r => r.bucket === b).map(r => ({ t: `${fmtDate(r.date, true)}: ${r.what}`, d: `${r.type} · ${r.asset} · ${r.source}`, url: r.ref && LG.system(c, r.ref.systemId, r.ref.systemDetailId), sev: b === 'Expired' ? 'bad' : b === 'Next 90 days' ? 'warn' : '' }))])),
  intro: 'Warranties, OS support dates, security subscriptions, licences, certificates and domains on one timeline, from every tool the client runs. This is the refresh and renewal pipeline for the client.',
  exports: [{ label: 'PDF: renewal forecast (next 12 months)', mode: 'review', title: 'Renewal forecast', kicker: 'Next 12 months' }],
  render(m) {
    const next = m.rows.filter(r => r.days >= -30 && r.days <= 365);
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(x => `<li><span>${esc(x)}</span></li>`).join('')}</ul></div>
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <div class="review-only"><p>Everything that renews or reaches end of support for ${esc(m.environment.Name)} in the next 12 months (and anything that lapsed in the last 30 days). Tick <b>Quote</b> for anything you’d like us to price.</p>
        <table class="review"><thead><tr><th>Date</th><th>Type</th><th>What</th><th>Asset</th><th>Quote</th></tr></thead><tbody>${next.map(r => `<tr><td>${fmtDate(r.date, true)}</td><td>${esc(r.type)}</td><td>${esc(r.what)}</td><td>${esc(r.asset)}</td><td class="box">☐</td></tr>`).join('') || '<tr><td colspan="5">Nothing renews in the next 12 months.</td></tr>'}</tbody></table>
        <div class="signoff"><div>Reviewed by: ____________________________</div><div>Date: ______________</div><div></div></div></div>
      <div class="card"><h3>Next 12 months</h3><div class="lane-wrap"><svg id="lcChart" role="group" aria-label="Renewals over the next 12 months"></svg></div></div>
      <div class="filters"><div class="quick" id="lcFilter">${m.types.map((t, i) => `<button type="button" data-lct="${esc(t)}" aria-pressed="${i === 0}">${esc(t)}</button>`).join('')}</div>
        <div class="search" style="flex:1;min-width:200px;margin:0"><input id="lcQ" placeholder="Search what, asset or source" autocomplete="off" aria-label="Search renewals"></div>
        <button type="button" class="btn ghost sm no-print" id="lcIcs" title="Download the next 12 months as a calendar file for Outlook or Google Calendar">Calendar (.ics)</button></div>
      <div class="tw"><table id="lcTable"></table></div>`;
  },
  after(m, ctx) {
    const chip = { 'Expired': 'c-crit', 'Next 90 days': 'c-warn', 'Next 12 months': 'c-gold', 'Later': 'c-none' };
    let type = 'All', q = '', shown = [];
    // One renewal as a drawer item: what it is, where it is, when, and a link to it in Liongard (or Lookup for a device).
    const item = r => ({ t: `${fmtDate(r.date, true)}: ${r.what}`, d: [r.type, r.asset, r.source, r.days < 0 ? agoText(Math.abs(r.days)) : `in ${r.days} days`, r.note].filter(Boolean).join(' · '),
      url: r.ref && LG.system(ctx, r.ref.systemId, r.ref.systemDetailId), page: !r.ref && !/,/.test(r.asset) && !/^Device|Microsoft/.test(r.source) ? 'lookup' : null, q: r.asset,
      sev: r.bucket === 'Expired' ? 'bad' : r.bucket === 'Next 90 days' ? 'warn' : '' });
    // A dot opens the drawer with that renewal first, then anything else within 3 days (dots that close together overlap).
    const openDot = i => {
      const r = shown[i]; if (!r) return;
      const t = Date.parse(r.date + 'T00:00:00Z');
      const near = shown.filter(x => x !== r && Math.abs(Date.parse(x.date + 'T00:00:00Z') - t) <= 3 * 864e5).sort((a, b) => a.date.localeCompare(b.date));
      openDrawer(r.asset || r.what, [`${r.type} · ${fmtDate(r.date, true)}`, near.length ? `and ${near.length} more within 3 days` : ''].filter(Boolean).join(' · '), [r, ...near].map(item), m);
    };
    $('lcChart').addEventListener('click', e => { const c = e.target.closest('[data-i]'); if (c) openDot(+c.dataset.i); });
    $('lcChart').addEventListener('keydown', e => { const c = e.target.closest('[data-i]'); if (c && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openDot(+c.dataset.i); } });
    const draw = () => {
      const rows = m.rows.filter(r => (type === 'All' || r.type === type) && (!q || [r.what, r.asset, r.source, r.note].join(' ').toLowerCase().includes(q)));
      $('lcTable').innerHTML = `<thead><tr><th>Date</th><th>When</th><th>Type</th><th>What</th><th>Asset</th><th>Source</th></tr></thead><tbody>` +
        rows.map(r => `<tr><td class="num">${fmtDate(r.date, true)}</td><td><span class="chip ${chip[r.bucket]}">${r.days < 0 ? `${agoText(Math.abs(r.days))}` : `${r.days} days`}</span></td><td>${esc(r.type)}</td><td class="wrap"><b>${esc(r.what)}</b>${r.note ? `<div class="sub" style="margin:2px 0 0">${esc(r.note)}</div>` : ''}</td><td class="wrap" data-csv="${esc(r.asset)}">${r.ref ? lgA(LG.system(ctx, r.ref.systemId, r.ref.systemDetailId), esc(r.asset), 'Open in Liongard') : /,/.test(r.asset) || /^Device|Microsoft/.test(r.source) ? esc(r.asset) : pageA('lookup', r.asset, esc(r.asset), 'Everything about this asset (Lookup)')}</td><td class="sub">${toolIcon(r.source)}${esc(r.source)}</td></tr>`).join('') + '</tbody>';
      const now = new Date(m.pulledOn || Date.now()).getTime();
      // Drawn at its real width, so the text doesn't scale up on wide screens.
      const W = Math.max(1000, Math.round((($('lcChart') || {}).parentElement || {}).clientWidth || 1000)), L = 20, R = 20, H = 120, start = now - 60 * 864e5, end = now + 365 * 864e5, x = t => L + (t - start) / (end - start) * (W - L - R);
      let g = `<rect x="${L}" y="40" width="${x(now) - L}" height="40" fill="var(--crit)" fill-opacity=".08"/>`;
      const d0 = new Date(start); for (let k = 0; k < 15; k++) { const t = Date.UTC(d0.getUTCFullYear(), d0.getUTCMonth() + k, 1); if (t < start || t > end) continue; const xx = x(t); g += `<line x1="${xx}" x2="${xx}" y1="34" y2="86" stroke="var(--line)"/><text x="${xx + 3}" y="100" font-size="11.5" fill="var(--muted)" font-family="IBM Plex Sans, Arial">${new Date(t).toLocaleDateString('en-GB', { month: 'short', timeZone: 'UTC' })}</text>`; }
      g += `<line x1="${x(now)}" x2="${x(now)}" y1="22" y2="90" stroke="var(--ink)" stroke-width="1.5"/><text x="${x(now)}" y="16" font-size="12" font-weight="600" fill="var(--ink)" text-anchor="middle" font-family="IBM Plex Sans, Arial">Today</text>`;
      shown = rows;
      rows.forEach((r, i) => { const t = Date.parse(r.date + 'T00:00:00Z'); if (t < start || t > end) return; const col = r.bucket === 'Expired' ? 'var(--crit)' : r.bucket === 'Next 90 days' ? 'var(--warn)' : 'var(--gold)';
        const label = `${fmtDate(r.date, true)} · ${r.type}: ${r.what} · ${r.asset}`;
        g += `<circle class="lc-dot" data-i="${i}" tabindex="0" role="button" aria-label="${esc(label)}" cx="${x(t).toFixed(1)}" cy="${60 + ((i % 3) - 1) * 11}" r="7" fill="${col}" stroke="var(--surface)" stroke-width="1.5"><title>${esc(label)} (click for details)</title></circle>`; });
      const svg = $('lcChart'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.innerHTML = g;
    };
    draw();
    $('lcQ').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); draw(); });
    $('lcIcs').addEventListener('click', async () => {
      const ics = s => String(s || '').replace(/[\\,;]/g, c => '\\' + c).replace(/[\r\n]+/g, ' ');   // a stray CR or LF would start a new calendar property
      const ev = m.rows.filter(r => r.days >= 0 && r.days <= 365).map((r, i) => ['BEGIN:VEVENT', `UID:lg-ops-${m.environment.ID}-${r.date}-${i}@liongard-ops-portal`, `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`,
        `DTSTART;VALUE=DATE:${r.date.replace(/-/g, '')}`, `SUMMARY:${ics(`${m.environment.Name}: ${r.type} \u2013 ${r.what}`)}`, `DESCRIPTION:${ics(`${r.asset}. Source: ${r.source}${r.note ? `. ${r.note}` : ''}`)}`,
        'BEGIN:VALARM', 'TRIGGER:-P30D', 'ACTION:DISPLAY', 'DESCRIPTION:Renewal in 30 days', 'END:VALARM', 'END:VEVENT'].join('\r\n'));
      const content = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Liongard Ops Portal//EN', ...ev, 'END:VCALENDAR'].join('\r\n');
      const saved = await window.portal.exportFile({ name: `${m.environment.Name}-renewals`.replace(/[^\w-]+/g, '-'), ext: 'ics', label: 'Calendar', content });
      if (saved) $('statusLine').textContent = `Saved ${saved}`;
    });
    $('lcFilter').addEventListener('click', e => { const b = e.target.closest('[data-lct]'); if (!b) return; type = b.dataset.lct; [...$('lcFilter').children].forEach(x => x.setAttribute('aria-pressed', x === b)); draw(); });
  },
  how: m => [
    `POST /api/v2/inventory/device-profiles/query  (Environment ${m.environment.ID})  → WarrantyExpiration, EOLDate, LicenseExpiration, OperatingSystem`,
    'POST /api/v2/dataprints/evaluate/…  SonicWall LicenseStatus · Barracuda SecuritySubscriptions · Meraki LicensingOverview · KnowBe4 AccountInfo',
    'POST /api/v2/dataprints/evaluate/…  Internet Domain/DNS (registration expiry) · TLS/SSL (certificate expiry)',
    'Windows support dates: Microsoft lifecycle (src/main/catalog.js). Rules: src/main/panels/lifecycle.js',
  ].join('\n'),
};
