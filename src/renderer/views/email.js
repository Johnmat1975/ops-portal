// Email & domain security view: in short, the client's mail protection, every domain in one table (detail on demand),
// the records to publish grouped by DNS host, certificates, and a printable DNS change request.
window.VIEWS.email = {
  title: 'Email & domain security',
  kpiItems: {
    'Domains': (m, c) => m.domains.map(d => ({ t: d.name, d: `${d.sends ? `Sends email (${d.mailVendor || 'host not identified'})` : 'Doesn’t send email'} · grade ${d.grade}`, url: d.sys && LG.system(c, d.sys.systemId, d.sys.systemDetailId), sev: d.spoofable ? 'bad' : 'ok' })),
    'Can be spoofed': (m, c) => m.domains.filter(d => d.spoofable).map(d => ({ t: d.name, d: `${d.sends ? 'Sends email' : 'Doesn’t send'} · DMARC: ${d.dmarc[2]} · SPF: ${d.spf[2]}`, url: d.sys && LG.system(c, d.sys.systemId, d.sys.systemDetailId), sev: d.sends ? 'bad' : 'warn' })),
    'DMARC enforced': (m, c) => m.domains.filter(d => d.sends).map(d => ({ t: d.name, d: d.dmarc[2], url: d.sys && LG.system(c, d.sys.systemId, d.sys.systemDetailId), sev: d.dmarc[0] === 'pass' ? 'ok' : d.dmarc[0] }))
      .map(x => ({ ...x, sev: x.sev === 'fail' ? 'bad' : x.sev })),
    'Certificates due': (m, c) => m.certs.filter(t => t.state === 'fail' || (t.days != null && t.days <= 30)).map(t => ({ t: t.site, d: !t.exists ? 'No certificate' : `Expires ${fmtDate(t.expires, true)} (${t.days} days) · ${t.issuer}`, url: t.sys && LG.system(c, t.sys.systemId, t.sys.systemDetailId), sev: t.days < 0 || !t.exists ? 'bad' : 'warn' })),
    'Registration & lock': (m, c) => m.domains.filter(d => (d.regDays != null && d.regDays <= 60) || d.locked === 'no').map(d => ({ t: d.name, d: [d.regDays != null && d.regDays <= 60 && `Renews ${fmtDate(d.regExpires, true)} (${d.regDays} days)`, d.locked === 'no' && 'No registrar transfer lock', d.registrar && `Registrar: ${d.registrar}`].filter(Boolean).join(' · '), url: d.sys && LG.system(c, d.sys.systemId, d.sys.systemDetailId), sev: 'warn' })),
  },
  intro: 'SPF, DKIM and DMARC for every domain the client owns, with registrar lock, DNSSEC, mail filtering and certificates. A domain that sends email without an enforced DMARC policy can be spoofed in a business email compromise attack, and it’s one of the cheapest fixes an MSP can sell.',
  exports: [{ label: 'PDF: DNS change request (records to publish)', mode: 'review', title: 'DNS change request', kicker: 'For your DNS provider' }],
  render(m, ctx) {
    // Domains and certificates whose data couldn't be read are listed, not scored, so they never show as spoofable.
    const unread = (m.unread || []).length ? `<div class="card flag warn"><p style="margin:0"><b>Couldn’t read ${m.unread.length} from Liongard:</b> ${m.unread.map(u => `${esc(u.kind)} ${lgA(LG.system(ctx, u.sys && u.sys.systemId, u.sys && u.sys.systemDetailId), esc(u.name || 'unnamed'))}`).join(', ')}. They aren’t scored on this page; refresh to try again.</p></div>` : '';
    if (!m.domains.length) return unread + '<div class="card"><h3>No domains inspected</h3><p class="sub">This client has no Internet Domain/DNS launchpoints with data. Add the client’s domains in Liongard to see them here.</p></div>';
    const tool = t => `<span class="prod">${toolIcon(t.inspector || t.name)}${lgA(LG.system(ctx, t.systemId, t.systemDetailId), esc(t.name))}${t.health === 'Failing' || t.health === 'Stale' ? ' <span class="chip c-warn">not reporting</span>' : ''}</span>`;
    const tiles = m.mailTools.map(t => { const ok = t.tools.length || (t.seen || []).length; return `<div class="pt" style="--sev:${ok ? 'var(--ok)' : 'var(--line)'};--sev-text:${ok ? 'var(--sev-ok-ink)' : 'var(--sev-none-ink)'}"><div style="padding:10px 12px"><div class="pt-t">${esc(t.k)}</div>
      <div style="font-size:13px">${t.tools.map(tool).join(', ') || ''}${(t.seen || []).filter(x => !t.tools.some(y => y.name === x)).length ? `${t.tools.length ? '<br>' : ''}<span class="sub" style="margin:0">From DNS: ${esc(t.seen.filter(x => !t.tools.some(y => y.name === x)).join(', '))}</span>` : ''}${!ok ? '<span class="sub" style="margin:0">Not monitored in Liongard</span>' : ''}</div></div></div>`; }).join('');
    const fwd = m.fwd.length ? `<div class="card flag"><h3>External mail forwarding</h3><ul class="plain">${m.fwd.map(f => `<li><span><b>${esc(f.value)}</b> rule${+f.value === 1 ? '' : 's'} in ${lgA(LG.system(ctx, f.systemId, f.systemDetailId), esc(f.system))}${(f.list || []).length ? `<div class="sub" style="margin:2px 0 0">${(f.list || []).slice(0, 6).map(x => esc(typeof x === 'string' ? x : Array.isArray(x) ? x.join(' · ') : JSON.stringify(x))).join('<br>')}</div>` : ''}</span></li>`).join('')}</ul>
      <p class="sub">Mail forwarded outside the organisation is a common sign of a compromised mailbox. ${pageA('identity', '', 'Check the people on the Identity page →')}</p></div>` : '';
    const byHost = [...new Set(m.fixPack.map(r => r.dnsHost))];
    const pack = m.fixPack.length ? byHost.map(h => `<h4 class="mini" style="margin-top:10px">${esc(h)}</h4><div class="tw"><table><thead><tr><th>Domain</th><th>Name</th><th>Type</th><th>Value</th><th></th></tr></thead><tbody>${m.fixPack.filter(r => r.dnsHost === h).map(r => `<tr><td class="mono">${esc(r.domain)}</td><td class="mono wrap">${esc(r.host)}</td><td class="mono">${esc(r.type)}</td><td class="mono wrap">${esc(r.value)}</td><td class="no-print"><button type="button" class="linkbtn" data-copy="${esc(r.value)}">Copy</button></td></tr>`).join('')}</tbody></table></div>`).join('') : '<p class="sub">No DNS records to publish.</p>';
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain">${(m.summary || []).map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ul></div>
      ${unread}<div class="kpis">${kpiStrip(m.kpis)}</div>
      <h3>Mail protection</h3>
      <div class="ptgrid">${tiles}</div>
      ${fwd}
      <h3 style="margin-top:22px">Domains</h3>
      <div class="filters">
        <div class="quick" id="emF">${[['all', 'All'], ['spoof', 'Can be spoofed'], ['send', 'Sending'], ['idle', 'Not sending'], ['due', 'Expiring or unlocked'], ['low', 'Grade C or worse']].map(([k, l], i) => `<button type="button" data-f="${k}" aria-pressed="${i === 0}">${l}</button>`).join('')}</div>
        <div class="search" style="flex:1;min-width:200px;margin:0"><input id="emQ" placeholder="Search domain, mail host, registrar or DNS host" autocomplete="off" aria-label="Search domains"></div>
      </div>
      <p class="sub" id="emCount"></p>
      <div class="tw tech"><table id="emTable"></table></div>
      <p class="sub tech">Click a domain’s row for its records and what to fix. Grades judge sending domains mostly on DMARC enforcement, then SPF and DKIM; domains that don’t send are judged on being locked down (SPF -all and DMARC reject). Certificates, DNSSEC, registrar lock and renewal adjust the grade.</p>
      <h3 style="margin-top:22px">Records to publish</h3>
      <p class="sub">Every DNS record the domains above need, grouped by who hosts the DNS. <button type="button" class="btn ghost sm no-print" id="copyAll">Copy all as text</button></p>
      ${pack}
      <h3 style="margin-top:22px">Certificates</h3>
      ${m.certs.length ? `<div class="tw"><table><thead><tr><th>Site</th><th>Issuer</th><th>Expires</th><th>Notes</th></tr></thead><tbody>${m.certs.map(c => `<tr><td class="mono">${lgA(LG.system(ctx, c.sys && c.sys.systemId, c.sys && c.sys.systemDetailId), esc(c.site))}${c.cn && c.cn !== c.site ? `<div class="sub" style="margin:0">${esc(c.cn)}</div>` : ''}</td><td>${esc(c.issuer || '—')}</td><td data-csv="${esc(c.expires || '')}">${!c.exists ? '<span class="chip c-crit">No certificate</span>' : c.expires ? `${fmtDate(c.expires, true)} <span class="chip ${c.days < 0 ? 'c-crit' : c.days <= 30 ? 'c-warn' : 'c-none'}">${c.days < 0 ? `${-c.days} days ago` : `${c.days} days`}</span>` : '—'}</td><td class="wrap">${[c.oldTls.length && `${c.oldTls.join(' and ')} still enabled`, c.match === false && 'Name doesn’t match the site'].filter(Boolean).join('. ')}</td></tr>`).join('')}</tbody></table></div>` : '<p class="sub">No TLS/SSL inspectors for this client.</p>'}
      <div class="review-only">
        <p>Please publish the DNS records below${byHost.length === 1 ? ` at ${esc(byHost[0])}` : ', grouped by DNS host'}. They protect ${esc(m.environment.Name)}’s domains from being used to send spoofed email. Add each record exactly as shown, then let us know so we can confirm it in Liongard.</p>
        ${byHost.map(h => `<h4>${esc(h)}</h4><table class="review"><thead><tr><th>Domain</th><th>Name</th><th>Type</th><th>Value</th><th>Done</th></tr></thead><tbody>${m.fixPack.filter(r => r.dnsHost === h).map(r => `<tr><td>${esc(r.domain)}</td><td class="mono">${esc(r.host)}</td><td>${esc(r.type)}</td><td class="mono">${esc(r.value)}</td><td class="box">☐</td></tr>`).join('')}</tbody></table>`).join('') || '<p>No records need publishing.</p>'}
        <div class="signoff"><div>Published by: ____________________________</div><div>Date: ______________</div><div>Ticket: ______________</div></div>
      </div>`;
  },
  after(m, ctx) {
    if (!m.domains.length) return;
    const st = { pass: '<i class="tick t-ok" title="OK">✓</i>', warn: '<i class="tick t-warn" title="Review">!</i>', fail: '<i class="tick t-bad" title="Problem">✕</i>', none: '<i class="tick t-none" title="Not applicable">–</i>' };
    const gChip = g => g === 'A' ? 'c-ok' : g === 'B' ? 'c-warn' : 'c-crit';
    const block = (title, s, code, extra) => `<div class="src"><h4>${title}</h4><div style="display:flex;gap:8px;align-items:center">${st[s[0]]}<span>${esc(s[2] || s[1])}</span></div>${code ? `<code class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(s[1])}</code>` : (s[2] ? `<span class="sub" style="margin:0">${esc(s[1])}</span>` : '')}${extra || ''}</div>`;
    const detail = d => `<div class="profile">${block('SPF', d.spf, true, d.spfIssues.length > 1 ? `<ul class="sub" style="margin:4px 0 0;padding-left:16px">${d.spfIssues.slice(1).map(i => `<li>${esc(i)}</li>`).join('')}</ul>` : '')}${block('DKIM', d.dkim)}${block('DMARC', d.dmarc, true, d.dmarcIssues.length > 1 ? `<ul class="sub" style="margin:4px 0 0;padding-left:16px">${d.dmarcIssues.slice(1).map(i => `<li>${esc(i)}</li>`).join('')}</ul>` : '')}${block('Certificate', d.cert)}</div>
      <p class="sub" style="margin:6px 0">MX: ${esc(d.nullMx ? 'null MX (accepts no mail)' : d.mx.join(', ') || 'none')}${d.mxVendors.length ? ` (${esc(d.mxVendors.map(v => v.name).join(', '))})` : ''} · DNS: ${esc(d.dnsHost || d.ns || '—')}${d.webHost ? ` · Website: ${esc(d.webHost)}` : ''} · Registrar: ${esc(d.registrar || '—')}${d.regExpires ? `, renews ${fmtDate(d.regExpires, true)}` : ''} · Transfer lock: ${d.locked === 'no' ? 'off' : d.locked ? 'on' : 'unknown'} · DNSSEC: ${d.dnssec === 'pass' ? 'on' : 'off'}${d.subs ? ` · ${d.subs} subdomains seen` : ''}</p>
      ${d.fix.length ? `<h4 class="mini">What to fix</h4><ul style="margin:0;padding-left:18px;font-size:14px">${d.fix.map(f => `<li>${esc(f)}</li>`).join('')}</ul>` : '<p class="sub">Nothing to fix.</p>'}`;
    let f = 'all', q = '';
    const match = d => (f === 'all' || (f === 'spoof' && d.spoofable) || (f === 'send' && d.sends) || (f === 'idle' && !d.sends) || (f === 'due' && ((d.regDays != null && d.regDays <= 60) || d.locked === 'no' || d.cert[0] === 'fail' || /\(\d+ days\)/.test(d.cert[1]))) || (f === 'low' && /[CDF]/.test(d.grade)))
      && (!q || [d.name, d.mailVendor, d.registrar, d.dnsHost, d.ns].join(' ').toLowerCase().includes(q));
    const draw = () => {
      const rows = m.domains.filter(match);
      $('emCount').textContent = `${rows.length} domain${rows.length === 1 ? '' : 's'}`;
      $('emTable').innerHTML = `<thead><tr><th>Domain</th><th>Sends email</th><th class="c">SPF</th><th class="c">DKIM</th><th class="c">DMARC</th><th class="c">DNSSEC</th><th class="c">Lock</th><th class="c">Certificate</th><th>Registration</th><th class="c">Grade</th></tr></thead><tbody>` +
        rows.map((d, i) => `<tr class="clickrow" data-i="${m.domains.indexOf(d)}"><td class="mono" data-csv="${esc(d.name)}">${lgA(LG.system(ctx, d.sys && d.sys.systemId, d.sys && d.sys.systemDetailId), esc(d.name), 'Open this domain in Liongard')} <button type="button" class="linkbtn em-more no-print" aria-expanded="false" aria-controls="emd${m.domains.indexOf(d)}">Details<span class="sr-only"> for ${esc(d.name)}</span></button>${d.spoofable ? ' <span class="chip c-crit">Spoofable</span>' : ''}${d.parked ? ' <span class="chip c-none">Parked</span>' : ''}</td>
          <td data-csv="${d.sends ? `Yes ${esc(d.mailVendor)}` : 'No'}">${d.sends ? `<span class="chip c-gold">Yes</span> <span class="sub">${esc(d.mailVendor)}${d.mxVendors.some(v => v.kind === 'gateway') ? ` via ${esc(d.mxVendors.filter(v => v.kind === 'gateway').map(v => v.name).join(', '))}` : ''}</span>` : 'No'}</td>
          <td class="c" data-csv="${esc(d.spf[2])}">${st[d.spf[0]]}${d.lookups != null && d.sends ? `<div class="sub mono" style="margin:0">${d.lookups}/10</div>` : ''}</td><td class="c" data-csv="${esc(d.dkim[2])}">${st[d.dkim[0]]}</td>
          <td class="c" data-csv="${esc(d.dmarc[2])}">${st[d.dmarc[0]]}${d.policy ? `<div class="sub mono" style="margin:0">${esc(d.policy)}${d.pct < 100 ? ` ${d.pct}%` : ''}</div>` : ''}</td><td class="c">${st[d.dnssec]}</td><td class="c">${st[d.lock]}</td><td class="c" data-csv="${esc(d.cert[1])}">${st[d.cert[0]]}</td>
          <td data-csv="${esc(d.regExpires || '')}">${d.regExpires ? `${fmtDate(d.regExpires, true)}${d.regDays != null && d.regDays <= 60 ? ` <span class="chip ${d.regDays < 0 ? 'c-crit' : 'c-warn'}">${d.regDays} days</span>` : ''}` : '—'}</td>
          <td class="c"><span class="chip ${gChip(d.grade)}" style="font-size:13px">${d.grade}</span></td></tr>
          <tr class="detail" id="emd${m.domains.indexOf(d)}" hidden><td colspan="10"></td></tr>`).join('') + '</tbody>';
    };
    $('emTable').addEventListener('click', e => {
      if (e.target.closest('a')) return;
      const r = e.target.closest('tr.clickrow'); if (!r) return;
      const det = $(`emd${r.dataset.i}`); det.hidden = !det.hidden;
      const btn = r.querySelector('.em-more'); if (btn) btn.setAttribute('aria-expanded', String(!det.hidden));   // keyboard users open it with this button
      if (!det.hidden && !det.firstElementChild.innerHTML) det.firstElementChild.innerHTML = detail(m.domains[+r.dataset.i]);   // built on demand, so 100s of domains stay fast
    });
    $('emF').addEventListener('click', e => { const b = e.target.closest('[data-f]'); if (!b) return; [...$('emF').children].forEach(x => x.setAttribute('aria-pressed', x === b)); f = b.dataset.f; draw(); });
    $('emQ').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); draw(); });
    draw();
    // Full reports print every domain's detail (built up front only for a normal-sized client).
    if (m.domains.length <= 60) document.querySelectorAll('tr.detail').forEach(r => { const i = +r.id.slice(3); if (!r.firstElementChild.innerHTML) r.firstElementChild.innerHTML = detail(m.domains[i]); });
    $('panelBody').onclick = e => {   // one handler per page load (not one more per refresh)
      const b = e.target.closest('[data-copy]'); if (!b) return;
      navigator.clipboard.writeText(b.dataset.copy).then(() => { b.textContent = 'Copied'; setTimeout(() => (b.textContent = 'Copy'), 1500); });
    };
    $('copyAll').addEventListener('click', () => {
      const text = m.fixPack.map(r => `${r.domain}\t${r.host}\t${r.type}\t${r.value}`).join('\n');
      navigator.clipboard.writeText(text).then(() => { $('copyAll').textContent = 'Copied'; setTimeout(() => ($('copyAll').textContent = 'Copy all as text'), 1500); });
    });
  },
  how: m => [
    `GET  /api/v1/launchpoints + /api/v1/timeline (env ${m.environment.ID})  → Internet Domain/DNS and TLS/SSL systems and their latest dataprints`,
    'POST /api/v2/dataprints/evaluate/…  Internet Domain/DNS: SPF/DMARC records, EmailSecurity checks (SPF lookup and void counts, duplicate records, DKIM key, DMARC syntax), SpoofIntel, MX, DNSSEC, registrar, domain status (transfer lock), name servers',
    'POST /api/v2/dataprints/evaluate/…  TLS/SSL: expiry, issuer, protocols, name match',
    'POST /api/v2/metrics/evaluate/systems  → mail host, email filtering, DNS filtering and training tools, and external forwarding rules',
    'Rules: src/main/panels/email.js. Null DKIM keys (v=DKIM1; p=) on a domain that doesn’t send count as correct.',
  ].join('\n'),
};
