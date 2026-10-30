// Licence reconciliation view: seats bought against seats used, who's missing a seat, stale seats, what it costs, and a
// true-up list for the client to approve. Columns only appear for products this client actually has.
window.VIEWS.licences = {
  title: 'Licence reconciliation',
  kpiItems: {
    'Spare paid M365 seats': m => m.subs.filter(s => s.source === 'Microsoft 365' && s.buy != null && s.buy > s.use && !/\bfree\b|trial/i.test(s.product)).map(s => ({ t: s.product, d: `${s.buy - s.use} spare of ${s.buy} purchased · ${s.note}`, sev: 'warn' })),
    'People missing a seat': m => m.people.filter(p => !p.orphan && (p.cells.teams === 'bad' || p.cells.kb4 === 'bad')).map(p => ({ t: p.name, d: p.action, page: 'identity', q: p.upn, sev: 'bad' })),
    'Seats with no owner': m => m.people.filter(p => p.orphan).map(p => ({ t: p.name, d: p.action, sev: 'bad' })).concat(m.devices.filter(d => d.mobile && d.note).map(d => ({ t: d.name, d: d.note, sev: 'warn' }))),
    'Devices outside RMM and EDR': m => m.devices.filter(d => !d.mobile && d.cells.ninja.k === 'bad' && d.cells.cs.k === 'bad').map(d => ({ t: d.name, d: d.note, page: 'lookup', q: d.name, sev: 'warn' })),
    'Devices not managed': (m, c) => (m.unmanaged || []).map(d => ({ t: d.name, d: `${d.os || '—'} · seen by ${(d.seenBy || []).join(', ') || 'discovery'}`, url: LG.device(c, d.id), page: 'coverage', q: d.name, sev: 'warn' })),
    'Dormant M365 licences': m => m.dormant.filter(r => r.m365 && (!['active', 'unknown'].includes(r.m365.band) || r.disabled)).map(r => ({ t: r.name, d: r.reason, page: 'identity', q: r.name, sev: 'bad' })),
    'KnowBe4 seats never used': m => m.dormant.filter(r => r.kb4 && r.kb4.band === 'never').map(r => ({ t: r.name, d: r.reason, sev: 'warn' })),
    'Stale Duo seats': m => m.dormant.filter(r => r.duo && (r.duo.band !== 'active' || r.orphan)).map(r => ({ t: r.name, d: r.reason, sev: 'warn' })),
    'Anthropic seats with no key': m => m.dormant.filter(r => r.anthKeys === 0).map(r => ({ t: r.name, d: 'Member with no API key', sev: 'warn' })),
  },
  intro: 'What the client pays for, matched against the people and devices Liongard can see: spare seats, missing seats, seats with nobody behind them, and licensed users who have gone quiet.',
  exports: [{ label: 'PDF: licence true-up (for client approval)', mode: 'review', title: 'Licence true-up', kicker: 'For client approval' }],
  render(m, ctx) {
    const T = { ok: '<i class="tick t-ok">✓</i>', bad: '<i class="tick t-bad">✕</i>', warn: '<i class="tick t-warn">!</i>', none: '<i class="tick t-none">–</i>' };
    const CHIP = { ok: '<span class="chip c-ok">Balanced</span>', warn: '<span class="chip c-warn">Review</span>', bad: '<span class="chip c-crit">Act</span>', none: '<span class="chip c-none">No action</span>' };
    const cell = (k, note, tools) => `<td class="c" data-csv="${esc(k || 'none')}${note ? ` (${esc(note)})` : ''}">${T[k] || T.none}${note ? `<div class="sub" style="margin-top:4px;white-space:normal;min-width:110px">${tools ? tools.map(toolIcon).join('') : ''}${esc(note)}</div>` : ''}</td>`;   // tools: show each tool's icon
    const act = (a, extra) => {
      if (a === null || a === undefined) return '<td class="c"><span class="sub">–</span></td>';
      if (a.archived) return '<td class="c"><span class="chip c-none">Archived</span></td>';
      if (a.band === 'unknown') return '<td class="c" data-csv="Not available"><span class="chip c-none" title="Liongard has no sign-in dates for this tenant">Not available</span></td>';
      if (!a.d) return `<td class="c" data-csv="Never"><span class="chip c-crit">Never</span>${extra ? `<div class="sub" style="margin-top:4px">${esc(extra)}</div>` : ''}</td>`;
      const c = a.band === 'dormant' ? 'c-crit' : a.band === 'stale' ? 'c-warn' : 'c-ok';
      return `<td class="c" data-csv="${esc(a.d)}"><span class="chip ${c}">${fmtDate(a.d)}</span><div class="sub" style="margin-top:4px">${a.n} day${a.n === 1 ? '' : 's'}${extra ? ` · ${esc(extra)}` : ''}</div></td>`;
    };
    const keys = n => n === null || n === undefined ? '<td class="c"><span class="sub">–</span></td>' : n === 0 ? '<td class="c"><span class="chip c-warn">No API key</span></td>' : `<td class="c"><span class="chip c-ok">${n} key${n > 1 ? 's' : ''}</span></td>`;
    const src = s => { const x = m.systems[s]; return x ? lgA(LG.system(ctx, x.systemId, x.systemDetailId), esc(s), `Open ${s} in Liongard`) : esc(s); };
    const { ACTIVE_DAYS, DORMANT_DAYS, DEVICE_STALE_DAYS } = m.thresholds;
    // Only the product columns this client has data for.
    const PCOLS = [['ad', 'Active<br>Directory'], ['e5', 'M365<br>E5'], ['teams', 'Teams<br>Enterprise'], ['kb4', 'KnowBe4'], ['duo', 'Duo'], ['anth', 'Anthropic']].filter(([k]) => m.people.some(p => p.cells[k] && p.cells[k] !== 'none'));
    const DCOLS = (m.deviceSource === 'coverage' ? [['rmm', 'RMM'], ['edr', 'EDR / AV'], ['backup', 'Backup'], ['tl', 'App control<br>ThreatLocker']] : [['ninja', 'RMM<br>NinjaOne'], ['cs', 'EDR<br>CrowdStrike'], ['tl', 'App control<br>ThreatLocker']]).filter(([k]) => m.devices.some(d => d.cells[k] && d.cells[k].k !== 'none'));
    const ACOLS = [['m365', 'Microsoft 365<br>sign-in'], ['ad', 'Active Directory<br>logon'], ['duo', 'Duo<br>login'], ['kb4', 'KnowBe4<br>activity'], ['anthKeys', 'Anthropic<br>API keys']].filter(([k]) => m.dormant.some(r => r[k] != null));
    const who = p => `<b>${pageA('identity', p.upn || p.name, esc(p.name), 'Open on the Identity page')}</b> ${pageA('lookup', p.upn || p.name, '↗', 'Everything about this person (Lookup)')}`;
    const stale = m.dormant.filter(r => r.verdict !== 'ok');
    const spare = m.subs.filter(s => s.buy != null && s.buy - s.use > 0 && !/\bfree\b|trial/i.test(s.product));
    const pp = (m.perPerson && m.perPerson.people) || [];
    return `
      <div class="card summary"><h3>In short</h3><ul class="plain" id="licSummary"></ul></div>
      ${m.missing.length ? `<p class="sub">Not available for this client: ${esc(m.missing.join(', '))}. Licence data from the client’s other tools is listed at the bottom of the page.</p>` : ''}
      <div class="kpis">${kpiStrip(m.kpis)}</div>
      <h3>Subscriptions</h3>
      <p class="sub no-print msp">Add what each seat costs (per month) to see what the spare and stale seats are costing the client. Prices are saved on this computer only.</p>
      <div class="tw"><table id="subTable"><thead><tr><th>Product</th><th>Source</th><th class="c">Purchased</th><th class="c">In use</th><th class="c">Spare</th><th class="c no-print msp">Price / seat / month${mspCurrency() ? ` (${esc(mspCurrency())})` : ''}</th><th class="c">Spare cost / month</th><th>Status</th><th>Why</th></tr></thead><tbody>
        ${m.subs.map((s, i) => `<tr><td><b>${esc(s.product)}</b></td><td>${src(s.source)}</td><td class="c mono">${s.buy != null ? esc(s.buy) : '<span class="sub">Not reported</span>'}</td><td class="c mono">${esc(s.use)}</td><td class="c mono">${s.buy == null ? '–' : s.buy - s.use}</td>
          <td class="c no-print msp"><input class="price" data-i="${i}" inputmode="decimal" aria-label="Price per seat for ${esc(s.product)}" placeholder="Price / seat"></td><td class="c mono" id="cost${i}">–</td><td>${CHIP[s.sev]}</td><td class="wrap">${esc(s.note)}</td></tr>`).join('')}
      </tbody></table></div>
      <div class="two">
        <div class="card flag warn"><h3>What to do</h3><ul class="plain">${m.actions.map(x => `<li><i class="tick t-${x.sev === 'bad' ? 'bad' : 'warn'}" style="flex:none">${x.sev === 'bad' ? '✕' : '!'}</i><div><b>${esc(x.a)}</b><div class="sub" style="margin:0">${esc(x.b)}</div></div></li>`).join('') || '<li>Nothing to do.</li>'}</ul></div>
        ${m.m365Bars.length ? `<div class="card"><h3>Microsoft 365 seats</h3><div class="bars">${m.m365Bars.map(b => `<div class="bar"><span>${esc(b.n)}</span><div class="track"><div class="fill${b.c / b.t < 0.5 ? ' gold' : ''}" style="width:${b.t ? b.c / b.t * 100 : 0}%"></div></div><span class="mono">${b.c}/${b.t}</span></div>`).join('')}</div>
          <p class="sub">Assigned seats out of purchased seats. Free SKUs aren’t shown.</p></div>` : ''}
      </div>
      ${pp.length ? `<h3 id="perPerson">Licences per person</h3>
      <p class="sub">Every seat and device product tied to one person, priced per seat: Microsoft 365, training, MFA and other accounts in their name, plus the RMM, EDR / AV, backup and app control on the devices they use. Prices are the monthly price per seat you enter: one list for every client, saved on this computer, and the same list as Subscriptions above. ${m.perPerson.idState !== 'ok' ? '' : m.perPerson.linked ? 'Each device is counted once, for the person it’s assigned to (or who signed in last). Shared devices (three or more people, or a server nobody is assigned to) are listed but not added to anyone’s total.' : 'No tool links devices to people for this client yet, so only user-based seats are shown.'}</p>
      ${m.perPerson.idState !== 'ok' ? `<div class="card flag warn"><p style="margin:0"><b>People and devices come from Identity & access, which ${m.perPerson.idState === 'error' ? `couldn’t be read for this client${m.perPerson.idError ? ` (${esc(m.perPerson.idError)})` : ''}` : 'isn’t loaded for this client yet'}.</b> Only Microsoft 365 users are shown, without their devices. Refresh this page to load it.</p></div>` : ''}
      <div class="filters no-print"><label for="ppSel" style="font-weight:600">Person</label><select id="ppSel" style="min-width:260px"><option value="">Everyone: compare monthly cost</option>${pp.map(p => `<option value="${esc(p.key)}">${esc(p.name)}${p.email ? ` (${esc(p.email)})` : ''}</option>`).join('')}</select></div>
      <p class="sr-only" id="ppStatus" role="status"></p><div id="ppOut"></div>` : ''}
      ${PCOLS.length ? `<h3>People against products</h3>
      <div class="filters no-print"><label class="toggle"><input type="checkbox" id="pplAct"> Only people who need action</label><div class="search" style="flex:1;min-width:200px;margin:0"><input id="pplQ" placeholder="Search people" autocomplete="off" aria-label="Search people"></div></div>
      <div class="tw tech"><table id="pplTable"><thead><tr><th>Person</th>${PCOLS.map(([, l]) => `<th class="c">${l}</th>`).join('')}<th>Action</th></tr></thead><tbody>
        ${m.people.map(p => `<tr data-act="${p.action ? 1 : 0}" data-q="${esc(`${p.name} ${p.upn || ''}`.toLowerCase())}"><td class="wrap" data-csv="${esc(p.name)} <${esc(p.upn || '')}>">${who(p)}<div class="sub mono" style="margin:0">${esc(p.upn || '')}</div>${p.orphan ? '<span class="chip c-crit">No M365 or AD account</span>' : ''}</td>${PCOLS.map(([k]) => cell(p.cells[k], p.notes && p.notes[k])).join('')}<td class="wrap">${p.action ? esc(p.action) : '<span class="sub">Nothing to do</span>'}</td></tr>`).join('')}
      </tbody></table></div>` : ''}
      ${ACOLS.length ? `<h3>Dormant and stale licensed users</h3>
      <p class="sub">Last activity for every licensed person in each tool, measured to the latest inspection. Active means within ${ACTIVE_DAYS} days, Stale means ${ACTIVE_DAYS + 1} to ${DORMANT_DAYS - 1} days, and Dormant means ${DORMANT_DAYS} days or more, or never used.</p>
      <div class="kpis">${kpiStrip(m.dormKpis)}</div>
      <p class="sub xref">“Dormant” here means no Microsoft 365 sign-in for 30+ days. Accounts with no sign-in at all for 90+ days are on ${pageA('identity', '', 'Identity & access →')}</p>
      <div class="tw tech"><table><thead><tr><th>Person</th><th>Licensed for</th>${ACOLS.map(([, l]) => `<th class="c">${l}</th>`).join('')}<th>Verdict</th></tr></thead><tbody>
        ${m.dormant.map(r => `<tr><td class="wrap" data-csv="${esc(r.name)}">${who(r)}</td><td class="wrap" style="min-width:160px;font-size:12.5px">${esc(r.licences.join(' · '))}</td>${ACOLS.map(([k]) => k === 'anthKeys' ? keys(r.anthKeys) : k === 'm365' ? (r.m365 ? act(r.m365) : '<td class="c"><span class="sub">No account</span></td>') : k === 'kb4' ? act(r.kb4, r.kb4 && !r.kb4.archived ? (r.kb4.pastDue && !r.kb4.d ? 'training past due' : r.kb4.viaTraining ? 'training' : r.kb4.d ? '' : 'no training done') : '') : act(r[k])).join('')}
          <td class="wrap" data-csv="${r.verdict === 'ok' ? 'Active' : r.verdict === 'warn' ? 'Review' : 'Stale seat'}: ${esc(r.reason)}"><span class="chip ${r.verdict === 'ok' ? 'c-ok' : r.verdict === 'warn' ? 'c-warn' : 'c-crit'}">${r.verdict === 'ok' ? 'Active' : r.verdict === 'warn' ? 'Review' : 'Stale seat'}</span><div class="sub" style="margin-top:4px">${esc(r.reason)}</div></td></tr>`).join('')}
      </tbody></table></div>` : ''}
      ${DCOLS.length ? `<h3>Devices against per-device products</h3>
      <div class="tw tech"><table><thead><tr><th>Device</th><th>OS</th>${DCOLS.map(([, l]) => `<th class="c">${l}</th>`).join('')}<th>Note</th></tr></thead><tbody>
        ${m.devices.map(d => `<tr><td class="mono" data-csv="${esc(d.name)}">${pageA('lookup', d.name.replace(/\s*\(.*$/, ''), esc(d.name), 'Everything about this device (Lookup)')}</td><td>${d.eos ? `<span class="chip c-crit">${esc(d.os)}</span>` : esc(d.os)}</td>${DCOLS.map(([k]) => cell(d.cells[k].k, d.cells[k].last ? (m.deviceSource === 'coverage' ? d.cells[k].last : `last ${d.cells[k].last}`) : '', m.deviceSource === 'coverage' && d.cells[k].last ? d.cells[k].last.split(', ') : null)).join('')}<td class="wrap">${d.note ? esc(d.note) : '<span class="sub">Covered</span>'}</td></tr>`).join('')}
      </tbody></table></div>
      <p class="sub">${pageA('coverage', '', 'Stack coverage')} shows every device against every tool the client runs.</p>` : ''}
      <div class="legend tech"><span><i class="tick t-ok">✓</i> Has the seat</span><span><i class="tick t-bad">✕</i> Missing a seat they need</span><span><i class="tick t-warn">!</i> ${m.deviceSource === 'coverage' ? 'Not confirmed: the tool may not report devices to Liongard' : `Has a seat, but something’s wrong (or check-in older than ${DEVICE_STALE_DAYS} days)`}</span><span><i class="tick t-none">–</i> Not in that system (may be fine)</span></div>
      <div class="review-only">
        <p>We reconciled ${esc(m.environment.Name)}’s licences against the people and devices we manage. Please approve the changes below. Tick <b>Approve</b> for each change you’d like us to make.</p>
        <h4>Subscriptions with spare seats</h4>
        <table class="review"><thead><tr><th>Product</th><th>Purchased</th><th>In use</th><th>Spare</th><th>Suggested change</th><th>Approve</th></tr></thead><tbody>${spare.map(s => `<tr><td>${esc(s.product)}</td><td>${s.buy}</td><td>${s.use}</td><td>${s.buy - s.use}</td><td>Reduce to ${s.use} seats at renewal</td><td class="box">☐</td></tr>`).join('') || '<tr><td colspan="6">No spare seats.</td></tr>'}</tbody></table>
        <h4>Licences held by people who aren’t using them</h4>
        <table class="review"><thead><tr><th>Person</th><th>Licences</th><th>Why</th><th>Suggested change</th><th>Approve</th></tr></thead><tbody>${stale.map(r => `<tr><td>${esc(r.name)}</td><td>${esc(r.licences.join(', '))}</td><td>${esc(r.reason)}</td><td>${r.verdict === 'bad' ? 'Remove the licences or disable the account' : 'Confirm they still need it'}</td><td class="box">☐</td></tr>`).join('') || '<tr><td colspan="5">Everyone licensed is active.</td></tr>'}</tbody></table>
        <h4>Other changes</h4>
        <table class="review"><thead><tr><th>Change</th><th>Why</th><th>Approve</th></tr></thead><tbody>${m.actions.map(a => `<tr><td>${esc(a.a)}</td><td>${esc(a.b)}</td><td class="box">☐</td></tr>`).join('')}</tbody></table>
        <div class="signoff"><div>Approved by (client): ____________________________</div><div>Date: ______________</div><div>Signature: ____________________________</div></div>
      </div>`;
  },
  after(m) {
    // Seat prices are MSP-wide (Settings › Defaults), kept by the app. Saved a moment after typing stops.
    let prices = { ...((SETTINGS && SETTINGS.prices) || {}) }, saveT = null;
    const savePrices = () => { clearTimeout(saveT); saveT = setTimeout(async () => { try { await window.portal.updateSettings({ prices }); SETTINGS = await window.portal.settings(); } catch (err) { $('statusLine').textContent = `Prices not saved: ${cleanErr(err)}`; } }, 600); };
    const cur = mspCurrency();
    const money = v => fmtMoney(v, cur);   // Settings › Defaults › Currency
    const staleSeats = m.dormant.filter(r => r.verdict === 'bad');
    const paint = () => {
      let spareCost = 0, priced = 0;
      m.subs.forEach((s, i) => {
        const p0 = parsePrice(prices[s.product]), p = p0 == null ? NaN : p0; const sp = s.buy == null ? 0 : Math.max(0, s.buy - s.use);
        if (!isNaN(p)) { priced++; spareCost += p * sp; }
        const c = $(`cost${i}`); if (c) c.textContent = isNaN(p) || s.buy == null ? '–' : money(p * sp);
      });
      const spare = m.subs.filter(s => s.buy != null && s.buy - s.use > 0 && !/\bfree\b|trial/i.test(s.product));   // free and trial SKUs cost nothing
      const lines = [
        // Same number as the "Spare paid M365 seats" tile; other tools' spare seats are listed separately.
        (() => { const t = (m.kpis.find(k => k.k === 'Spare paid M365 seats') || {}).v || 0; const other = spare.filter(s => s.source !== 'Microsoft 365'); const on = other.reduce((n, s) => n + s.buy - s.use, 0);
          return `${m.subs.length} subscription${m.subs.length === 1 ? '' : 's'} checked: ${t ? `${t} spare paid Microsoft 365 seat${t === 1 ? '' : 's'}` : 'no spare paid Microsoft 365 seats'}${on ? `, plus ${on} spare in ${[...new Set(other.map(s => s.source))].join(', ')}` : ''}.`; })(),
        staleSeats.length ? `${staleSeats.length} licensed ${staleSeats.length === 1 ? 'person hasn’t' : 'people haven’t'} used their licence in ${m.thresholds.DORMANT_DAYS}+ days: ${staleSeats.slice(0, 4).map(r => r.name).join(', ')}${staleSeats.length > 4 ? ' and more' : ''}.` : 'Every licensed person is active.',
        m.actions.length ? `${m.actions.length} change${m.actions.length === 1 ? '' : 's'} to make, ${m.actions.filter(a => a.sev === 'bad').length} urgent.` : '',
        priced ? `Spare seats cost about ${money(spareCost)} a month (${money(spareCost * 12)} a year) at the prices entered.` : 'Add seat prices below to see what spare seats cost.',
      ].filter(Boolean);
      // The currency hint is for the MSP only, never printed for the client.
      $('licSummary').innerHTML = lines.map(l => `<li><span>${esc(l)}${priced && !cur && /^Spare seats cost/.test(l) ? ' <span class="msp no-print">(set your currency in Settings › Defaults)</span>' : ''}</span></li>`).join('');
    };
    // ---------- Licences per person ----------
    // A seat's monthly cost: free SKUs and usage-billed products cost nothing per seat; unpriced seats are left out of totals.
    const pp = (m.perPerson && m.perPerson.people) || [];
    const price = p => parsePrice(prices[p]);
    const seatCost = x => x.free || x.usage ? 0 : price(x.product);
    const allSeats = p => [...p.seats, ...p.devices.flatMap(d => d.seats)];
    // Usage-billed seats (Anthropic) are counted separately: they're neither priced nor unpriced.
    const totals = p => { let sum = 0, unpriced = 0, priced = 0, usage = []; for (const x of allSeats(p)) { if (x.shared) continue; if (x.usage) { usage.push(x.product); continue; } const c = seatCost(x); if (c == null) unpriced++; else { sum += c; if (!x.free) priced++; } } return { sum, unpriced, priced, usage }; };
    // A bare total would read as the whole cost when seats are unpriced, so a partial total always says so.
    const totalText = t => !t.priced && t.unpriced ? '–' : money(t.sum) + (t.unpriced ? ` + ${t.unpriced} unpriced` : '');
    const GROUP_ORDER = ['Microsoft 365', 'Security training', 'MFA', 'AI', 'Other accounts', 'RMM', 'EDR / AV', 'Backup', 'App control'];
    const seatRow = x => `<tr${x.shared ? ' class="muted"' : ''}><td>${esc(x.group)}</td><td><b>${toolIcon(x.product)}${esc(x.product)}</b>${x.account ? '<div class="sub" style="margin:0">Has an account; add a price if it’s billed per user</div>' : ''}</td><td>${x.unit === 'device' ? `Per device: ${pageA('lookup', x.device, esc(x.device), 'Everything about this device (Lookup)')}${x.alsoUsedBy ? ` <span class="chip c-none">Also used by ${esc(x.alsoUsedBy)}, not counted</span>` : x.shared ? ' <span class="chip c-none">Shared, not counted</span>' : ''}` : 'Per user'}</td>
      <td class="c">${x.free ? '<span class="chip c-none">Free</span>' : x.usage ? '<span class="chip c-none">Billed on usage</span>' : `<input class="price pprice no-print msp" data-k="${esc(x.product)}" inputmode="decimal" aria-label="Price per ${x.unit} per month for ${esc(x.product)}" placeholder="Price / ${x.unit}" value="${esc(prices[x.product] ?? '')}">`}</td>
      <td class="c mono" data-cost="${esc(x.product)}" data-shared="${x.shared ? 1 : 0}">–</td></tr>`;
    const renderPerson = () => {
      const out = $('ppOut'); if (!out) return;
      const sel = $('ppSel').value, p = pp.find(x => x.key === sel);
      // One short announcement when the person changes, not the whole card on every keystroke.
      $('ppStatus').textContent = p ? `Showing ${p.name}: ${p.seats.length} user seat${p.seats.length === 1 ? '' : 's'}, ${p.devices.length} device${p.devices.length === 1 ? '' : 's'}.` : 'Showing everyone.';
      if (!p) {
        out.innerHTML = `<div class="tw"><table id="ppAll"><caption class="sub" style="text-align:left;caption-side:top">Monthly cost per person at the prices entered. Pick a name to see the breakdown.</caption><thead><tr><th>Person</th><th class="c">User seats</th><th class="c">Devices</th><th class="c">Cost / month</th><th class="c">Cost / year</th><th>Not priced yet</th></tr></thead><tbody></tbody></table></div>`;
        return paintPeople();
      }
      const seats = [...p.seats, ...p.devices.flatMap(d => d.seats)].sort((a, b) => GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group));
      out.innerHTML = `<div class="card"><h3 style="margin-top:0">${esc(p.name)} ${pageA('identity', p.email || p.name, '↗', 'Open on the Identity page')}</h3>
        <div class="sub mono" style="margin:0">${esc(p.email || '')}${p.kind !== 'Person' ? ` · ${esc(p.kind)}` : ''}</div>${p.enabled === false ? '<span class="chip c-crit">Account disabled: still holding these seats</span>' : ''}
        <div class="kpis" id="ppKpis" style="margin-top:12px"></div>
        <div class="tw"><table id="ppTable"><thead><tr><th>Type</th><th>Product</th><th>Billed</th><th class="c">Price / month${mspCurrency() ? ` (${esc(mspCurrency())})` : ''}</th><th class="c">Cost / month</th></tr></thead><tbody>${seats.map(seatRow).join('') || '<tr><td colspan="5" class="sub">No seats found.</td></tr>'}</tbody>
        <tfoot><tr><th colspan="4" style="text-align:right">Total per month</th><th class="c mono" id="ppTotal">–</th></tr></tfoot></table></div>
        ${p.devices.length ? `<p class="sub">Devices: ${p.devices.map(d => `${pageA('lookup', d.host, esc(d.host), 'Everything about this device (Lookup)')}${d.os ? ` (${esc(d.os)})` : ''}${d.shared ? ' shared' : d.alsoUsedBy ? `, counted for ${esc(d.alsoUsedBy)}` : ''}, ${d.strength === 'assigned' ? 'assigned to them' : 'they signed in last'}${d.seats.length ? '' : '. No device tools seen on it'}${(d.alsoSeen || []).length ? `. Also seen: ${esc(d.alsoSeen.join(', '))} (not billed separately)` : ''}`).join('; ')}. Linked by ${esc([...new Set(p.devices.flatMap(d => d.sources))].join(', '))}.</p>` : `<p class="sub">${m.perPerson.linked ? 'No device is linked to this person.' : 'Device links aren’t available for this client.'}</p>`}</div>`;
      out.querySelectorAll('input.pprice').forEach(inp => inp.addEventListener('input', () => setPrice(inp.dataset.k, inp.value, inp)));
      paintPerson(p);
    };
    const paintPerson = p => {
      document.querySelectorAll('#ppTable [data-cost]').forEach(td => { const x = allSeats(p).find(s => s.product === td.dataset.cost); const c = x ? seatCost(x) : null; td.textContent = x && (x.free || x.usage) ? money(0) : c == null ? '–' : money(c); });
      const t = totals(p), nUser = p.seats.length, nDev = p.devices.filter(d => !d.shared).length;
      $('ppTotal').textContent = totalText(t);
      $('ppKpis').innerHTML = kpiStrip([
        { k: 'User seats', v: nUser, s: [...new Set(p.seats.map(x => x.group))].join(', ') || 'None', sev: 'info' },
        { k: 'Devices', v: p.devices.length, s: p.devices.length ? `${nDev} their own${p.devices.length - nDev ? `, ${p.devices.length - nDev} shared` : ''}` : 'None linked', sev: 'info' },
        { k: 'Cost / month', v: totalText(t), s: [t.unpriced ? `${t.unpriced} seat${t.unpriced === 1 ? '' : 's'} not priced yet` : 'Every seat priced', t.usage.length ? `Excludes usage-billed: ${[...new Set(t.usage)].join(', ')} (see AI usage)` : ''].filter(Boolean).join('. '), sev: t.unpriced ? 'info' : 'ok' },
        { k: 'Cost / year', v: !t.priced && t.unpriced ? '–' : money(t.sum * 12) + (t.unpriced ? '+' : ''), s: 'At the prices entered', sev: 'info' },
      ]);
    };
    const paintPeople = () => {
      const tb = document.querySelector('#ppAll tbody'); if (!tb) return;
      // Fully priced people first, then partial ones: a partial total isn't comparable.
      const rowsP = pp.map(p => ({ p, t: totals(p) })).sort((a, b) => (a.t.unpriced > 0) - (b.t.unpriced > 0) || b.t.sum - a.t.sum || a.p.name.localeCompare(b.p.name));
      const cell = (t, v) => !t.priced && t.unpriced ? '–' : `${money(v)}${t.unpriced ? '+' : ''}`;
      tb.innerHTML = rowsP.map(({ p, t }) =>
        `<tr><td><button type="button" class="linkbtn" data-pick="${esc(p.key)}">${esc(p.name)}</button>${p.enabled === false ? ' <span class="chip c-crit">Disabled</span>' : ''}</td><td class="c mono">${p.seats.length}</td><td class="c mono">${p.devices.length}</td><td class="c mono"${t.unpriced ? ` title="${t.unpriced} seat${t.unpriced === 1 ? '' : 's'} not priced"` : ''}>${cell(t, t.sum)}</td><td class="c mono">${cell(t, t.sum * 12)}</td><td>${t.unpriced ? `${t.unpriced} seat${t.unpriced === 1 ? '' : 's'}` : '<span class="sub">None</span>'}</td></tr>`).join('');
      if (rowsP.every(r => !r.t.priced)) tb.insertAdjacentHTML('afterbegin', '<tr><td colspan="6" class="sub">No prices yet. Add them in the person’s breakdown, on Subscriptions above, or in Settings › Licence prices.</td></tr>');
      tb.querySelectorAll('[data-pick]').forEach(b => b.addEventListener('click', () => { $('ppSel').value = b.dataset.pick; renderPerson(); $('ppSel').focus(); }));
    };
    // One price list: typing a price anywhere updates every input and total that uses it.
    const setPrice = (k, raw, from) => {
      const v = String(raw).trim(), n = parsePrice(v);
      // "12,50" is read as 12.50. Something that isn't a price is flagged and not saved.
      if (from) from.toggleAttribute('aria-invalid', v !== '' && n == null);
      if (v !== '' && n == null) { $('statusLine').textContent = `The price for ${k} isn’t a number. Use a number like 12.50.`; return; }
      if (v === '') delete prices[k]; else prices[k] = n;
      document.querySelectorAll('input.price').forEach(i => { const key = i.dataset.k || (m.subs[+i.dataset.i] || {}).product; if (i !== from && key === k) i.value = v; });
      savePrices(); paint();
      const p = pp.find(x => x.key === ($('ppSel') || {}).value); if (p) paintPerson(p); else paintPeople();
    };
    document.querySelectorAll('input.price:not(.pprice)').forEach(inp => {
      const s = m.subs[+inp.dataset.i]; if (prices[s.product] != null) inp.value = prices[s.product];
      inp.addEventListener('input', () => setPrice(s.product, inp.value, inp));
    });
    paint();
    if ($('ppSel')) {
      $('ppSel').addEventListener('change', renderPerson);
      const p0 = new URLSearchParams(location.search).get('person'); if (p0) { const hit = pp.find(p => p.key === p0 || p.email === p0.toLowerCase()); if (hit) $('ppSel').value = hit.key; }
      renderPerson();
    }
    const filt = () => {
      const only = $('pplAct') && $('pplAct').checked, q = ($('pplQ') && $('pplQ').value || '').trim().toLowerCase();
      document.querySelectorAll('#pplTable tbody tr').forEach(r => { r.hidden = (only && r.dataset.act !== '1') || (q && !r.dataset.q.includes(q)); });
    };
    if ($('pplAct')) { $('pplAct').addEventListener('change', filt); $('pplQ').addEventListener('input', filt); }
    const q0 = new URLSearchParams(location.search).get('q'); if (q0 && $('pplQ')) { $('pplQ').value = q0; filt(); }
  },
  handlesQuery: true,
  how: m => [
    `GET  /api/v1/launchpoints, /api/v1/timeline  (env ${m.environment.ID})  → find each licence source by inspector name`,
    ...Object.entries(m.systems).map(([a, s]) => `POST /api/v2/dataprints/evaluate/${s.systemDetailId}  ${a} (system ${s.systemId}, inspected ${fmtDate(s.inspectedOn, true)})`),
    'POST /api/v2/metrics/evaluate/systems  → licence and seat data from the client’s other tools (listed at the bottom)',
    `Rules: src/main/panels/licences-rules.js (Active ≤${m.thresholds.ACTIVE_DAYS} d, Dormant ≥${m.thresholds.DORMANT_DAYS} d, device stale >${m.thresholds.DEVICE_STALE_DAYS} d)`,
  ].join('\n'),
};
