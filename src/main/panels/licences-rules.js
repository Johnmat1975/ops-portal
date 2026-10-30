// Licence reconciliation rules. Pure function: collected data in, page model out.
// Same rules as the published portal's licence page and the "Ops Portal" prompt (section 6).

const DAY = 864e5;
const ACTIVE_DAYS = 30, DORMANT_DAYS = 90, DEVICE_STALE_DAYS = 14;

const lc = s => String(s || '').trim().toLowerCase();
const local = e => lc(e).split('@')[0];
const toDate = s => { if (!s) return null; const d = new Date(String(s).replace(' ', 'T').replace(/(T\d\d:\d\d:\d\d)$/, '$1Z')); return isNaN(d) ? null : d; };
const latest = (...ds) => ds.filter(Boolean).sort((a, b) => b - a)[0] || null;
const iso = d => d ? d.toISOString().slice(0, 10) : null;

function compute(input) {
  const D = { ...(input.data || {}) };
  if (D.threatlocker && !D.threatlocker.computers && !D.threatlocker.mobile) D.threatlocker = null;   // connected but no devices returned
  for (const k of ['ninja', 'crowdstrike', 'ad']) if (Array.isArray(D[k]) && !D[k].length) D[k] = null;
  const ALIAS = { m365: 'Microsoft 365', kb4: 'KnowBe4', duo: 'Duo Security', threatlocker: 'ThreatLocker', ninja: 'NinjaOne', crowdstrike: 'CrowdStrike EDR', anthropic: 'Anthropic', ad: 'Active Directory' };
  const emptySources = Object.keys(input.data || {}).filter(k => D[k] === null || D[k] === undefined).map(k => `${ALIAS[k] || k} (connected, but returned no data)`);
  const ref = toDate(input.inspectedOn) || new Date();
  const refDay = Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth(), ref.getUTCDate());
  const days = d => d ? Math.round((refDay - Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())) / DAY) : null;
  const band = d => d == null ? 'never' : days(d) > DORMANT_DAYS - 1 ? 'dormant' : days(d) > ACTIVE_DAYS ? 'stale' : 'active';
  const has = k => D[k] !== undefined && D[k] !== null;
  const m365SignIns = ((D.m365 && D.m365.users) || []).some(u => toDate(u.last));

  // ---------- Microsoft 365 ----------
  const m365 = D.m365 || { lic: [], users: [] };
  const skus = (m365.lic || []).map(l => ({ ...l, enabled: +l.enabled || 0, consumed: +l.consumed || 0 }));
  const isFree = l => /FREE/i.test(l.sku);
  const isTeams = s => /teams/i.test(s) && !/no.?teams/i.test(s);
  const isE5NoTeams = s => /E5/i.test(s) && /no.?teams/i.test(s);
  const friendly = l => /^Microsoft_Teams_Enterprise/i.test(l.name) ? 'Microsoft Teams Enterprise' : (!l.name || /^other$/i.test(l.name)) ? l.sku : l.name;
  const mUsers = (m365.users || []).map(u => {
    const prods = String(u.prod || '').split('|').map(s => s.trim()).filter(Boolean);
    return { name: u.n, upn: u.upn, email: lc(u.upn), enabled: u.en !== false && u.en !== 'false', prods,
             licensed: prods.length > 0, lastSignIn: toDate(u.last) };
  });
  const byEmail = new Map(mUsers.map(u => [u.email, u]));
  const byName = new Map(mUsers.map(u => [lc(u.name), u]));
  const isSharedAdmin = u => /^(admin|administrator|it|support|helpdesk)@/i.test(u.upn);

  // ---------- other sources ----------
  const kb4 = D.kb4 || {}, duo = D.duo || {}, tl = D.threatlocker || {}, anth = D.anthropic || {};
  const kbUsers = (kb4.users || []).filter(u => u.e);
  const kbByEmail = new Map(kbUsers.map(u => [lc(u.e), u]));
  const kbDone = new Map();
  for (const t of kb4.training || []) { const d = toDate(t.done); if (d) kbDone.set(lc(t.e), latest(kbDone.get(lc(t.e)), d)); }
  const kbPastDue = new Set((kb4.training || []).filter(t => /past due/i.test(t.s) && !t.done).map(t => lc(t.e)));
  const duoUsers = (duo.users || []).filter(u => u.u || u.e);
  const anthUsers = anth.users || [];
  const keysBy = new Map(); for (const k of anth.keys || []) if (lc(k.s) === 'active') keysBy.set(k.by, (keysBy.get(k.by) || 0) + 1);
  const anthByEmail = new Map(anthUsers.map(u => [lc(u.e), u]));
  const adUsers = (D.ad || []).filter(u => u.en !== false && u.en !== 'false');
  const adByUser = new Map(adUsers.map(u => [lc(u.u), u]));

  // Duo record -> M365 person (by email, else by name) + record problems
  const duoFor = new Map(), duoIssues = new Map(), orphans = [];
  for (const d of duoUsers) {
    const viaEmail = byEmail.get(lc(d.e)), viaName = byName.get(lc(d.u));
    const person = viaName || viaEmail;
    if (!person) { orphans.push({ tool: 'Duo', name: d.u || d.e, email: d.e, last: toDate(d.last) }); continue; }
    duoFor.set(person.email, d);
    const issues = [];
    if (viaName && viaEmail && viaName !== viaEmail) issues.push(`Email is ${local(d.e)}@`);
    else if (viaEmail && !viaName && /\s/.test(String(d.u || '').trim())) issues.push(`Named \u201c${d.u}\u201d`);   // logins like "jsmith" aren't names
    if (d.enr === false || d.enr === 'false') issues.push('Not enrolled');
    if (issues.length) duoIssues.set(person.email, issues);
  }

  // ---------- people x products ----------
  const licensed = mUsers.filter(u => u.licensed);
  const people = licensed.map(u => {
    const e5 = u.prods.some(isE5NoTeams) || u.prods.some(p => /E5|E3|Business (Premium|Standard|Basic)/i.test(p));
    const teams = u.prods.some(isTeams);
    const needsTeams = u.prods.some(isE5NoTeams) && !teams;
    const kb = kbByEmail.get(u.email), dRec = duoFor.get(u.email), an = anthByEmail.get(u.email), ad = adByUser.get(local(u.email));
    const cells = {
      ad: ad ? 'ok' : 'none',
      e5: e5 ? 'ok' : 'none',
      teams: needsTeams ? 'bad' : teams ? 'ok' : 'none',
      kb4: !has('kb4') ? 'none' : !kb ? (isSharedAdmin(u) ? 'none' : 'bad') : lc(kb.s) === 'archived' ? 'bad' : 'ok',
      duo: !has('duo') ? 'none' : !dRec ? (isSharedAdmin(u) ? 'none' : 'bad') : duoIssues.has(u.email) ? 'warn' : 'ok',
      anth: an ? 'ok' : 'none',
    };
    const notes = {
      kb4: kb && lc(kb.s) === 'archived' ? `Archived ${fmt(toDate(kb.archived))}` : '',
      duo: (duoIssues.get(u.email) || []).join(' · '),
      anth: an && an.r === 'admin' ? 'Org admin' : '',
      e5: u.prods.some(p => /Defender Vulnerability/i.test(p)) ? '+ Defender VM' : '',
    };
    const actions = [];
    if (isSharedAdmin(u)) actions.push(`Shared admin holds ${u.prods.length} licence${u.prods.length > 1 ? 's' : ''}. Make it an unlicensed admin`);
    if (needsTeams) actions.push('Assign Teams');
    if (cells.kb4 === 'bad') actions.push(kb ? 'Restore to KnowBe4' : 'Add to KnowBe4');
    if (cells.duo === 'bad') actions.push('Add to Duo');
    for (const i of duoIssues.get(u.email) || []) actions.push(i === 'Not enrolled' ? 'Finish Duo enrolment' : `Fix Duo record (${lcFirst(i)})`);
    return { name: u.name, upn: u.upn, shared: isSharedAdmin(u), enabled: u.enabled, cells, notes, action: actions.join('. ') };
  });
  for (const o of orphans) people.push({ name: o.name, upn: o.email, orphan: true,
    cells: { ad: 'none', e5: 'none', teams: 'none', kb4: 'none', duo: 'bad', anth: 'none' },
    notes: { duo: 'Orphan seat' }, action: `Not in Microsoft 365 or AD. Remove from ${o.tool} or confirm who this is` });

  // ---------- dormant / stale ----------
  const dormant = licensed.map(u => {
    const kb = kbByEmail.get(u.email), dRec = duoFor.get(u.email), an = anthByEmail.get(u.email), ad = adByUser.get(local(u.email));
    const kbAct = kb && lc(kb.s) !== 'archived' ? latest(toDate(kb.last), kbDone.get(u.email)) : undefined;
    const r = {
      name: u.name, shared: isSharedAdmin(u), disabled: !u.enabled,
      licences: u.prods.map(p => p.replace(/Microsoft_Teams_Enterprise_New/, 'Teams').replace(/Microsoft 365 /, '').replace(/ \(no Teams\)/, '').replace(/Microsoft Power Automate Free/, 'Power Automate').replace(/Microsoft Defender Vulnerability Management Add-on/, 'Defender VM')),
      // If Liongard reports no sign-in date for anyone in the tenant, the data isn't available: "unknown", not "never".
      m365: m365SignIns ? { d: iso(u.lastSignIn), n: days(u.lastSignIn), band: band(u.lastSignIn) } : { d: null, n: null, band: 'unknown' },
      ad: ad ? { d: iso(toDate(ad.last)), n: days(toDate(ad.last)), band: band(toDate(ad.last)) } : null,
      duo: dRec ? { d: iso(toDate(dRec.last)), n: days(toDate(dRec.last)), band: band(toDate(dRec.last)) } : null,
      kb4: kb ? (lc(kb.s) === 'archived' ? { archived: true } : { d: iso(kbAct), n: days(kbAct), band: band(kbAct), pastDue: kbPastDue.has(u.email), viaTraining: !!(kbDone.get(u.email) && (!toDate(kb.last) || kbDone.get(u.email) > toDate(kb.last))) }) : null,
      anthKeys: an ? (keysBy.get(an.id) || 0) : null,
    };
    if (kb) r.licences.push('KnowBe4'); if (dRec) r.licences.push('Duo'); if (an) r.licences.push('Anthropic');
    const stale = [];
    if (r.disabled) stale.push('Account is disabled but still licensed');
    if (!['active', 'unknown'].includes(r.m365.band)) stale.push(`M365 sign-in ${r.m365.band === 'never' ? 'never' : r.m365.n + ' days ago'}`);
    if (r.kb4 && !r.kb4.archived && r.kb4.band === 'never') stale.push('KnowBe4 seat never used');
    else if (r.kb4 && !r.kb4.archived && r.kb4.band !== 'active') stale.push(`KnowBe4 ${r.kb4.band}`);
    if (r.duo && r.duo.band !== 'active') stale.push(`Duo ${r.duo.band} (${r.duo.n} days)`);
    if (r.ad && r.ad.band !== 'active') stale.push(`AD ${r.ad.band} (${r.ad.n} days)`);
    if (r.anthKeys === 0) stale.push('Anthropic seat with no API key');
    const severe = r.disabled || !['active', 'unknown'].includes(r.m365.band) || (r.kb4 && r.kb4.band === 'never') || (r.duo && r.duo.band === 'dormant');
    r.verdict = stale.length === 0 ? 'ok' : severe ? 'bad' : 'warn';
    r.reason = stale.length ? stale.join('. ') : (r.shared ? 'Active (shared admin)' : 'Active everywhere');
    return r;
  });
  for (const o of orphans) dormant.push({ name: o.name, orphan: true, licences: [o.tool + ' only'], m365: null, ad: null,
    duo: { d: iso(o.last), n: days(o.last), band: band(o.last) }, kb4: null, anthKeys: null, verdict: 'bad',
    reason: `Orphan. Active in ${o.tool} but has no M365 or AD account` });

  // ---------- devices ----------
  const devMap = new Map();
  const addDev = (n, src, last, os, extra) => { if (!n) return; const k = lc(n); const d = devMap.get(k) || { name: n, os: null, src: {} }; d.src[src] = { last: toDate(last), ...extra }; if (os && !d.os) d.os = os; devMap.set(k, d); };
  for (const c of tl.computers || []) addDev(c.n, 'tl', c.last, c.os);
  for (const c of D.ninja || []) addDev(c.n, 'ninja', c.last);
  for (const c of D.crowdstrike || []) addDev(c.n, 'cs', c.last);
  const devices = [...devMap.values()].map(d => {
    const cell = s => { if (!has(s === 'tl' ? 'threatlocker' : s === 'cs' ? 'crowdstrike' : 'ninja')) return { k: 'none' }; const x = d.src[s]; if (!x) return { k: 'bad' }; const n = days(x.last); return { k: n != null && n > DEVICE_STALE_DAYS ? 'warn' : 'ok', last: fmt(x.last), n }; };
    const c = { ninja: cell('ninja'), cs: cell('cs'), tl: cell('tl') };
    const notes = [];
    const missing = ['ninja', 'cs'].filter(s => c[s].k === 'bad').map(s => s === 'ninja' ? 'RMM' : 'EDR');
    const only = Object.keys(d.src).length === 1;
    if (only && missing.length === 2) notes.push(`Only ${c.tl.k !== 'bad' ? 'ThreatLocker' : 'one tool'} sees it. Add RMM and EDR, or retire it`);
    else if (c.cs.k === 'bad') notes.push('No CrowdStrike sensor');
    else if (c.ninja.k === 'bad') notes.push('Not in NinjaOne');
    for (const [s, label] of [['ninja', 'NinjaOne'], ['cs', 'CrowdStrike'], ['tl', 'ThreatLocker']]) if (c[s].k === 'warn') notes.push(`${label} last heard from it ${c[s].n} days ago`);
    const os = shortOs(d.os);
    const eos = /Windows 10/i.test(d.os || '');
    if (eos) notes.push('Windows 10 is out of support');
    return { name: d.name, os, eos, cells: c, note: notes.join('. ') };
  }).sort((a, b) => devRank(a) - devRank(b) || a.name.localeCompare(b.name));
  for (const m of tl.mobile || []) devices.push({ name: `${m.n} (${cap(m.os)})`, os: cap(m.os), mobile: true,
    cells: { ninja: { k: 'none' }, cs: { k: 'none' }, tl: { k: lc(m.s) === 'inactive' ? 'warn' : 'ok', last: fmt(toDate(m.last)) } },
    note: lc(m.s) === 'inactive' ? 'Listed as Inactive in ThreatLocker. Check whether it\u2019s still billed' : '' });

  // ---------- subscriptions ----------
  const subs = [];
  const paid = skus.filter(l => !isFree(l));
  const noTeamsCount = people.filter(p => p.cells.teams === 'bad').length;
  const sharedHolders = mUsers.filter(u => u.licensed && isSharedAdmin(u));
  const lapsed = [];
  for (const l of skus) {
    const spare = l.enabled - l.consumed;
    let sev = spare > 0 ? 'warn' : spare < 0 ? 'bad' : 'ok', note = spare > 0 ? `${spare} spare` : spare < 0 ? `Over-assigned by ${-spare}` : 'Fully used';
    if (isFree(l)) { sev = 'none'; note = 'Free, so there\u2019s no cost'; }
    // 0 active seats with people still assigned: the subscription has lapsed or been suspended (a renewal problem, not over-assignment).
    else if (l.enabled === 0 && l.consumed > 0) {
      sev = 'bad'; note = `Lapsed or suspended: ${l.consumed} people still assigned. Check the renewal`;
      lapsed.push({ name: friendly(l), n: l.consumed });
    }
    else if (isTeams(l.name) && noTeamsCount) note += `, while ${noTeamsCount} E5 user${noTeamsCount > 1 ? 's have' : ' has'} no Teams seat`;
    else if (isE5NoTeams(l.name) && sharedHolders.length) note += `. One is used by the shared ${sharedHolders[0].upn.split('@')[0]}@ account`;
    else if (spare > 0 && l.consumed <= 2) { const who = mUsers.filter(u => u.prods.includes(l.name)).map(u => u.name); if (who.length) note += `. Only ${who.join(' and ')} ${who.length > 1 ? 'have' : 'has'} it`; }
    subs.push({ product: friendly(l), source: 'Microsoft 365', buy: l.enabled, use: l.consumed, sev, note });
  }
  if (has('kb4')) {
    const active = kbUsers.filter(u => lc(u.s) !== 'archived').length, arch = kbUsers.filter(u => lc(u.s) === 'archived');
    const seats = +((kb4.acct || {}).seats) || null;
    subs.push({ product: `KnowBe4${kb4.acct && kb4.acct.level ? ' ' + kb4.acct.level : ''}`, source: 'KnowBe4', buy: seats, use: active,
      sev: seats == null ? 'warn' : seats - active < 0 ? 'bad' : arch.length && arch.some(a => byEmail.get(lc(a.e))) ? 'warn' : 'ok',
      note: [kb4.acct && kb4.acct.ends ? `Renews ${fmt(toDate(kb4.acct.ends), true)}` : '', ...arch.filter(a => byEmail.get(lc(a.e))).map(a => `${byEmail.get(lc(a.e)).name} is archived`)].filter(Boolean).join('. ') });
  }
  if (has('duo')) {
    const reported = duo.info && duo.info.user_count;
    const bits = [`${duoUsers.length} user records`];
    if (reported != null && +reported !== duoUsers.length) bits[0] += `, but Duo\u2019s own count says ${reported}`;
    if (orphans.length) bits.push(`Includes ${orphans.length} orphan${orphans.length > 1 ? 's' : ''}`);
    subs.push({ product: 'Duo', source: 'Duo Security', buy: null, use: duoUsers.length, sev: orphans.length || (reported != null && +reported !== duoUsers.length) ? 'warn' : 'ok', note: bits.join('. ') });
  }
  if (has('threatlocker')) {
    const mob = (tl.mobile || []).length, inactive = (tl.mobile || []).filter(m => lc(m.s) === 'inactive').length;
    subs.push({ product: `ThreatLocker${tl.billing ? ` (billed per ${tl.billing})` : ''}`, source: 'ThreatLocker', buy: null, use: (tl.computers || []).length + mob,
      sev: inactive ? 'warn' : 'ok', note: `${(tl.computers || []).length} computers${mob ? ` + ${mob} ${inactive ? 'inactive ' : ''}phone${mob > 1 ? 's' : ''}` : ''}` });
  }
  const csMissing = devices.filter(d => !d.mobile && d.cells.cs.k === 'bad'), nMissing = devices.filter(d => !d.mobile && d.cells.ninja.k === 'bad');
  if (has('crowdstrike')) subs.push({ product: 'CrowdStrike Falcon', source: 'CrowdStrike EDR', buy: null, use: (D.crowdstrike || []).length, sev: csMissing.length ? 'warn' : 'ok', note: csMissing.length ? `Missing on ${csMissing.length} device${csMissing.length > 1 ? 's' : ''} other tools see` : 'On every device other tools see' });
  if (has('ninja')) subs.push({ product: 'NinjaOne', source: 'NinjaOne', buy: null, use: (D.ninja || []).length, sev: nMissing.length ? 'warn' : 'ok', note: nMissing.length ? `Missing on ${nMissing.length} device${nMissing.length > 1 ? 's' : ''} other tools see` : 'On every device other tools see' });
  if (has('anthropic')) { const notIn = anthUsers.filter(a => !byEmail.get(lc(a.e))).length;
    subs.push({ product: 'Anthropic (Claude API)', source: 'Anthropic', buy: null, use: anthUsers.length, sev: notIn ? 'warn' : 'none', note: `Billed on usage, not seats. ${notIn ? `${notIn} user${notIn > 1 ? 's are' : ' is'} not in M365` : `All ${anthUsers.length} users exist in M365`}` }); }

  // ---------- KPIs ----------
  const sparePaid = paid.reduce((a, l) => a + Math.max(0, l.enabled - l.consumed), 0);
  const kbMissing = people.filter(p => !p.orphan && p.cells.kb4 === 'bad').length;
  const devOutside = devices.filter(d => !d.mobile && d.cells.ninja.k === 'bad' && d.cells.cs.k === 'bad').length;
  const inactiveMobile = devices.filter(d => d.mobile && d.cells.tl.k === 'warn').length;
  const kpis = [
    { k: 'Spare paid M365 seats', v: sparePaid, s: paid.filter(l => l.enabled > l.consumed).map(l => `${l.enabled - l.consumed} ${shortSku(l)}`).join(', ') || 'None', sev: sparePaid ? 'warn' : 'ok' },
    // People, not gaps: someone missing both Teams and KnowBe4 counts once (the breakdown below still names both).
    { k: 'People missing a seat', v: people.filter(p => !p.orphan && (p.cells.teams === 'bad' || p.cells.kb4 === 'bad')).length, s: [noTeamsCount ? `${noTeamsCount} E5 user${noTeamsCount > 1 ? 's' : ''} without Teams` : '', kbMissing ? `${kbMissing} missing from training` : ''].filter(Boolean).join(', ') || 'None', sev: noTeamsCount + kbMissing ? 'bad' : 'ok' },
    { k: 'Seats with no owner', v: orphans.length + inactiveMobile, s: [orphans.length ? `${orphans.length} ${orphans.map(o => o.tool)[0]} user${orphans.length > 1 ? 's' : ''} with no M365 or AD account` : '', inactiveMobile ? `${inactiveMobile} inactive phone${inactiveMobile > 1 ? 's' : ''} in ThreatLocker` : ''].filter(Boolean).join(', ') || 'None', sev: orphans.length + inactiveMobile ? 'bad' : 'ok' },
    // Device reconciliation covers NinjaOne and CrowdStrike only; other stacks are covered on Stack coverage.
    has('ninja') || has('crowdstrike')
      ? { k: 'Devices outside RMM and EDR', v: devOutside, s: devOutside ? 'Another tool sees them, but NinjaOne and CrowdStrike don\u2019t' : 'None', sev: devOutside ? 'bad' : 'ok' }
      : { k: 'Devices outside RMM and EDR', v: '—', s: 'Checked on Stack coverage for this client\u2019s tools', sev: 'info' },
  ];
  const lic = dormant.filter(r => !r.orphan);
  const dormantM365 = lic.filter(r => !['active', 'unknown'].includes(r.m365.band) || r.disabled);
  const kbNever = lic.filter(r => r.kb4 && !r.kb4.archived && r.kb4.band === 'never');
  const duoStale = dormant.filter(r => r.duo && (r.duo.band !== 'active' || r.orphan));
  const anthNoKey = lic.filter(r => r.anthKeys === 0);
  const oldest = lic.filter(r => r.m365.n != null).sort((a, b) => b.m365.n - a.m365.n)[0];
  const dormKpis = [
    // The definition is on the tile: Identity's "Stale accounts" is no sign-in for 90+ days, a different rule.
    { k: 'Dormant M365 licences', v: dormantM365.length, s: dormantM365.length ? `No M365 sign-in for ${ACTIVE_DAYS}+ days, or disabled: ${names(dormantM365)}` : !m365SignIns ? `Sign-in dates aren’t available from Liongard for this tenant${lic.some(r => r.disabled) ? '' : '; no licensed account is disabled'}` : `Every licensed user signed in within the last ${oldest ? oldest.m365.n : 0} days${lic.some(r => r.disabled) ? '' : ', and none is disabled'}`, sev: dormantM365.length ? 'bad' : 'ok' },
    { k: 'KnowBe4 seats never used', v: kbNever.length, s: kbNever.length ? names(kbNever) : 'None', sev: kbNever.length ? 'bad' : 'ok' },
    { k: 'Stale Duo seats', v: duoStale.length, s: duoStale.length ? duoStale.map(r => r.orphan ? `the orphan ${r.name}` : `${r.name} (${r.duo.n} days)`).join(' and ') : 'None', sev: duoStale.length ? 'warn' : 'ok' },
    { k: 'Anthropic seats with no key', v: anthNoKey.length, s: anthNoKey.length ? names(anthNoKey) : 'None', sev: anthNoKey.length ? 'warn' : 'ok' },
  ];

  // ---------- actions ----------
  const actions = [];
  const teamsSku = skus.find(l => isTeams(l.name));
  if (noTeamsCount) { const spare = teamsSku ? teamsSku.enabled - teamsSku.consumed : 0;
    actions.push({ sev: 'bad', a: `Give Teams to the ${noTeamsCount} E5 user${noTeamsCount > 1 ? 's' : ''} who don\u2019t have it.`, b: spare >= noTeamsCount ? `The ${spare} spare Teams seats cover all of them, with ${spare - noTeamsCount} left over.` : `Only ${spare} spare Teams seats, so buy ${noTeamsCount - spare} more.` }); }
  for (const l of paid) { const spare = l.enabled - l.consumed; if (spare > 0 && !isTeams(l.name) && !isE5NoTeams(l.name) && spare >= l.enabled / 2)
    actions.push({ sev: 'warn', a: `Cut ${shortSku(l)} from ${l.enabled} seats to ${l.consumed}, or roll it out to more users.`, b: `${spare} paid seats are unused.` }); }
  if (sharedHolders.length) { const e5 = skus.find(l => isE5NoTeams(l.name)); const spareE5 = e5 ? e5.enabled - e5.consumed + 1 : 0;
    actions.push({ sev: 'warn', a: `Take the licences off the shared ${sharedHolders[0].upn.split('@')[0]}@ account.`, b: e5 ? `That frees an E5 seat, giving ${spareE5} spare E5 seats to cut at renewal.` : 'Shared admin accounts don\u2019t need user licences.' }); }
  if (orphans.length > 3) actions.push({ sev: 'bad', a: `Review ${orphans.length} ${orphans[0].tool} users with no Microsoft 365 or AD account.`, b: `${orphans.slice(0, 5).map(o => o.name).join(', ')}${orphans.length > 5 ? ` and ${orphans.length - 5} more` : ''}. Remove them or match them to real accounts.` });
  else for (const o of orphans) actions.push({ sev: 'bad', a: `Remove ${o.name} from ${o.tool}, or confirm who they are.`, b: 'They don\u2019t exist in Microsoft 365 or Active Directory.' });
  for (const p of people.filter(p => !p.orphan && p.cells.kb4 === 'bad')) actions.push({ sev: 'warn', a: `Put ${p.name} ${p.notes.kb4 ? 'back ' : ''}in KnowBe4.`, b: `${p.notes.kb4 ? `They\u2019re an active, licensed user who was archived (${p.notes.kb4.replace('Archived ', '')}).` : 'They\u2019re a licensed user with no training seat.'}` });
  if (kbNever.length) actions.push({ sev: 'bad', a: `Reclaim or re-engage ${kbNever.length} KnowBe4 seat${kbNever.length > 1 ? 's' : ''} that ${kbNever.length > 1 ? 'have' : 'has'} never been used: ${names(kbNever)}.`, b: `None of them has signed in or completed any training${kbNever.some(r => r.kb4.pastDue) ? ', and some training is past due' : ''}.` });
  for (const r of lic.filter(r => (r.duo && r.duo.band !== 'active') || (r.ad && r.ad.band !== 'active'))) {
    const bits = [r.duo && r.duo.band !== 'active' ? `Duo login (${fmt(new Date(r.duo.d), false)})` : '', r.ad && r.ad.band !== 'active' ? `AD logon (${fmt(new Date(r.ad.d), false)})` : ''].filter(Boolean);
    actions.push({ sev: 'warn', a: `Check on ${r.name}.`, b: `Their ${bits.join(' and ')} ${bits.length > 1 ? 'are' : 'is'} over ${ACTIVE_DAYS} days old${r.m365.band === 'active' ? `, but they signed in to Microsoft 365 on ${fmt(new Date(r.m365.d), false)}` : ''}.` });
  }
  if (anthNoKey.length) actions.push({ sev: 'warn', a: `Review the Anthropic memberships for ${names(anthNoKey)}.`, b: 'They\u2019re members but have never created an API key.' });
  const onlyOne = devices.filter(d => !d.mobile && d.cells.ninja.k === 'bad' && d.cells.cs.k === 'bad');
  if (onlyOne.length) actions.push({ sev: 'warn', a: `Decide what to do with ${onlyOne.map(d => d.name).join(', ')}.`, b: 'One tool bills for them, but they have no RMM or EDR.' });
  const recIssues = [...duoIssues.entries()].filter(([, i]) => i.some(x => x !== 'Not enrolled'));
  if (recIssues.length) actions.push({ sev: 'warn', a: `Fix Duo records: ${recIssues.map(([e, i]) => `${byEmail.get(e).name} (${i.filter(x => x !== 'Not enrolled').map(lcFirst).join(', ')})`).join('; ')}.`, b: 'Mismatched records break reconciliation and offboarding.' });
  for (const l of lapsed) actions.push({ sev: 'bad', a: `Check the ${l.name} subscription renewal.`, b: `Liongard reports 0 active seats, but ${l.n} people are still assigned to it, so it has most likely lapsed or been suspended.` });
  actions.sort((a, b) => (a.sev === 'bad' ? 0 : 1) - (b.sev === 'bad' ? 0 : 1));

  const m365Bars = paid.map(l => ({ n: shortSku(l), c: l.consumed, t: l.enabled }));
  return { environment: input.environment, inspectedOn: input.inspectedOn, pulledOn: input.pulledOn, source: input.source || 'api',
           systems: input.systems || {}, missing: [...(input.missing || []), ...emptySources], kpis, subs, actions, m365Bars, people, dormKpis, dormant, devices,
           thresholds: { ACTIVE_DAYS, DORMANT_DAYS, DEVICE_STALE_DAYS } };
}

function fmt(d, year) { if (!d || isNaN(d)) return ''; return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', ...(year ? { year: 'numeric' } : {}), timeZone: 'UTC' }); }
function names(rs) { const n = rs.map(r => r.name); if (n.length > 5) return `${n.slice(0, 4).join(', ')} and ${n.length - 4} more`; return n.length > 1 ? n.slice(0, -1).join(', ') + ' and ' + n[n.length - 1] : n[0]; }
function lcFirst(s) { return s.charAt(0).toLowerCase() + s.slice(1); }
function cap(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }
function shortOs(os) { if (!os) return ''; return os.replace(/^Microsoft /, '').replace(/Windows Server (\d+).*/, 'Server $1').replace(/Windows 11 Enterprise LTSC/, 'Win 11 LTSC').replace(/Windows (\d+) Pro/, 'Win $1 Pro'); }
function shortSku(l) { if (!l.name || /^other$/i.test(l.name)) return l.sku; return /Teams/i.test(l.name) && !/no.?Teams/i.test(l.name) ? 'Teams' : /^Microsoft 365 E5/i.test(l.name) ? 'E5' : /Defender Vulnerability/i.test(l.name) ? 'Defender VM add-on' : l.name; }
function devRank(d) { return /server/i.test(d.os || '') ? 0 : d.cells.ninja.k === 'bad' && d.cells.cs.k === 'bad' ? 2 : 1; }

module.exports = { compute };
