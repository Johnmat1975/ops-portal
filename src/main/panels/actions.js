// Action plan: every problem the other pages find for this client, as one list ranked by risk, each with what it affects,
// how to fix it, who usually owns it, the effort, and the compliance references it fails. Built from the other pages'
// own rules and data (the same numbers they show), so nothing new is pulled from Liongard.
const cyber = require('./cyber');
const identity = require('./identity');
const coverage = require('./coverage');
const email = require('./email');
const network = require('./network');
const inspectors = require('./inspectors');
const licences = require('./licences');
const lifecycle = require('./lifecycle');
const { MAP } = require('./compliance');

// Parts in `have` were already pulled (Refresh all); a part that fails becomes { error } and its actions are left out (and said so).
const PARTS = { cy: cyber, id: identity, cov: coverage, mail: email, net: network, insp: inspectors, lic: licences, life: lifecycle };
async function collect(api, env, have = {}) {
  const out = { environment: env };
  await Promise.all(Object.entries(PARTS).map(async ([k, p]) => { out[k] = have[k] || await p.collect(api, env).catch(e => ({ error: e.message })); }));
  return out;
}

const RISK = { critical: 100, high: 70, medium: 40, low: 15 };
// Liongard alerts: open = not closed, resolved, completed or silenced (the Wallboard's rule); security = Cyber security's rule.
const alertOpen = a => !/clos|resolv|complete|silenc/i.test(a.status || '');
const alertSec = a => cyber.SEC.test(`${a.name} ${a.inspector}`);
const priKey = a => String(a.priority || '').trim().toLowerCase();
const OWNER = { desk: 'Service desk', sec: 'Security', am: 'Account manager', net: 'Network' };
const EFFORT = { quick: 'Quick fix', medium: 'Some work', project: 'Project' };

function compute(input) {
  const P = input.pulledOn;
  const extra = { pulledOn: P, stack: input.stack, msp: input.msp, coveragePolicy: input.coveragePolicy, policy: input.coveragePolicy, thresholds: input.thresholds };
  const ok = r => r && !r.error;
  const safe = (fn, raw) => { try { return ok(raw) ? fn({ ...raw, ...extra }) : null; } catch { return null; } };
  const id = safe(identity.compute, input.id), cov = safe(coverage.compute, input.cov), em = safe(email.compute, input.mail);
  const net = safe(network.compute, input.net), ih = safe(inspectors.compute, input.insp), lic = safe(licences.compute, input.lic), life = safe(lifecycle.compute, input.life);
  // Cyber security with the same identity, coverage and email data as the rest of this page, so the numbers agree.
  const cy = ok(input.cy) ? safe(cyber.compute, { ...input.cy, id: input.id || input.cy.id, cov: input.cov || input.cy.cov, mail: input.mail || input.cy.mail, insp: input.insp || input.cy.insp }) : null;
  const missing = Object.entries({ 'Cyber security': cy, 'Identity & access': id, 'Stack coverage': cov, 'Email & domain security': em, 'Network & firmware': net, 'Inspector health': ih, 'Licence reconciliation': lic, 'Lifecycle & renewals': life })
    .filter(([, m]) => !m).map(([n]) => n);

  const actions = [];
  // risk: critical|high|medium|low; affected: [{ t, d, link }] where link = { identityId | deviceId | systemId, systemDetailId }
  const add = a => { if (!a.count) return; const refs = (a.check && MAP[a.check]) || {}; actions.push({ ...a, refs: Object.fromEntries(Object.entries(refs).filter(([, v]) => v.length)) }); };
  const people = list => list.map(r => ({ t: r.name, d: r.email || r.username || '', link: { identityId: r.id } }));
  const devs = list => list.map(r => ({ t: r.host, d: [r.kind, r.os].filter(Boolean).join(' · '), link: { deviceId: r.id } }));
  const sysRef = i => ({ t: i.t || i.system, d: i.sub || i.d || '', link: { identityId: i.identityId, deviceId: i.deviceId, systemId: i.systemId, systemDetailId: i.systemDetailId, alertId: i.alertId } });

  // ---------- Cyber security: exposure right now ----------
  if (cy) {
    const P = k => cy.posture.find(p => p.key === k && p.count && !p.unknown);
    let p;
    if ((p = P('threats'))) add({ key: 'threats', cat: 'Threats', risk: 'critical', title: `Investigate ${p.count} active threat${p.count === 1 ? '' : 's'}`, why: 'Security tools report threats that are still active.', count: p.count, affected: p.items.map(sysRef), fix: ['Open each detection in the security tool and confirm it is contained or remediated.', 'Isolate any device where the threat is still running.', 'Record the outcome in the client’s ticket.'], owner: OWNER.sec, effort: 'medium', page: 'cyber', check: 'malware' });
    if ((p = P('privmfa'))) add({ key: 'privmfa', cat: 'Identity', risk: 'critical', title: `Turn on MFA for ${p.count} admin account${p.count === 1 ? '' : 's'}`, why: 'Admin accounts without MFA are the easiest way into every system they manage.', count: p.count, affected: p.items.filter(i => i.identityId).map(sysRef), fix: ['Enforce MFA for these accounts in every system listed (Conditional Access in Microsoft 365, Duo, the tool’s own settings).', 'Remove admin rights the account no longer needs.'], owner: OWNER.desk, effort: 'quick', page: 'identity', check: 'privMfa' });
    if ((p = P('fwd'))) add({ key: 'fwd', cat: 'Email', risk: 'critical', title: `Review ${p.count} external mail forwarding rule${p.count === 1 ? '' : 's'}`, why: 'Mail forwarded outside the organisation is a classic sign of a compromised mailbox.', count: p.count, affected: p.items.map(sysRef), fix: ['Check each rule with the mailbox owner.', 'Remove rules nobody can explain and reset that mailbox’s password.', 'Block automatic external forwarding in the Microsoft 365 outbound spam policy.'], owner: OWNER.sec, effort: 'quick', page: 'identity', check: 'mfa' });
    if ((p = P('dark'))) add({ key: 'dark', cat: 'Identity', risk: 'high', title: 'Reset passwords for credentials exposed on the dark web', why: 'Exposed passwords are used for credential stuffing.', count: p.count, affected: p.items.map(sysRef), fix: ['Reset the passwords of the people named in the dark web report.', 'Make sure MFA is on for them.'], owner: OWNER.sec, effort: 'quick', page: 'identity', check: 'mfa' });
    if ((p = P('mfa'))) add({ key: 'mfa', cat: 'Identity', risk: 'high', title: `Turn on MFA for ${p.count} user${p.count === 1 ? '' : 's'}`, why: 'Accounts without MFA in every system can be taken over with just a password.', count: p.count, affected: p.items.filter(i => i.identityId).map(sysRef), fix: ['Enrol these users in MFA in every system they use.', 'Consider requiring MFA for all users with a Conditional Access policy.'], owner: OWNER.desk, effort: 'quick', page: 'identity', check: 'mfa' });
    if ((p = P('edr'))) add({ key: 'edr', cat: 'Endpoints', risk: 'high', title: `Install EDR on ${p.count} managed device${p.count === 1 ? '' : 's'}`, why: 'Devices without EDR or active antivirus can be compromised without anyone noticing.', count: p.count, affected: p.items.map(sysRef), fix: ['Deploy the client’s EDR to these devices from the RMM.', 'Confirm each one checks in to the EDR console.'], owner: OWNER.sec, effort: 'medium', page: 'coverage', check: 'edrAll' });
    // Security alerts Liongard rates Critical or High are on the "Liongard priority" items below (one alert truth);
    // this item keeps the rest, and its risk is never lower than the highest priority inside it.
    if ((p = P('alerts'))) {
      const allOpen = Array.isArray(input.cy && input.cy.alerts) ? input.cy.alerts.filter(a => alertOpen(a) && alertSec(a)) : null;
      const rest = allOpen ? allOpen.filter(a => !['critical', 'high'].includes(priKey(a))) : null;
      const items = rest ? p.items.filter(i => rest.some(a => a.id === i.alertId)) : p.items;
      const count = rest ? rest.length : p.count;
      if (count) add({ key: 'alerts', cat: 'Threats', risk: 'high', title: `Triage ${count} open security alert${count === 1 ? '' : 's'}${rest ? ' (Liongard priority: Medium or Low)' : ''}`, why: 'Open security alerts in Liongard haven’t been reviewed.', count, affected: items.map(sysRef), fix: ['Review each alert in Liongard; resolve, or record why it’s expected.'], owner: OWNER.desk, effort: 'quick', page: 'wallboard', check: 'evidence' });
    }
    if ((p = P('patch'))) add({ key: 'patch', cat: 'Endpoints', risk: 'medium', title: `Fix patching on ${p.count} system${p.count === 1 ? '' : 's'}`, why: 'Failed or missing patches leave known vulnerabilities open.', count: p.count, affected: p.items.map(sysRef), fix: ['Check the patch errors in the RMM and re-run patching.', 'Reboot devices that have updates waiting for a restart.'], owner: OWNER.desk, effort: 'medium', page: 'coverage', check: 'patch' });
    if ((p = P('encrypt'))) add({ key: 'encrypt', cat: 'Endpoints', risk: 'medium', title: `Turn on disk encryption on ${p.count} system${p.count === 1 ? '' : 's'}`, why: 'A lost or stolen device without encryption exposes everything on it.', count: p.count, affected: p.items.map(sysRef), fix: ['Enable BitLocker (or FileVault on Macs) and escrow the recovery keys.'], owner: OWNER.desk, effort: 'medium', page: 'coverage', check: 'encrypt' });
  }

  // ---------- Liongard alerts rated Critical or High ----------
  // Every open alert Liongard rates Critical or High, security or not, so the plan's count equals the Wallboard's
  //. Security alerts are counted here, not under "Triage".
  if (ok(input.cy) && Array.isArray(input.cy.alerts)) {
    const open = input.cy.alerts.filter(alertOpen);
    const name = a => String(a.name || '').replace(/^[^|]+\|\s*/, '') || a.name;
    for (const [pri, risk] of [['Critical', 'critical'], ['High', 'high']]) {
      const list = open.filter(a => priKey(a) === risk).sort((a, b) => String(b.created).localeCompare(String(a.created)));
      const sec = list.filter(alertSec).length;
      if (list.length) add({ key: `alerts-${risk}`, cat: 'Alerts', risk, title: `Resolve ${list.length} open alert${list.length === 1 ? '' : 's'} (Liongard priority: ${pri})`, why: `Liongard rates ${list.length === 1 ? 'this alert' : 'these alerts'} ${pri}${sec ? ` (${sec} security, ${list.length - sec} other)` : ''}, and ${list.length === 1 ? 'it is' : 'they are'} still open.`, count: list.length, liongardPriority: pri,
        affected: list.slice(0, 200).map(a => ({ t: name(a), d: `Liongard priority: ${pri}${a.inspector ? ` · ${a.inspector}` : ''}${a.created ? ` · raised ${String(a.created).slice(0, 10)}` : ''}`, link: { alertId: a.id } })),
        fix: ['Open each alert in Liongard and fix the cause, or record why it is expected and close it.', 'If an alert keeps coming back, adjust the alert rule rather than ignoring it.'], owner: OWNER.desk, effort: 'quick', page: 'wallboard', check: null });
    }
  }

  // ---------- Identity ----------
  if (id) {
    const G = k => (id.groups.find(g => g.key === k) || {}).items || [];
    const rowsOf = items => id.rows.filter(r => items.some(i => i.identityId === r.id));
    const leavers = G('leavers'); if (leavers.length) add({ key: 'leavers', cat: 'Identity', risk: 'high', title: `Remove ${leavers.length} leaver${leavers.length === 1 ? '' : 's'} from the tools they can still reach`, why: 'Disabled in the directory but still present in other tools: their access hasn’t really ended.', count: leavers.length, affected: leavers.map(i => ({ t: i.t, d: i.d, link: { identityId: i.identityId } })), fix: ['Remove or disable these accounts in every tool listed.', 'Add those tools to the client’s offboarding checklist.'], owner: OWNER.desk, effort: 'quick', page: 'identity', check: 'leavers' });
    const msp = G('msp'); if (msp.length) add({ key: 'mspmfa', cat: 'Identity', risk: 'critical', title: `Turn on MFA for ${msp.length} of your MSP accounts`, why: 'Your own accounts reach every client, so they need MFA first.', count: msp.length, affected: msp.map(i => ({ t: i.t, d: i.d, link: { identityId: i.identityId } })), fix: ['Enforce MFA on these MSP accounts in every system.'], owner: OWNER.sec, effort: 'quick', page: 'identity', check: 'privMfa' });
    const stale = G('stale'); if (stale.length) add({ key: 'stale', cat: 'Identity', risk: 'medium', title: `Disable ${stale.length} unused account${stale.length === 1 ? '' : 's'}`, why: 'Accounts nobody uses are an easy, unnoticed way in.', count: stale.length, affected: stale.map(i => ({ t: i.t, d: i.d, link: { identityId: i.identityId } })), fix: ['Confirm with the client, then disable these accounts and remove their licences.'], owner: OWNER.desk, effort: 'quick', page: 'identity', check: 'stale' });
    const byp = G('bypass'); if (byp.length) add({ key: 'bypass', cat: 'Identity', risk: 'medium', title: `Review ${byp.length} Duo bypass code${byp.length === 1 ? '' : 's'} and enrolment gap${byp.length === 1 ? '' : 's'}`, why: 'A long-lived bypass code is a way around MFA.', count: byp.length, affected: byp.map(i => ({ t: i.t, d: i.d })), fix: ['Delete bypass codes that are no longer needed; give the rest a short expiry.', 'Finish Duo enrolment for the users listed.'], owner: OWNER.desk, effort: 'quick', page: 'identity', check: 'mfa' });
    const lic2 = G('licence'); if (lic2.length) add({ key: 'licholders', cat: 'Licences', risk: 'low', title: `Reclaim licences from ${lic2.length} account${lic2.length === 1 ? '' : 's'} that don’t need them`, why: 'Disabled, stale and shared accounts holding paid licences cost money every month.', count: lic2.length, affected: lic2.map(i => ({ t: i.t, d: i.d, link: { identityId: i.identityId } })), fix: ['Remove the licences, or convert shared mailboxes to unlicensed shared mailboxes.'], owner: OWNER.am, effort: 'quick', page: 'licences', check: null });
    const ud = id.userDevices && id.userDevices.exceptions;
    if (ud && ud.leavers.length) add({ key: 'leaverdevices', cat: 'Identity', risk: 'high', title: `Recover devices from ${ud.leavers.length} disabled account${ud.leavers.length === 1 ? '' : 's'}`, why: 'A disabled person is still the user or owner of a device.', count: ud.leavers.length, affected: people(id.rows.filter(r => ud.leavers.includes(r.id))), fix: ['Collect or wipe the device, then reassign it.'], owner: OWNER.desk, effort: 'medium', page: 'identity', check: 'leavers' });
  }

  // ---------- Stack coverage ----------
  if (cov) {
    const live = cov.rows.filter(r => !r.stale && (r.kind === 'Server' || r.kind === 'Workstation'));
    const um = cov.unmanaged.filter(r => !r.stale);
    if (um.length) add({ key: 'unmanaged', cat: 'Endpoints', risk: 'high', title: `Bring ${um.length} unmanaged device${um.length === 1 ? '' : 's'} under management`, why: 'Liongard sees these devices, but no RMM or EDR manages them: nobody patches or protects them.', count: um.length, affected: devs(um), fix: ['Enrol each device in the RMM and EDR, or retire it.'], owner: OWNER.desk, effort: 'medium', page: 'coverage', check: 'assets' });
    const eosSrv = live.filter(r => r.eos && r.kind === 'Server'), eosWs = live.filter(r => r.eos && r.kind === 'Workstation');
    if (eosSrv.length) add({ key: 'eos-srv', cat: 'Endpoints', risk: 'high', title: `Upgrade or retire ${eosSrv.length} server${eosSrv.length === 1 ? '' : 's'} on an unsupported OS`, why: 'Unsupported operating systems get no security fixes.', count: eosSrv.length, affected: devs(eosSrv), fix: ['Plan the upgrade or migration; until then, isolate these servers and restrict who can reach them.'], owner: OWNER.am, effort: 'project', page: 'coverage', check: 'os' });
    if (eosWs.length) add({ key: 'eos-ws', cat: 'Endpoints', risk: 'medium', title: `Replace or upgrade ${eosWs.length} workstation${eosWs.length === 1 ? '' : 's'} on an unsupported OS`, why: 'Unsupported operating systems get no security fixes.', count: eosWs.length, affected: devs(eosWs), fix: ['Upgrade to a supported Windows version, or quote replacements.'], owner: OWNER.am, effort: 'project', page: 'coverage', check: 'os' });
    const fw = live.filter(r => r.firewall === 'bad');
    if (fw.length) add({ key: 'hostfw', cat: 'Endpoints', risk: 'medium', title: `Turn the Windows firewall back on for ${fw.length} device${fw.length === 1 ? '' : 's'}`, why: 'A device firewall that’s off on any profile lets attackers move between machines.', count: fw.length, affected: devs(fw), fix: ['Re-enable Windows Firewall on all profiles, ideally through Group Policy or Intune so it stays on.'], owner: OWNER.desk, effort: 'quick', page: 'coverage', check: 'hostFw' });
    const av = live.filter(r => r.protection === 'off');
    if (av.length) add({ key: 'avoff', cat: 'Endpoints', risk: 'high', title: `Turn antivirus back on for ${av.length} device${av.length === 1 ? '' : 's'}`, why: 'Defender is off and no other antivirus is reported.', count: av.length, affected: devs(av), fix: ['Re-enable Defender real-time protection, or deploy the client’s EDR.'], owner: OWNER.sec, effort: 'quick', page: 'coverage', check: 'malware' });
    const nobk = live.filter(r => (r.missing || []).includes('backup'));
    if (nobk.length) add({ key: 'nobackup', cat: 'Backup', risk: nobk.some(r => r.kind === 'Server') ? 'high' : 'medium', title: `Back up ${nobk.length} device${nobk.length === 1 ? '' : 's'} the coverage policy says need it`, why: 'Without backup, ransomware or a failed disk means lost data.', count: nobk.length, affected: devs(nobk), fix: ['Add these devices to the client’s backup product and confirm the first job succeeds.'], owner: OWNER.desk, effort: 'medium', page: 'coverage', check: 'backup' });
  }

  // ---------- Email & domains ----------
  if (em) {
    const spoof = em.domains.filter(d => d.spoofable);
    for (const d of spoof) {
      const recs = em.fixPack.filter(r => r.domain === d.name);
      add({ key: `spoof-${d.name}`, cat: 'Email', risk: d.sends ? 'critical' : 'medium', title: `Stop ${d.name} being spoofed`, why: d.sends ? 'This domain sends email but doesn’t enforce DMARC, so anyone can send mail that appears to come from it.' : 'This domain doesn’t send email and isn’t locked down, so it can be used for convincing phishing.', count: 1,
        affected: [{ t: d.name, d: `Grade ${d.grade} · ${d.dmarc[2] || ''}`, link: d.sys ? { systemId: d.sys.systemId, systemDetailId: d.sys.systemDetailId } : null }],
        fix: recs.length ? recs.map(r => `Publish ${r.type} at ${r.host}: ${r.value}`) : (d.fix || []), owner: OWNER.desk, effort: 'quick', page: 'email', check: 'dmarc' });
    }
    const unlocked = em.domains.filter(d => d.locked === 'no');
    if (unlocked.length) add({ key: 'reglock', cat: 'Email', risk: 'low', title: `Turn on registrar lock for ${unlocked.length} domain${unlocked.length === 1 ? '' : 's'}`, why: 'Without a transfer lock a domain can be hijacked.', count: unlocked.length, affected: unlocked.map(d => ({ t: d.name, d: d.registrar || '' })), fix: ['Enable the transfer lock at the registrar.'], owner: OWNER.desk, effort: 'quick', page: 'email', check: 'dmarc' });
  }

  // ---------- Network ----------
  // Real findings only: an inspector that isn't reporting is a monitoring problem (listed under "Fix failing inspectors"),
  // and a finding from a stale inspector is ranked lower and labelled, since it may already be fixed.
  if (net) for (const c of net.cards) {
    const bad = c.rows.filter(r => r[2] === 'bad' && r[0] !== 'Inspector');
    if (!bad.length) continue;
    const staleSrc = c.rows.some(r => r[0] === 'Inspector' && r[2] === 'bad');
    add({ key: `net-${c.systemId || c.name}`, cat: 'Network', risk: staleSrc ? 'medium' : 'high', older: staleSrc, title: `Fix ${c.name} (${c.site}): ${bad.map(r => `${r[0]} ${String(r[1]).toLowerCase()}`).slice(0, 2).join(', ')}`, why: 'The perimeter firewall has security services off or other critical findings.', count: bad.length,
      affected: bad.map(r => ({ t: r[0], d: String(r[1]), link: { systemId: c.systemId, systemDetailId: c.systemDetailId } })), fix: [staleSrc ? 'First confirm it’s still true: this inspector’s data is out of date (fix the inspector, then re-check).' : '', 'Turn the security services back on (check the licence is active).', 'Update the firmware if it’s behind.'].filter(Boolean), owner: OWNER.net, effort: 'quick', page: 'network', check: 'boundary' });
  }

  // ---------- Lifecycle ----------
  if (life) {
    const exp = life.rows.filter(r => r.days < 0 && r.days >= -365 && !/^OS support/.test(r.type));   // expired in the last year (OS support is covered above)
    if (exp.length) add({ key: 'expired', cat: 'Renewals', risk: exp.some(r => /certificate|domain/i.test(r.type)) ? 'high' : 'medium', title: `Renew ${exp.length} expired item${exp.length === 1 ? '' : 's'} (certificates, warranties, subscriptions)`, why: 'Expired certificates break services; expired warranties and subscriptions leave gaps in support and protection.', count: exp.length, affected: exp.map(r => ({ t: r.what, d: `${r.asset} · expired ${-r.days} days ago`, link: r.ref || null })), fix: ['Renew or replace each item, or record that it’s no longer needed.'], owner: OWNER.am, effort: 'quick', page: 'lifecycle', check: null });
    const soon = life.rows.filter(r => r.days >= 0 && r.days <= 30);
    if (soon.length) add({ key: 'renewsoon', cat: 'Renewals', risk: 'low', title: `Renew ${soon.length} item${soon.length === 1 ? '' : 's'} due in the next 30 days`, why: 'Renewing before expiry avoids outages and support gaps.', count: soon.length, affected: soon.map(r => ({ t: r.what, d: `${r.asset} · in ${r.days} days`, link: r.ref || null })), fix: ['Quote and renew before the date.'], owner: OWNER.am, effort: 'quick', page: 'lifecycle', check: null });
  }

  // ---------- Licences ----------
  if (lic) for (const a of lic.actions.filter(a => a.sev === 'bad'))
    add({ key: `lic-${a.a.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60)}`, cat: 'Licences', risk: 'medium', title: a.a.replace(/\.$/, ''), why: a.b, count: 1, affected: [], fix: [a.a], owner: OWNER.am, effort: 'quick', page: 'licences', check: null });

  // ---------- Evidence: inspectors that aren't reporting ----------
  if (ih) {
    const failing = ih.rows.filter(r => r.health === 'Failing');
    if (failing.length) add({ key: 'failing', cat: 'Monitoring', risk: 'medium', title: `Fix ${failing.length} Liongard inspector${failing.length === 1 ? '' : 's'} that ${failing.length === 1 ? 'is' : 'are'} failing`, why: 'While an inspector fails, problems in that tool can’t be seen: this list may be missing items.', count: failing.length, affected: failing.map(r => ({ t: r.name, d: r.why, link: { systemId: r.systemId, systemDetailId: r.systemDetailId } })), fix: ['Open each launchpoint in Liongard and fix the credentials or agent it reports.'], owner: OWNER.desk, effort: 'quick', page: 'inspectors', check: 'evidence' });
  }

  // ---------- Rank ----------
  // Score = risk + a little for scale (log of what's affected) + a little for quick wins at the same risk.
  for (const a of actions) a.score = RISK[a.risk] + Math.min(15, Math.round(Math.log2(1 + a.count) * 4)) + (a.effort === 'quick' ? 3 : 0);
  actions.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  // Statuses saved on this computer (done, in progress, accepted risk, not applicable). An item marked done or accepted
  // reopens by itself when it gets worse (more affected than when it was marked), and says so.
  const saved = input.statuses || {};
  actions.forEach(a => {
    a.ownerLabel = a.owner; a.effortLabel = EFFORT[a.effort]; a.quickWin = a.effort === 'quick' && (a.risk === 'critical' || a.risk === 'high');
    const st = saved[a.key];
    a.status = st ? st.status : 'open'; a.statusAt = st ? st.at : null; a.ticket = st && st.status === 'ticketed' ? st.ticket || '' : '';
    // Marked done before this data was pulled, and Liongard still finds it: say so (it reopens if it got worse, below).
    if (st && st.status === 'done' && P && new Date(P) > new Date(st.at)) a.verify = 'still';
    if (st && ['done', 'accepted', 'na'].includes(st.status) && st.count != null && a.count > st.count) { a.status = 'open'; a.reopened = `Reopened: ${a.count} affected now, ${st.count} when it was marked ${st.status === 'done' ? 'done' : st.status === 'accepted' ? 'accepted' : 'not applicable'} on ${String(st.at).slice(0, 10)}`; }
  });
  const isOpen = a => a.status === 'open' || a.status === 'progress' || a.status === 'ticketed';   // ticketed = open, worked in the PSA
  const all = actions, open = all.filter(isOpen);
  // Work done: items marked done that Liongard no longer finds. Confirmed only by data pulled after the mark;
  // marked after this pull, they wait for the next one. Nothing here is inferred for items nobody marked.
  const live = new Set(actions.map(a => a.key));
  const fixed = Object.entries(saved).filter(([k, st]) => st && st.status === 'done' && !live.has(k))
    .map(([key, st]) => ({ key, title: st.title || key, markedAt: st.at, confirmedAt: P && new Date(P) > new Date(st.at) ? P : null }))
    .sort((a, b) => String(b.markedAt).localeCompare(String(a.markedAt)));
  const n = r => open.filter(a => a.risk === r).length;
  const qw = open.filter(a => a.quickWin);
  const closed = all.filter(a => !isOpen(a));
  return {
    environment: input.environment, pulledOn: P, source: input.source, actions, missing, fixed,
    // Items added from the Compliance drill-down; their state is what the last Compliance load found (saved with them).
    remediation: Object.entries(input.remediation || {}).map(([id, r]) => ({ id, ...r, state: r.status === 'done' ? (['verified', 'reopened'].includes(r.state) ? r.state : 'awaiting') : r.state === 'fixed' ? 'fixed' : r.status })).sort((a, b) => ['Critical', 'High', 'Medium', 'Low'].indexOf(a.sev) - ['Critical', 'High', 'Medium', 'Low'].indexOf(b.sev)),
    // Tiles count open work (open or in progress); completed, accepted and not-applicable items are counted separately.
    kpis: [
      { k: 'Open actions', v: open.length, s: `${n('critical')} critical · ${n('high')} high · ${n('medium')} medium · ${n('low')} low`, sev: open.length ? (n('critical') ? 'bad' : 'warn') : 'ok' },
      { k: 'Critical', v: n('critical'), s: n('critical') ? 'Fix first' : 'None', sev: n('critical') ? 'bad' : 'ok' },
      { k: 'High', v: n('high'), s: n('high') ? 'Fix this week' : 'None', sev: n('high') ? 'warn' : 'ok' },
      { k: 'Quick wins', v: qw.length, s: 'Critical or high risk, quick to fix', sev: qw.length ? 'warn' : 'ok' },
      { k: 'Completed', v: closed.length, s: closed.length ? `${closed.filter(a => a.status === 'done').length} done · ${closed.filter(a => a.status === 'accepted').length} risk accepted · ${closed.filter(a => a.status === 'na').length} not applicable` : 'Nothing marked yet', sev: 'info' },
    ],
    summary: [
      open.length ? `${open.length} open action${open.length === 1 ? '' : 's'} for ${input.environment.Name}: ${n('critical')} critical, ${n('high')} high${closed.length ? `; ${closed.length} already completed or accepted` : ''}.` : all.length ? `All ${all.length} actions for ${input.environment.Name} are completed or accepted.` : 'Nothing to fix from the data Liongard has for this client.',
      open[0] ? `Start with: ${open[0].title}.` : '',
      all.some(a => a.reopened) ? `${all.filter(a => a.reopened).length} item${all.filter(a => a.reopened).length === 1 ? ' was' : 's were'} reopened because ${all.filter(a => a.reopened).length === 1 ? 'it' : 'they'} got worse since being marked done.` : '',
      qw.length ? `${qw.length} quick win${qw.length === 1 ? '' : 's'}: high-risk items that take minutes, not days.` : '',
      missing.length ? `Not included because the data couldn’t be read: ${missing.join(', ')}.` : '',
    ].filter(Boolean),
  };
}

module.exports = { id: 'actions', usesStack: true, partsOnly: true, collect, compute };
