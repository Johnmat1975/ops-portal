// Network & firmware: firewall health and security services, firmware drift across identical models, and network admin accounts.
const { pMap } = require('../api');

const FW_Q = {
  'SonicWall': '{name: SystemInfo._SystemName, model: SystemInfo.Model, fw: SystemInfo.FirmwareVersion, prev: SystemInfo.PreviousFirmwareVersion, ' +
    'ha: HighAvailabilityStatus.{status: Status, mode: HaMode}, gav: GatewayAntivirus.Enable, ' +
    'suite: LicenseStatus.SecuritySuite[?Expiration].{n: SecurityService, exp: Expiration}, svc: LicenseStatus.SecurityServices[?Expiration].{n: SecurityService, exp: Expiration}}',
  'Barracuda Firewall': '{name: SystemInfo.hostname, model: SystemInfo.appliance, fw: SystemInfo.release, enc: SystemInfo.isdiskencrypted, health: Health, ' +
    'subs: SecuritySubscriptions[?expires > `0`].{n: description, status: status, exp: expiresOn}, admins: Admins[].{n: name, full: fullName, roles: roles, auth: authenticationLevel, enabled: enabled}}',
  'Cisco Meraki': '{licExp: LicensingOverview.expirationDate, licStatus: LicensingOverview.status, users: Users[].{n: name, e: email, org: orgAccess, type: UserType, mfa: twoFactorAuthEnabled, status: UserStatus}}',
};
const FIREWALLISH = /firewall|sonicwall|fortinet|fortigate|watchguard|pfsense|palo alto|sophos xg|opnsense|checkpoint|cisco asa/i;   // vendors without detailed checks yet

async function collect(api, env) {
  const [sys, devices, ids] = await Promise.all([api.systems(env.ID), api.inventory('devices', env.ID), api.inventory('identities', env.ID)]);
  const fwSys = sys.filter(s => s.enabled && s.systemDetailId && FW_Q[s.inspector]);
  const fw = await pMap(fwSys, 6, async s => ({ inspector: s.inspector, system: s.name, systemId: s.systemId, systemDetailId: s.systemDetailId, inspectedOn: s.inspectedOn,
    d: await api.evaluate(s.systemDetailId, FW_Q[s.inspector]).catch(err => ({ _error: String(err.message || err) })) }));   // unknown, never "off"
  return {
    environment: env, fw,
    otherNetwork: sys.filter(s => s.enabled && FIREWALLISH.test(s.inspector || '') && !FW_Q[s.inspector]).map(s => ({ inspector: s.inspector, system: s.name, inspectedOn: s.inspectedOn })),
    // Network gear only: servers and PCs report BIOS versions as firmware, which isn't drift worth tracking here.
    devices: devices.filter(d => d.InventoryState !== 'Archive' && d.Firmware && d.Model && !/workstation|server|desktop|laptop/i.test(`${d.Type} ${d.Role}`) && !/virtual machine|standard pc/i.test(d.Model)).map(d => ({ host: d.Hostname, model: d.Model, fw: d.Firmware, type: d.Type, category: d.Category, warranty: d.WarrantyExpiration })),
    emails: ids.map(i => String(i.Email || '').toLowerCase()).filter(Boolean),
  };
}

const parse = s => { const d = new Date(String(s || '').replace(/ UTC$/, '')); return isNaN(d) || d.getUTCFullYear() < 2000 ? null : d; };
const fmt = d => d ? d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : '';

function compute(input) {
  const now = input.pulledOn ? new Date(input.pulledOn) : new Date();
  const days = d => d ? Math.floor((d - now) / 864e5) : null;
  const cards = [], admins = [];
  const meraki = input.fw.find(f => f.inspector === 'Cisco Meraki');

  // Liongard's flags arrive as booleans or as "True"/"Enabled" strings; a missing flag is unknown, not off.
  const flag = v => v == null || v === '' ? null : v === true || v === 1 || /^(true|yes|on|enabled|1)$/i.test(String(v).trim());
  const onOff = (v, offText = 'Off') => flag(v) === true ? ['On', 'ok'] : flag(v) === false ? [offText, 'bad'] : ['Not reported', 'none'];
  for (const f of input.fw) {
    const d = f.d || {}, rows = [];
    // A dataprint that couldn't be read (or an empty one, from caches before 0.5) says nothing about the firewall.
    if (d._error || !Object.keys(d).length) {
      cards.push({ name: f.inspector, site: f.system, rows: [['Data', `Couldn’t read this ${f.inspector} from Liongard, so its settings are unknown. Refresh to try again.`, 'none']], f, unread: true });
      continue;
    }
    if (f.inspector === 'SonicWall') {
      rows.push(['Firmware', d.fw ? d.fw + (d.prev && !String(d.fw).includes(d.prev) ? ` (was ${d.prev})` : '') : 'Not reported', 'none']);
      rows.push(['High availability', /disabled|none/i.test(`${d.ha && d.ha.status} ${d.ha && d.ha.mode}`) ? 'Not configured' : (d.ha && d.ha.status) || 'Unknown', /disabled|none/i.test(`${d.ha && d.ha.status} ${d.ha && d.ha.mode}`) ? 'bad' : d.ha && d.ha.status ? 'ok' : 'none']);   // unknown isn't good news
      const gavLicensed = (d.suite || []).some(s => /gateway av/i.test(s.n));
      const [gavText, gavSev] = onOff(d.gav, gavLicensed ? 'Off, though licensed' : 'Off');
      rows.push(['Gateway anti-virus', gavText, gavSev]);
      const suiteExp = (d.suite || []).map(s => parse(s.exp)).filter(Boolean).sort((a, b) => a - b)[0];
      if (suiteExp) rows.push(['Security suite', days(suiteExp) < 0 ? `Ended ${fmt(suiteExp)}` : `Licensed to ${fmt(suiteExp)}`, days(suiteExp) < 0 ? 'bad' : days(suiteExp) <= 90 ? 'warn' : 'ok']);
      const support = (d.svc || []).find(s => /support/i.test(s.n));
      if (support) rows.push(['Support and firmware updates', `To ${fmt(parse(support.exp))}`, days(parse(support.exp)) < 0 ? 'bad' : 'ok']);
      cards.push({ name: `SonicWall ${d.model || ''}`.trim(), site: d.name || f.system, rows, f });
    } else if (f.inspector === 'Barracuda Firewall') {
      rows.push(['Firmware', d.fw || '—', 'none']);
      const HL = { serverState: 'server', procState: 'processes', diskState: 'disk', systemState: 'system', netState: 'network', eventOperativeState: 'operational events', eventSecurityState: 'security events', licState: 'licence' };
      const errs = Object.entries(d.health || {}).filter(([, v]) => v === 'error').map(([k]) => HL[k] || k.replace(/State$/, ''));
      rows.push(['Health', errs.length ? `Errors: ${errs.join(', ')}` : 'OK', errs.length ? 'bad' : 'ok']);
      const subs = d.subs || [];
      const ended = subs.map(s => parse(s.exp)).filter(x => x && days(x) < 0).sort((a, b) => b - a)[0];
      const next = subs.map(s => parse(s.exp)).filter(x => x && days(x) >= 0).sort((a, b) => a - b)[0];
      rows.push(['Security subscriptions', ended ? `Ended ${fmt(ended)}` : next ? `To ${fmt(next)}` : 'None found', ended ? 'bad' : next && days(next) <= 90 ? 'warn' : 'ok']);
      const mal = subs.find(s => /malware/i.test(s.n)); if (mal) rows.push(['Malware protection', /disabled/i.test(mal.status) ? 'Licensed but disabled' : mal.status, /disabled/i.test(mal.status) ? 'warn' : 'ok']);
      const ips = subs.find(s => /^ips/i.test(s.n)); if (ips) rows.push(['IPS', /active/i.test(ips.status) ? 'Active' : ips.status, /active/i.test(ips.status) ? 'ok' : 'warn']);
      rows.push(['Disk encryption', ...onOff(d.enc)]);
      for (const a of d.admins || []) admins.push({ name: a.full || a.n, login: a.n, where: f.system, access: (a.roles || []).join(', '), mfa: /password$/i.test(a.auth || '') ? 'NO' : null, inDirectory: null });
      cards.push({ name: `Barracuda ${d.model || ''}`.trim(), site: d.name || f.system, rows, f });
    } else if (f.inspector === 'Cisco Meraki') {
      for (const u of d.users || []) admins.push({ name: u.n, login: u.e, where: 'Meraki dashboard', access: u.org === 'full' ? 'Full organisation' : u.org === 'read-only' ? 'Read-only organisation' : u.type === 'Network Level' ? 'Network level' : 'None', mfa: u.mfa === true ? 'YES' : u.mfa === false ? 'NO' : null, inDirectory: input.emails.includes(String(u.e || '').toLowerCase()) });
    }
  }
  // Meraki MX appliances come from the device inventory (firmware, warranty) plus the org licence.
  const licExp = meraki && parse(meraki.d && meraki.d.licExp);
  for (const dv of input.devices.filter(x => /^MX\d/i.test(x.model))) {
    const w = parse(dv.warranty);
    const rows = [['Firmware', dv.fw, 'none']];
    if (licExp) rows.push(['Licence', `Co-term to ${fmt(licExp)}`, days(licExp) < 0 ? 'bad' : days(licExp) <= 90 ? 'warn' : 'ok']);
    if (w) rows.push(['Warranty', days(w) < 0 ? `Ended ${fmt(w)}` : `To ${fmt(w)}`, days(w) < 0 ? 'bad' : 'ok']);
    cards.push({ name: `Meraki ${dv.model}`, site: dv.host, rows });
  }
  // Every other network device the client runs: a card built from Liongard's metrics, whatever the vendor.
  const st = input.stack;
  const ROW = /firmware|software version|model|licen[cs]|subscription|expir|offline|online|devices? (down|count)|failover|high availab|\bha\b|intrusion|\bips\b|anti.?virus|gateway|warranty|outdated|pending|admin/i;
  if (st) {
    const { display, plain: shortName } = require('../metric-signals');   // display names without "Count"/"List"
    const detailed = new Set(input.fw.map(f => f.systemId));
    for (const sys of st.systems.filter(x => x.caps.includes('network') && x.health !== 'Inactive' && !detailed.has(x.systemId) && !/DNS filtering|Web security|Public IP/.test(x.role))) {
      const metrics = (st.metricsBySys.get(sys.systemId) || []).filter(mm => ROW.test(mm.n) && (typeof mm.v !== 'object' || mm.v === null));
      const found = st.findings.filter(x => x.systemId === sys.systemId);
      const rows = [...new Map(metrics.map(mm => [shortName(mm.n).toLowerCase(), [shortName(mm.n), display(mm.v, mm.n)]])).values()].filter(([k]) => !found.some(f => f.label.toLowerCase() === k.toLowerCase())).slice(0, 10).map(([k, v]) => [k, v, 'none']);
      for (const f of found) rows.unshift([f.label, String(f.value), f.sev === 'bad' ? 'bad' : 'warn']);
      for (const e of st.expiries.filter(x => x.systemId === sys.systemId && x.days <= 90)) rows.unshift([e.label, e.days < 0 ? `Ended ${fmt(new Date(e.date))}` : `To ${fmt(new Date(e.date))}`, e.days < 0 ? 'bad' : 'warn']);
      if (sys.health === 'Failing' || sys.health === 'Stale') rows.unshift(['Inspector', `${sys.health}: ${sys.why || ''}`.trim(), 'bad']);
      if (!rows.length) rows.push(['Last good data', sys.lastGood ? fmt(new Date(sys.lastGood)) : 'Never', sys.lastGood ? 'none' : 'bad']);
      cards.push({ name: sys.inspector, site: sys.name, role: sys.role, rows, f: { systemId: sys.systemId, systemDetailId: sys.systemDetailId }, generic: true });
    }
  } else for (const o of input.otherNetwork) cards.push({ name: o.inspector, site: o.system, rows: [['Last inspected', o.inspectedOn ? fmt(new Date(o.inspectedOn)) : 'Never', o.inspectedOn ? 'none' : 'bad']] });
  for (const c of cards) c.flag = c.rows.some(r => r[2] === 'bad') ? 'crit' : c.rows.some(r => r[2] === 'warn') ? 'warn' : 'ok';

  // Firmware drift: same model on more than one firmware version.
  const byModel = new Map();
  for (const dv of input.devices) { const g = byModel.get(dv.model) || []; g.push(dv); byModel.set(dv.model, g); }
  const firmware = [...byModel].map(([model, ds]) => {
    const versions = [...new Set(ds.map(x => x.fw))];
    return { model, versions, devices: ds.map(x => String(x.host).split('.')[0]), status: ds.length === 1 ? 'Single device' : versions.length > 1 ? 'Drift' : 'Consistent' };
  }).sort((a, b) => ({ Drift: 0, Consistent: 1, 'Single device': 2 }[a.status] - { Drift: 0, Consistent: 1, 'Single device': 2 }[b.status]) || a.model.localeCompare(b.model));

  for (const a of admins) {
    const notes = [];
    if (a.inDirectory === false) notes.push('Not in the client’s directory (M365, AD or Duo). Check whether this person still needs access');
    if (a.access === 'None') notes.push('No access granted, but the account still exists');
    if (/^(support|internalit|it|admin|helpdesk)@/i.test(a.login || '')) notes.push('Shared mailbox account');
    if (a.mfa == null && /barracuda/i.test(a.where)) notes.push('Password-only login reported by the inspector');
    a.notes = notes.join('. ');
  }
  const issues = cards.filter(c => c.flag === 'crit');
  const drift = firmware.filter(f => f.status === 'Drift');
  const noMfa = admins.filter(a => a.mfa === 'NO' && a.access !== 'None');
  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source,
    kpis: [
      { k: 'Network devices', v: cards.length, s: `${new Set(cards.map(c => c.name.split(' ')[0])).size} vendors`, sev: 'info' },
      { k: 'With issues', v: issues.length, s: issues.length ? issues.map(c => c.name).join(', ') : 'None', sev: issues.length ? 'bad' : 'ok' },
      { k: 'Models with firmware drift', v: drift.length, s: drift.length ? drift.map(f => f.model).join(', ') : 'All consistent', sev: drift.length ? 'warn' : 'ok' },
      // No admin data at all is unknown (—), not a green zero.
      admins.length ? { k: 'Network admins without MFA', v: noMfa.length, s: `${admins.length} admin accounts in total`, sev: noMfa.length ? 'bad' : 'ok' } : { k: 'Network admins without MFA', v: '—', s: 'No network admin data from these inspectors', sev: 'info' },
    ],
    cards: cards.map(c => ({ name: c.name, site: c.site, role: c.role || (/meraki/i.test(c.name) ? 'Firewall & Wi-Fi' : 'Firewall'), rows: c.rows, flag: c.flag, generic: !!c.generic, unread: !!c.unread, systemId: c.f && c.f.systemId, systemDetailId: c.f && c.f.systemDetailId })),
    summary: [
      `${cards.length} network device${cards.length === 1 ? '' : 's'} monitored (${[...new Set(cards.map(c => c.name.split(' ')[0]))].slice(0, 6).join(', ')}).`,
      issues.length ? `${issues.length} need${issues.length === 1 ? 's' : ''} attention: ${issues.slice(0, 4).map(c => c.site || c.name).join(', ')}${issues.length > 4 ? ' and more' : ''}.` : 'No critical findings on any network device.',
      drift.length ? `Firmware differs across identical ${drift.map(f => f.model).join(', ')} devices.` : '',
      noMfa.length ? `${noMfa.length} network admin account${noMfa.length > 1 ? 's have' : ' has'} no MFA.` : '',
    ].filter(Boolean),
    firmware, admins,
  };
}

module.exports = { id: 'network', usesStack: true, collect, compute };
