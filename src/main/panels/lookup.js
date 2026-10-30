// Lookup: one search across people, devices and domains, with a card per system that knows about the item
// and a one-line plain-English summary. Built from the same data as the other panels, so answers agree.
const identity = require('./identity');
const UDM = require('./user-devices');
const coverage = require('./coverage');
const email = require('./email');
const ai = require('./ai');
const actions = require('./actions');

async function collect(api, env, have = {}) {
  const keys = ['id', 'cov', 'mail', 'ai'];
  const [id, cov, mail, aiRaw, devices] = await Promise.all([identity, coverage, email, ai].map((p, i) => have[keys[i]] || p.collect(api, env).catch(e => ({ error: e.message })))
    .concat(api.inventory('devices', env.ID).catch(() => [])));
  return {
    environment: env, id, cov, mail, ai: aiRaw,
    devices: devices.filter(d => d.InventoryState !== 'Archive').map(d => ({ host: d.Hostname, os: d.OperatingSystem, type: d.Type, model: d.Model, manufacturer: d.Manufacturer, serial: d.SerialNumber,
      ip: d.InternalIP, mac: d.MACAddress, lastSeen: d.LastSeen, lastUser: d.LastLoginUser, warranty: d.WarrantyExpiration, state: d.InventoryState, location: d.Location,
      inspectors: (d.Inspectors || []).map(i => i.Alias) })),
  };
}

const short = h => String(h || '').split('.')[0].toUpperCase();
const lc = s => String(s || '').toLowerCase();
const fmt = iso => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }); };
const ipText = v => String(v || '').replace(/[{}"]/g, '');

function compute(input) {
  const P = input.pulledOn, ok = r => r && !r.error;
  const extra = { pulledOn: P, stack: input.stack, policy: input.coveragePolicy, msp: input.msp, thresholds: input.thresholds };   // same inputs as the other pages, so answers agree
  const id = ok(input.id) ? identity.compute({ ...input.id, ...extra }) : null;
  const cov = ok(input.cov) ? coverage.compute({ ...input.cov, ...extra }) : null;
  const em = ok(input.mail) ? email.compute({ ...input.mail, ...extra }) : null;
  const aiM = ok(input.ai) ? ai.compute({ ...input.ai, pulledOn: P }) : null;
  const covBy = new Map(cov ? (cov.rows || [...cov.managed, ...cov.unmanaged]).map(r => [r.host, r]) : []);
  // A device "needs attention" only when an open Critical or High action covers it.
  // Same rules as the Action plan, plus Cyber security's "no EDR on a managed endpoint" (High).
  const hotDevices = new Set();
  try {
    const plan = actions.compute({ environment: input.environment, pulledOn: P, source: input.source, id: input.id, cov: input.cov, mail: input.mail, stack: input.stack, msp: input.msp, coveragePolicy: input.coveragePolicy, thresholds: input.thresholds });
    for (const a of plan.actions) if (['critical', 'high'].includes(a.risk)) for (const x of a.affected) if (x.link && x.link.deviceId != null) hotDevices.add(String(x.link.deviceId));
  } catch {}
  if (cov) for (const r of cov.managed || []) if (r.tools && r.tools.edr === 'bad' && !r.stale) hotDevices.add(String(r.id));
  const items = [];

  for (const p of id ? id.rows : []) {
    // Devices from every tool that records a user (Identity's People & devices), strongest link first.
    const devs = (p.devices || []).map(d => `${short(d.host)} (${d.strength === 'assigned' ? 'owner' : 'last sign-in'}${d.shared ? ', shared' : ''} · ${d.sources.join(', ')})`);
    const aiRow = aiM && aiM.rows.find(r => r.email === lc(p.email));
    const sections = [
      { h: 'Directory', kv: [['Email', p.email || '—'], ['Status', p.enabled ? 'Enabled' : 'Disabled'], ['Activity', p.activity || '—'], ['Last sign-in', p.lastLogin ? `${fmt(p.lastLogin)} (${p.days} days ago)` : '—'], ['Seen by', p.sources.join(', '), p.sources]] },
      { h: 'Security', kv: [['MFA', p.mfa || 'Not reported'], ['Duo', p.duo === 'enrolled' ? 'Enrolled' : p.duo === 'not-enrolled' ? 'Not enrolled' : 'Not in Duo'], ['Privileged', p.privileged ? 'Yes' : 'No']] },
      { h: 'Licences', kv: p.licences.length ? p.licences.map(l => ['Licence', l]) : [['Licences', 'None']] },
    ];
    if (aiRow) sections.push({ h: 'AI platforms', kv: Object.entries(aiRow.platforms).map(([k, v]) => [k === 'anthropic' ? 'Claude' : 'ChatGPT', `${v.role}, ${v.keys} API key${v.keys === 1 ? '' : 's'}`]) });
    if (devs.length) sections.push({ h: 'Devices', kv: devs.map((d, i) => ['Device', d, p.devices[i].sources]) });
    const risks = [p.privileged && p.mfa === 'NO' && 'privileged with no MFA', p.duo === 'not-enrolled' && 'not enrolled in Duo', !p.enabled && p.licences.length && 'disabled but licensed', /dormant/i.test(p.activity) && 'dormant'].filter(Boolean);
    if (p.admin && p.admin.length) sections.push({ h: 'Admin rights', kv: p.admin.map(a => [a.inspector, a.role || 'Admin']) });
    if ((p.mfaMissingIn || []).length || (p.otherAccess || []).length || p.stale) sections.push({ h: 'To check', kv: [
      ...((p.mfaMissingIn || []).length ? [['No MFA in', p.mfaMissingIn.join(', ')]] : []), ...((p.otherAccess || []).length ? [['Disabled, still in', p.otherAccess.join(', ')]] : []),
      ...(p.stale ? [['Stale', p.lastLogin ? `Last sign-in ${fmt(p.lastLogin)}` : 'Never signed in']] : [])] });
    items.push({ kind: 'Person', key: p.email || p.name, label: p.name, sub: [p.email, p.kind !== 'Person' && p.kind, p.msp && 'MSP'].filter(Boolean).join(' · '), sections, link: p.id ? { identityId: p.id } : null, page: 'identity',
      answer: `${p.name} is ${p.enabled ? 'an active' : 'a disabled'} account seen by ${p.sources.length} system${p.sources.length === 1 ? '' : 's'}${p.licences.length ? `, licensed for ${p.licences.length} product${p.licences.length > 1 ? 's' : ''}` : ''}${p.mfa === 'YES' ? ', with MFA' : p.mfa === 'NO' ? ', with no MFA' : ''}.${risks.length ? ` Watch: ${risks.join(', ')}.` : ''}`,
      risk: risks.length > 0 });
  }

  for (const d of input.devices.filter(d => d.host)) {
    const c = covBy.get(short(d.host));
    const sections = [
      { h: 'Device', kv: [['Hostname', d.host], ['Type', [d.type, d.manufacturer, d.model].filter(Boolean).join(' · ') || '—'], ['OS', (c && c.osRaw) || d.os || '—'], ['IP', ipText(d.ip) || '—'], ['Serial', d.serial || '—'], ['Location', d.location || '—']] },
      { h: 'Seen by', kv: [['Inspectors', d.inspectors.join(', ') || '—', d.inspectors], ['Last seen', d.lastSeen ? fmt(d.lastSeen) : '—'], ['Last user', d.lastUser || '—'], ['Inventory state', d.state]] },
    ];
    // Who uses it, from every tool that records a user.
    const ud = id && id.userDevices && id.userDevices.devices.find(x => UDM.hostKey(x.host) === UDM.hostKey(d.host));
    if (ud && ud.links.length) sections.push({ h: 'Used by', kv: ud.links.slice(0, 8).map(l => [l.source, `${l.personId ? (id.rows.find(r => r.id === l.personId) || {}).name || l.user : l.user}${l.strength === 'assigned' ? ' (owner)' : ' (last sign-in)'}${l.kind === 'builtin' ? ', built-in account' : l.kind === 'account' ? ', admin account' : ''}`, [l.source]]) });
    if (c) sections.push({ h: 'Protection and tools', kv: [['Protection', c.products && c.products.length ? `${c.products.map(p => p.name).join(', ')} (${({ edr: 'EDR', av: 'AV only', off: 'off', none: 'none', unknown: 'unknown' })[c.protection] || c.protection})` : 'None reported', (c.products || []).map(p => p.name)],
      ['RMM / MDM', (c.rmm || []).map(x => x.name).join(', ') || '—', (c.rmm || []).map(x => x.name)], ['Backup', (c.backups || []).map(x => x.name).join(', ') || '—', (c.backups || []).map(x => x.name)], ['Other tools', [...(c.control || []), ...(c.agent || [])].map(x => x.name).join(', ') || '—', [...(c.control || []), ...(c.agent || [])].map(x => x.name)],
      ['Managed', c.managed ? 'Yes' : 'No'], ['Notes', c.notes.join('. ') || 'Meets the coverage policy']] });
    if (d.warranty) sections.push({ h: 'Lifecycle', kv: [['Warranty', fmt(d.warranty)]] });
    items.push({ kind: 'Device', key: d.host, label: short(d.host), link: c && c.id ? { deviceId: c.id } : null, page: 'coverage', sub: [d.type, (c && c.os) || d.os].filter(Boolean).join(' · '), sections,
      answer: `${short(d.host)} is ${c ? (c.managed ? 'a managed' : 'an unmanaged') : 'a'} ${d.type || 'device'} seen by ${d.inspectors.length} inspector${d.inspectors.length === 1 ? '' : 's'}${d.lastSeen ? `, last seen ${fmt(d.lastSeen)}` : ''}.${c && c.notes.length ? ` ${c.notes[0]}.` : ''}`,
      // Flag real problems only (unmanaged, a required tool missing, unsupported OS, protection off); every note still shows in the profile.
      risk: !!(c && hotDevices.has(String(c.id))) });
  }

  for (const d of em ? em.domains : []) {
    items.push({ kind: 'Domain', key: d.name, label: d.name, sub: `Grade ${d.grade}`, link: d.sys ? { systemId: d.sys.systemId, systemDetailId: d.sys.systemDetailId } : null, page: 'email', sections: [
      { h: 'Email security', kv: [['Sends email', d.sends ? `Yes${d.mailVendor ? ` (${d.mailVendor})` : ''}` : 'Not detected'], ['SPF', d.spf[2]], ['DKIM', d.dkim[2]], ['DMARC', d.dmarc[2]], ['DNSSEC', d.dnssec === 'pass' ? 'On' : 'Off']] },
      { h: 'Registration and certificate', kv: [['Registrar', d.registrar || '—'], ['Renews', d.regExpires ? fmt(d.regExpires) : '—'], ['Certificate', d.cert[1]]] },
      { h: 'What to fix', kv: d.fix.length ? d.fix.map(f => ['Fix', f]) : [['Fix', 'Nothing']] },
    ], answer: `${d.name} grades ${d.grade}: DMARC ${d.dmarc[2].toLowerCase()}, SPF ${d.spf[2].toLowerCase()}.${d.fix[0] ? ` First fix: ${d.fix[0]}.` : ''}`, risk: d.grade !== 'A' });
  }
  items.sort((a, b) => a.label.localeCompare(b.label));
  return { environment: input.environment, pulledOn: P, source: input.source, items,
    // "Accounts", not "People": every account is searchable here (disabled, service, shared, guests), while "People" on
    // Identity & access counts active people and admin accounts only.
    kpis: ['Person', 'Device', 'Domain'].map(k => ({ k: `${k === 'Person' ? 'Accounts' : k + 's'}`, v: items.filter(i => i.kind === k).length,
      s: k === 'Person' && id ? `${id.rows.filter(r => r.enabled && (r.kind === 'Person' || r.kind === 'Admin account')).length} active people (as on Identity) · ${items.filter(i => i.kind === k && i.risk).length} need attention`
        : k === 'Device' ? `${items.filter(i => i.kind === k && i.risk).length} with a critical or high action` : `${items.filter(i => i.kind === k && i.risk).length} need attention`, sev: 'info' })) };
}

module.exports = { id: 'lookup', usesStack: true, collect, compute };
