// Lifecycle & renewals: warranties, OS support, security subscriptions, licences, certificates and domains on one timeline.
const { pMap } = require('../api');
const { osSupport } = require('../catalog');
const { utcDate } = require('../metric-signals');
const email = require('./email');

// Vendor subscription dates, by inspector alias. Each returns rows of {n, exp, status?}.
const SUBS = {
  // Liongard's JMESPath doesn't flatten a multiselect list here, so SonicWall returns two lists that are merged below.
  'SonicWall': '{a: LicenseStatus.SecuritySuite[?Expiration].{n: SecurityService, exp: Expiration, status: SecurityStatus}, b: LicenseStatus.SecurityServices[?Expiration].{n: SecurityService, exp: Expiration, status: SecurityStatus}}',
  'Barracuda Firewall': 'SecuritySubscriptions[?expires > `0`].{n: description, exp: expiresOn, status: status}',
  'Cisco Meraki': '[LicensingOverview.{n: \'Meraki co-term licence\', exp: expirationDate, counts: licensedDeviceCounts}]',
  'KnowBe4': '[AccountInfo.{n: join(\' \', [\'KnowBe4\', subscription_level]), exp: subscription_end_date, seats: number_of_seats}]',
};

async function collect(api, env) {
  const [devices, sys, mail] = await Promise.all([api.inventory('devices', env.ID), api.systems(env.ID), email.collect(api, env)]);
  const subSys = sys.filter(s => s.enabled && s.systemDetailId && SUBS[s.inspector]);
  const subs = await pMap(subSys, 6, async s => ({ inspector: s.inspector, system: s.name, systemId: s.systemId, systemDetailId: s.systemDetailId,
    rows: flat(await api.evaluate(s.systemDetailId, SUBS[s.inspector]).catch(() => [])) }));
  return {
    environment: env, mail, subs,
    devices: devices.filter(d => d.InventoryState !== 'Archive').map(d => ({ host: d.Hostname, os: d.OperatingSystem, type: d.Type, model: d.Model, manufacturer: d.Manufacturer,
      warranty: d.WarrantyExpiration, eol: d.EOLDate, licence: d.LicenseExpiration, state: d.InventoryState })),
  };
}

const flat = v => Array.isArray(v) ? v : v && typeof v === 'object' ? Object.values(v).flatMap(x => Array.isArray(x) ? x : []) : [];
const parseDate = s => { if (!s) return null; const d = utcDate(s); return !d || d.getUTCFullYear() < 2000 ? null : d.toISOString().slice(0, 10); };
const short = h => String(h || '').split('.')[0];
const list = (a, n = 4) => a.length > n ? `${a.slice(0, n).join(', ')} and ${a.length - n} more` : a.join(', ');

function compute(input) {
  const now = input.pulledOn ? new Date(input.pulledOn) : new Date();
  const ev = [];
  const add = (date, type, what, asset, source, note = '', ref = null) => { const d = parseDate(date); if (d) ev.push({ date: d, type, what, asset, source, note, ref }); };

  // Hardware warranty and vendor end-of-life, grouped by date + model so a fleet shows as one line.
  const group = (field, type, label) => {
    const g = new Map();   // one line per date, listing the models, so a fleet renewal shows once
    for (const d of input.devices) { const dt = parseDate(d[field]); if (!dt) continue; g.set(dt, [...(g.get(dt) || []), d]); }
    for (const [dt, ds] of g) { const models = [...new Set(ds.map(d => d.model).filter(Boolean))]; add(dt, type, `${label}${models.length ? ` (${list(models, 5)})` : ''}`, list(ds.map(d => short(d.host))), 'Device inventory', ds.length > 1 ? `${ds.length} devices` : ''); }
  };
  group('warranty', 'Warranty', 'Hardware warranty');
  group('eol', 'End of life', 'Vendor end of life');
  group('licence', 'Licence', 'Device licence');

  // OS support, grouped by OS release.
  const os = new Map();
  for (const d of input.devices) { if (!/workstation|server/i.test(d.type || '') && !/windows|^10\.0/i.test(d.os || '')) continue; const s = osSupport(d.os); if (!s) continue; const k = `${s.label}|${s.entDate || s.date}`; os.set(k, { s, hosts: [...((os.get(k) || {}).hosts || []), short(d.host)] }); }
  for (const { s, hosts } of os.values()) add(s.entDate || s.date, 'OS support', `${s.label} end of support${s.entDate ? ' (Enterprise/Education; Home/Pro ended ' + fmt(s.date) + ')' : ''}`, list(hosts), 'Microsoft lifecycle', `${hosts.length} device${hosts.length > 1 ? 's' : ''}`);

  // Vendor subscriptions, grouped by system + date.
  for (const s of input.subs) {
    const byDate = new Map();
    for (const r of (s.rows || []).filter(Boolean)) { const d = parseDate(r.exp); if (!d || /not (licensed|purchased)/i.test(r.status || '')) continue; byDate.set(d, [...(byDate.get(d) || []), r]); }
    for (const [d, rows] of byDate) add(d, s.inspector === 'KnowBe4' ? 'Licence' : 'Subscription', rows.length > 1 ? `${s.inspector} subscriptions: ${list(rows.map(r => r.n), 5)}` : rows[0].n, s.system, `${s.inspector} dataprint`,
      rows[0].seats ? `${rows[0].seats} seats` : rows[0].counts ? Object.entries(rows[0].counts).map(([k, v]) => `${v} ${k}`).join(', ') : '', { systemId: s.systemId, systemDetailId: s.systemDetailId });
  }

  // A device-licence line on the same date as a vendor licence (e.g. Meraki co-term) is the same renewal: keep the vendor line.
  const subDates = new Set(ev.filter(e => e.source.endsWith('dataprint')).map(e => e.date));
  for (let i = ev.length - 1; i >= 0; i--) if (ev[i].type === 'Licence' && ev[i].source === 'Device inventory' && subDates.has(ev[i].date)) ev.splice(i, 1);

  // Certificates and domains, from the email panel's data.
  const m = email.compute({ ...input.mail, pulledOn: input.pulledOn });
  for (const d of m.domains) {
    const certExp = (input.mail.tls || []).find(t => String(t.name).toLowerCase() === d.name);
    if (certExp && certExp.expires) add(certExp.expires, 'Certificate', 'TLS certificate', d.name, 'TLS/SSL inspector', certExp.issuer || '');
    if (d.regExpires) add(d.regExpires, 'Domain', 'Domain registration', d.name, 'Internet Domain/DNS', d.registrar);
  }

  // Renewal dates from every other inspector, read from Liongard's metrics (licences, warranties, subscriptions on any vendor).
  if (input.stack) {
    const have = new Set(ev.map(e => `${e.date}|${String(e.asset).toLowerCase()}`));
    const DEEP = new Set(['TLS/SSL', 'Internet Domain/DNS', ...Object.keys(SUBS)]);
    const byKey = new Map();
    for (const x of input.stack.expiries.filter(x => !DEEP.has(x.inspector))) {
      const type = /warranty/i.test(x.label) ? 'Warranty' : /licen[cs]e/i.test(x.label) ? 'Licence' : /cert/i.test(x.label) ? 'Certificate' : 'Subscription';
      const k = `${x.date}|${x.inspector}|${type}`;   // one line per tool, date and type, so many devices on one date show once
      const g = byKey.get(k) || byKey.set(k, { x, type, labels: new Set(), systems: [] }).get(k);
      g.labels.add(x.label.replace(/^days until\s+/i, '').replace(/\s+expiration$/i, ' expiry')); g.systems.push(x);
    }
    for (const g of byKey.values()) {
      const asset = list([...new Set(g.systems.map(y => y.system))]);
      if (have.has(`${g.x.date}|${asset.toLowerCase()}`)) continue;
      add(g.x.date, g.type, `${g.x.inspector}: ${list([...g.labels], 3)}`, asset, `${g.x.inspector} (Liongard metric)`, '', g.systems.length === 1 ? { systemId: g.x.systemId, systemDetailId: g.x.systemDetailId } : null);
    }
  }

  const days = d => Math.round((Date.parse(d + 'T00:00:00Z') - now) / 864e5);
  const bucket = n => n < 0 ? 'Expired' : n <= 90 ? 'Next 90 days' : n <= 365 ? 'Next 12 months' : 'Later';
  const rows = ev.map(e => ({ ...e, days: days(e.date), bucket: bucket(days(e.date)) })).sort((a, b) => a.date.localeCompare(b.date));
  // Expired more than 2 years ago is history, not a renewal (keep OS support, which still matters).
  const shown = rows.filter(r => r.days > -730 || r.type === 'OS support');
  const c = b => shown.filter(r => r.bucket === b).length;
  const by = b => shown.filter(r => r.bucket === b);
  const types = arr => [...new Set(arr.map(r => r.type.replace(/^(?!OS\b)\w/, c => c.toLowerCase())))].join(', ');   // keep "OS" upper case
  const summary = [
    c('Expired') ? `${c('Expired')} item${c('Expired') > 1 ? 's have' : ' has'} already expired (${types(by('Expired'))}).` : 'Nothing has expired.',
    c('Next 90 days') ? `${c('Next 90 days')} renew${c('Next 90 days') === 1 ? 's' : ''} in the next 90 days: ${list(by('Next 90 days').map(r => `${r.what.split(':')[0]} (${fmt(r.date)})`), 3)}.` : 'Nothing renews in the next 90 days.',
    c('Next 12 months') ? `${c('Next 12 months')} more within 12 months, to quote and budget now.` : '',
    `Dates come from device inventory, Microsoft\u2019s lifecycle dates, vendor dataprints and Liongard metrics for every other tool.`,
  ].filter(Boolean);
  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, summary,
    kpis: [
      { k: 'Expired', v: c('Expired'), s: 'Already past the date', sev: c('Expired') ? 'bad' : 'ok' },
      { k: 'Next 90 days', v: c('Next 90 days'), s: 'Act this quarter', sev: c('Next 90 days') ? 'warn' : 'ok' },
      { k: 'Next 12 months', v: c('Next 12 months'), s: 'Budget and quote now', sev: 'info' },
      { k: 'Later', v: c('Later'), s: 'Tracked for planning', sev: 'info' },
    ],
    types: ['All', ...new Set(shown.map(r => r.type))],
    rows: shown,
  };
}

function fmt(d) { return new Date(d + 'T00:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }); }

module.exports = { id: 'lifecycle', usesStack: true, collect, compute };
