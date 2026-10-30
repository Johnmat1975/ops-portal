// Licence reconciliation, per person: every seat and device-based product tied to one person, so it can be priced.
// Pure function. People come from Identity (one matcher for every page); their M365 licences from the M365 inspector,
// training, MFA and AI seats from the licence data, and their devices from Identity's people-and-devices links, each
// device priced with the RMM, EDR/AV, backup and app-control products Stack coverage sees on it.
// Price keys are the product names on the Subscriptions table, so one price list drives both.

const lc = s => String(s || '').trim().toLowerCase();
const local = e => lc(e).split('@')[0];
const hostKey = h => lc(h).split(/[.\s]/)[0];
const friendly = p => /^Microsoft_Teams_Enterprise/i.test(p) ? 'Microsoft Teams Enterprise' : p;
// Identity "sources" that aren't a seat of their own: directories, monitoring, and Liongard itself.
const NOT_A_SEAT = /^(active directory|microsoft 365|azure ad|entra|dark web|liongard|knowbe4|duo)/i;

function build({ data = {}, subs = [], id = null, cov = null, idState = 'ok' }) {
  const subBy = new Map(subs.map(s => [s.product, s]));
  const subOf = source => subs.find(s => s.source === source);
  // A device tool's Subscriptions row, by inspector (via) or product name: "CrowdStrike" → "CrowdStrike Falcon".
  // Never a Microsoft 365 SKU: "Microsoft Defender" on a device isn't the "Microsoft Defender Vulnerability Management" add-on.
  const subFor = t => subs.find(s => s.source !== 'Microsoft 365' && [t.via, t.name].filter(Boolean).some(n => lc(s.source) === lc(n) || lc(s.product).startsWith(lc(n))));
  const m365 = new Map(((data.m365 && data.m365.users) || []).map(u => [lc(u.upn), String(u.prod || '').split('|').map(s => s.trim()).filter(Boolean)]));
  const kbUsers = new Map(((data.kb4 && data.kb4.users) || []).filter(u => u.e).map(u => [lc(u.e), u]));
  const anth = new Set(((data.anthropic && data.anthropic.users) || []).map(u => lc(u.e)).filter(Boolean));
  // Duo by email or login name, never by display name (two people can share a name).
  const duoUsers = ((data.duo && data.duo.users) || []);
  const duoEmail = new Set(duoUsers.map(u => lc(u.e)).filter(Boolean)), duoLogin = new Set(duoUsers.map(u => lc(u.u)).filter(Boolean));
  const rows = (cov && cov.rows) || [];
  const covById = new Map(rows.filter(r => r.id != null).map(r => [String(r.id), r]));
  const covByHost = new Map(rows.map(r => [lc(r.host), r]));
  const covByShort = new Map(); for (const r of rows) { const k = hostKey(r.host); covByShort.set(k, covByShort.has(k) ? null : r); }   // ambiguous short names match nothing
  const covFor = d => (d.deviceId != null && covById.get(String(d.deviceId))) || covByHost.get(lc(d.host)) || covByShort.get(hostKey(d.host)) || null;
  const deviceTools = new Set(rows.flatMap(r => [...(r.rmm || []), ...(r.backups || []), ...(r.control || []), ...(r.agent || []), ...(r.products || []).filter(p => p.systemId)].flatMap(t => [lc(t.via), lc(t.name)]).filter(Boolean)));

  const userSeat = (group, product, extra = {}) => ({ group, product, unit: 'user', free: !!(subBy.get(product) && subBy.get(product).sev === 'none' && /free/i.test(subBy.get(product).note)), ...extra });

  // People: Identity's people and admin accounts when Identity is available, else the licensed Microsoft 365 users.
  const base = id && id.rows ? id.rows.filter(r => ['Person', 'Admin account'].includes(r.kind))
    .map(r => ({ key: String(r.id), name: r.name, email: lc(r.email || (/@/.test(r.username || '') ? r.username : '')), kind: r.kind, enabled: r.enabled, licences: r.licences || [], sources: r.sources || [], devices: r.devices || [] }))
    : [...m365.entries()].filter(([, p]) => p.length).map(([e, p]) => ({ key: e, name: ((data.m365.users || []).find(u => lc(u.upn) === e) || {}).n || e, email: e, kind: 'Person', enabled: true, licences: p.map(friendly), sources: [], devices: [] }));

  // One owner per device, so a device's seats are counted once: the person it's assigned to, else the most recent sign-in.
  // Everyone else linked to it sees it listed, "also used by", but not added to their total.
  const owner = new Map();
  for (const p of base) for (const d of p.devices) {
    if (d.shared) continue;
    const k = d.deviceId != null ? `id:${d.deviceId}` : `h:${lc(d.host)}`;
    const cur = owner.get(k), rank = x => [x.d.strength === 'assigned' ? 1 : 0, String(x.d.seen || '')];
    const me = { p, d };
    if (!cur || rank(me)[0] > rank(cur)[0] || (rank(me)[0] === rank(cur)[0] && (rank(me)[1] > rank(cur)[1] || (rank(me)[1] === rank(cur)[1] && p.name.localeCompare(cur.p.name) < 0)))) owner.set(k, me);
  }

  const people = base.map(p => {
    const seats = [];
    // Microsoft 365: the inspector's own assignments (free SKUs included) when the person is in it, else Identity's list.
    const prods = p.email && m365.has(p.email) ? m365.get(p.email).map(friendly) : p.licences;
    for (const x of prods) seats.push(userSeat('Microsoft 365', x));
    const kb = p.email && kbUsers.get(p.email);
    if (kb && lc(kb.s) !== 'archived' && subOf('KnowBe4')) seats.push(userSeat('Security training', subOf('KnowBe4').product));
    if (p.email && (duoEmail.has(p.email) || duoLogin.has(p.email) || duoLogin.has(local(p.email))) && subOf('Duo Security')) seats.push(userSeat('MFA', subOf('Duo Security').product));
    if (p.email && anth.has(p.email) && subOf('Anthropic')) seats.push(userSeat('AI', subOf('Anthropic').product, { usage: true }));
    // Any other tool the person has an account in (per-user SaaS). Device tools are priced per device below instead,
    // and without device data (no Stack coverage) a tool can't be told apart, so none is guessed.
    if (rows.length) for (const s of p.sources) if (!NOT_A_SEAT.test(s) && !deviceTools.has(lc(s)) && !seats.some(x => lc(x.product).startsWith(lc(s)))) seats.push(userSeat('Other accounts', s, { account: true }));

    const devices = p.devices.map(d => {
      const r = covFor(d);
      const k = d.deviceId != null ? `id:${d.deviceId}` : `h:${lc(d.host)}`;
      const own = owner.get(k);
      const alsoUsedBy = !d.shared && own && own.p !== p ? own.p.name : null;
      const notCounted = !!d.shared || !!alsoUsedBy;
      // A product is a billed seat when an inspected tool reports it (systemId) or the client has a subscription for it.
      // AV seen only in the device's own record with no subscription (built-in Microsoft Defender) is listed, never priced.
      const billable = t => !!(t.systemId || subFor(t));
      const tools = !r ? [] : [
        ...(r.rmm || []).map(t => ({ group: 'RMM', t })),
        ...(r.products || []).filter(billable).map(t => ({ group: 'EDR / AV', t })),
        ...(r.backups || []).map(t => ({ group: 'Backup', t })),
        ...(r.control || []).map(t => ({ group: 'App control', t })),
      ].map(({ group, t }) => ({ group, product: (subFor(t) || {}).product || t.name }));
      const alsoSeen = !r ? [] : (r.products || []).filter(t => !billable(t)).map(t => t.name);
      return { host: d.host, deviceId: d.deviceId ?? (r ? r.id : null), os: r ? r.os : null, kind: r ? r.kind : null, shared: !!d.shared, alsoUsedBy, strength: d.strength, sources: d.sources || [], alsoSeen,
        seats: [...new Map(tools.map(t => [`${t.group}|${t.product}`, { ...t, unit: 'device', device: d.host, shared: notCounted, alsoUsedBy }])).values()] };
    }).sort((a, b) => (a.shared || !!a.alsoUsedBy) - (b.shared || !!b.alsoUsedBy) || a.host.localeCompare(b.host));
    return { key: p.key, name: p.name, email: p.email, kind: p.kind, enabled: p.enabled, seats, devices };
  }).filter(p => p.seats.length || p.devices.length)
    .sort((a, b) => a.name.localeCompare(b.name));

  return { people, linked: people.some(p => p.devices.length), fromIdentity: !!(id && id.rows), idState };
}

module.exports = { build };
