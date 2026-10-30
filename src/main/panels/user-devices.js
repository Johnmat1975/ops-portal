// People & devices: which person uses which device, from every tool that records it.
// Liongard's Asset Inventory only names a device's last user for some devices, so this also reads each RMM, EDR and MDM
// tool's own device list (one read-only query per tool). Every link says how strong it is:
//   assigned    the tool records the device's owner or primary user (MDM, Intune, phones)
//   last        the tool records who last signed in (RMM, EDR). Not proof of ownership: technicians sign in too.
// Field names verified against live dataprints on a Liongard test instance (Oct 2026).
const LINKS = {
  'Microsoft 365': { strength: 'assigned', query: 'ManagedIntuneDevices[].{host: deviceName, user: userPrincipalName || emailAddress, seen: lastSyncDateTime}' },
  'Iru': { strength: 'assigned', query: 'devices_index[].{host: device_name, user: user.email || user.name, name: user.name, seen: last_check_in}' },
  'ThreatLocker': { strength: 'assigned', query: 'mobileDevices[].{host: name, user: emailAddress || userName, seen: lastCheckIn}' },
  'ConnectWise Automate': { strength: 'last', query: 'Computers[].{host: ComputerName, user: LastUserName, seen: RemoteAgentLastContact}' },
  'Datto RMM': { strength: 'last', query: 'Devices[].{host: hostname, user: lastLoggedInUser, seen: lastSeen}' },
  'NinjaOne': { strength: 'last', query: 'Devices[].{host: systemName || dnsName, user: lastLoggedInUser, seen: lastContact}' },
  'Continuum RMM': { strength: 'last', query: 'Devices[].{host: machineName || hostName, user: lastLoginUser, seen: lastSeenOnline}' },
  'SentinelOne': { strength: 'last', query: 'Agents[].{host: computerName, user: lastLoggedInUserName || osUsername, seen: lastActiveDate}' },
  'Sophos Central': { strength: 'last', query: 'Endpoints[].{host: hostname, user: associatedPerson.viaLogin || associatedPerson.name, seen: lastSeenAt}' },
};

// One query per tool the client runs; a tool that fails is skipped (the rest still link).
async function collectLinks(api, systems) {
  const out = [];
  await Promise.all(Object.entries(LINKS).map(async ([inspector, def]) => {
    for (const s of systems.filter(x => x.enabled && x.inspector === inspector && x.systemDetailId)) {
      try {
        const rows = await api.evaluate(s.systemDetailId, def.query);
        for (const r of Array.isArray(rows) ? rows : []) if (r && r.host && r.user) out.push({ host: String(r.host), user: String(r.user), name: r.name || null, seen: r.seen ?? null, source: inspector, system: s.name, systemId: s.systemId, systemDetailId: s.systemDetailId, strength: def.strength });
      } catch { /* this tool's data couldn't be read; others still link */ }
    }
  }));
  return out;
}

const lc = s => String(s || '').toLowerCase().trim();
// Device names differ between tools ("CN-WS01", "cn-ws01.contoso.local"): compare the short, lower-case name.
const hostKey = h => lc(h).split(/[.\s]/)[0];
// Accounts that belong to the machine, not a person: built-ins, and "HOSTNAME\user" local accounts.
const BUILTIN_USER = /^(administrator|admin|guest|defaultaccount|wdagutilityaccount|system|local ?system|network service|root|user|owner|lgadmin|sbxadmin)$/i;
const toDate = v => {
  if (v == null || v === '') return null;
  if (typeof v === 'number') return new Date(v > 1e12 ? v : v * 1000);
  const d = new Date(v); return isNaN(d) ? null : d;
};

// Turn raw links into devices and per-person device lists. `find(userString)` resolves a person (Identity's own matcher).
function buildLinks({ links = [], inventory = [], find, rows, now = new Date() }) {
  const invByHost = new Map(inventory.map(d => [hostKey(d.host), d]));
  const rowById = new Map(rows.map(r => [r.id, r]));
  const devices = new Map();
  for (const l of links) {
    const hk = hostKey(l.host); if (!hk) continue;
    const raw = String(l.user).trim();
    const [dom, acct] = raw.includes('\\') ? raw.split('\\') : ['', raw];
    // Built-in accounts are the machine's, never a person's. A named local account ("PC-7\\gradya") still points to its person.
    const builtin = BUILTIN_USER.test(acct);
    const hit = builtin ? null : (find(raw) || (l.name && find(l.name)) || null);
    const row = hit && rowById.get(hit.id);
    // kind: person (a person's account), account (an admin/service/shared account), builtin, or unknown (no identity matches)
    const kind = builtin ? 'builtin' : !row ? 'unknown' : row.kind === 'Person' ? 'person' : 'account';
    const person = kind === 'person' ? hit : null;
    const seen = toDate(l.seen);
    const d = devices.get(hk) || devices.set(hk, { host: l.host, key: hk, inv: invByHost.get(hk) || null, links: [] }).get(hk);
    d.links.push({ user: raw, personId: person ? person.id : null, accountId: kind === 'account' ? hit.id : null, kind, localAccount: !!(dom && hostKey(dom) === hk), source: l.source, system: l.system, systemId: l.systemId, systemDetailId: l.systemDetailId, strength: l.strength, seen: seen ? seen.toISOString() : null });
  }
  const isServer = d => /server|domain controller|\bdc\d*\b/i.test(`${(d.inv || {}).os || ''} ${(d.inv || {}).type || ''} ${d.host}`) || /^(rds|srv|dc|sql|app|file|util)/i.test(d.key);
  const out = [...devices.values()].map(d => {
    const persons = [...new Set(d.links.map(x => x.personId).filter(Boolean))];
    const assigned = d.links.filter(x => x.strength === 'assigned' && x.personId);
    const shared = persons.length >= 3 || (isServer(d) && persons.length >= 1 && !assigned.length);
    // Most likely user: an assigned owner first, then the most recent sign-in.
    const best = assigned[0] || [...d.links].filter(x => x.personId).sort((a, b) => String(b.seen).localeCompare(String(a.seen)))[0] || null;
    const lastPersons = [...new Set(d.links.filter(x => x.strength === 'last' && x.personId).map(x => x.personId))];
    return {
      host: d.host, deviceId: d.inv ? d.inv.id : null, os: d.inv ? d.inv.os : null, type: d.inv ? d.inv.type : null,
      likely: best ? { personId: best.personId, name: (rowById.get(best.personId) || {}).name || best.user, strength: best.strength, source: best.source } : null,
      persons, shared, server: isServer(d),
      disagree: !shared && lastPersons.length >= 2,
      // No person at all: only built-in or admin/service accounts sign in, or the users aren't in the identity data.
      noPerson: !persons.length,
      unknownUsers: [...new Set(d.links.filter(x => x.kind === 'unknown').map(x => x.user))],
      adminUsers: [...new Set(d.links.filter(x => x.kind === 'account').map(x => (rowById.get(x.accountId) || {}).name || x.user))],
      links: d.links.sort((a, b) => (a.strength === 'assigned' ? 0 : 1) - (b.strength === 'assigned' ? 0 : 1) || String(b.seen).localeCompare(String(a.seen))),
      lastSeen: d.links.map(x => x.seen).filter(Boolean).sort().pop() || null,
    };
  }).sort((a, b) => a.host.localeCompare(b.host));

  // Per person: their devices, strongest link first. Shared servers are listed but marked, so they don't read as "theirs".
  const byPerson = new Map();
  for (const d of out) for (const pid of d.persons) {
    const ls = d.links.filter(x => x.personId === pid);
    const strength = ls.some(x => x.strength === 'assigned') ? 'assigned' : 'last';
    (byPerson.get(pid) || byPerson.set(pid, []).get(pid)).push({ host: d.host, deviceId: d.deviceId, strength, shared: d.shared, sources: [...new Set(ls.map(x => x.source))], seen: ls.map(x => x.seen).filter(Boolean).sort().pop() || null });
  }
  const sources = Object.entries(links.reduce((a, l) => (a[l.source] = (a[l.source] || 0) + 1, a), {})).map(([inspector, n]) => ({ inspector, n }));
  return { devices: out, byPerson, sources, linkedDevices: out.filter(d => d.persons.length).length };
}

module.exports = { LINKS, collectLinks, buildLinks, hostKey };
