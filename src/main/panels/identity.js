// Identity & access: every account Liongard reconciles across the client's identity sources, sorted into people, admin
// accounts, service accounts, shared mailboxes and guests. Adds what each system says about those people from Liongard's
// metrics: who is an admin where, who has no MFA in which system, who is disabled in one place but still present in others,
// stale accounts, guests, password hygiene, dark web exposure and overdue training. Plus Duo enrolment and bypass codes.
const DUO_Q = '{users: Users[].{u: username, e: email, enr: is_enrolled, last: last_login, status: status}, ' +
  'bypass: BypassCodes[].{u: user.username, e: user.email, exp: expiration, created: created, by: admin_email, reuse: reuse_count}, admins: Admins[].{n: name, e: email, role: role, last: last_login}}';
const DEFAULT_STALE_DAYS = 90;   // accounts with no sign-in for this long are stale (changeable in Settings)
const UD = require('./user-devices');

async function collect(api, env) {
  const [ids, sys, devices] = await Promise.all([api.inventory('identities', env.ID), api.systems(env.ID), api.inventory('devices', env.ID).catch(() => [])]);
  const duoSys = sys.find(s => s.enabled && s.inspector === 'Duo Security' && s.systemDetailId);
  const duo = duoSys ? await api.evaluate(duoSys.systemDetailId, DUO_Q).catch(() => null) : null;
  // Who uses which device, from each RMM, EDR and MDM tool's own device list (see user-devices.js).
  const links = await UD.collectLinks(api, sys).catch(() => []);
  return {
    environment: env,
    identities: ids.map(i => ({ id: i.ID, name: i.DisplayName || [i.FirstName, i.LastName].filter(Boolean).join(' ') || i.Username || i.Email, email: i.Email, username: i.Username,
      first: i.FirstName, last: i.LastName, department: i.Department, related: i.RelatedEmails,
      type: i.Type, state: i.InventoryState, enabled: i.Enabled, privileged: i.Privileged, mfa: i.MfaStatus, activity: i.AccountActivity, lastLogin: i.LastLogin,
      licences: i.EmailLicenses || [], sources: (i.Inspectors || []).map(x => x.Alias), sourceRefs: (i.Inspectors || []).map(x => ({ alias: x.Alias, systemId: x.SystemID, systemDetailId: x.SystemDetailID })),
      membership: i.Membership, deleted: !!i.DeletedOn })),
    devices: devices.filter(d => d.LastLoginUser).map(d => ({ id: d.ID, host: d.Hostname, user: d.LastLoginUser, lastSeen: d.LastSeen })),
    inventory: devices.filter(d => d.InventoryState !== 'Archive').map(d => ({ id: d.ID, host: d.Hostname, os: d.OperatingSystem, type: d.Type, lastSeen: d.LastSeen })),
    links,
    duo, duoSys: duoSys ? { systemId: duoSys.systemId, systemDetailId: duoSys.systemDetailId } : null,
  };
}

const lc = s => String(s || '').toLowerCase().trim();
const yes = v => v === true || /^(true|yes)$/i.test(String(v));
const SHARED = /^(info|office|reception|sales|accounts|billing|hr|support|helpdesk|help|noreply|no-reply|enquiries|contact|scanner|scans|marketing|jobs|careers|orders|invoices)@/i;
const BUILTIN = /^(administrator|guest|defaultaccount|wdagutilityaccount|krbtgt)$/i;

// What kind of account this is. Admin-only and service accounts skew MFA and licence numbers if counted as people.
function kindOf(i) {
  const n = `${i.name || ''} ${i.username || ''} ${i.email || ''}`;
  if (/#ext#|\(guest\)/i.test(n) || /guest/i.test(i.type || '') || /guest/i.test(i.membership || '')) return 'Guest';
  if (/service|application/i.test(i.type || '') || /^(krbtgt|guest|defaultaccount|wdagutilityaccount)$/i.test(i.username || '') || /\b(svc|service|sync|scanner|api|bot|noreply|no-reply|automate|integration)\b|_svc|svc_/i.test(n)) return 'Service';
  if (SHARED.test(i.email || '') || /\b(shared|mailbox|room|conf room|conference|equipment)\b/i.test(i.name || '')) return 'Shared';
  if (/\badmin(istrator)?\b|admin$|^adm[-_.]|[-_.]adm$/i.test(i.username || i.name || '') || (yes(i.privileged) && !i.first && !i.last && !/\s/.test(i.name || ''))) return 'Admin account';
  return 'Person';
}

// Identifiers in a metric list item: emails, "Name: user", {email, name, …}, "DOMAIN\\user".
function idsOf(x) {
  const out = [];
  const add = v => { if (v != null && v !== '') out.push(String(v)); };
  if (Array.isArray(x) && x.length && x.every(p => Array.isArray(p))) x = pairs(x);   // [["Name:", "x"], ["Enabled:", true]]
  if (x && typeof x === 'object' && !Array.isArray(x)) {
    for (const k of ['email', 'Email', 'Account', 'account', 'UserPrincipalName', 'upn', 'Username', 'username', 'user', 'User', 'name', 'Name', 'DisplayName', 'displayName', 'identifier']) {
      const v = x[k]; if (v && typeof v === 'object') { add(v.email); add(v.username); add(v.name); } else add(v);
    }
  } else if (Array.isArray(x)) x.forEach(v => typeof v === 'string' && add(v));
  else if (typeof x === 'string') {
    const s = x.trim();
    (s.match(/[\w.+'-]+@[\w-]+(\.[\w-]+)+/g) || []).forEach(add);
    const kv = s.match(/\b(?:user(?:name)?|name|email|account)\s*:\s*([^,|\]]+)/gi);
    if (kv) kv.forEach(p => add(p.replace(/^[^:]+:\s*/, '')));
    else if (!/@/.test(s)) s.split(/\s*[:|]\s*|\s+-\s+/).slice(0, 2).forEach(add);
  }
  return out.map(v => v.replace(/^.*\\/, '').trim()).filter(v => v && v.length < 120);
}
// A role from a metric list item, if it names one.
// Some metrics flatten several records into one list of ["Key:", value] pairs; split them back into records.
function regroup(list) {
  if (!list.length || !list.every(p => Array.isArray(p) && p.length >= 2 && typeof p[0] === 'string' && /:$/.test(p[0]))) return list;
  const out = []; let cur = null; const first = list[0][0];
  for (const p of list) { if (p[0] === first || !cur) { cur = []; out.push(cur); } cur.push(p); }
  return out;
}
const pairs = arr => Object.fromEntries(arr.filter(p => p.length >= 2).map(p => [String(p[0]).replace(/:$/, '').trim(), p[1]]));
function roleOf(x) {
  if (Array.isArray(x) && x.length && x.every(p => Array.isArray(p))) x = pairs(x);
  if (x && typeof x === 'object' && !Array.isArray(x)) { const r = x.PrivilegedRoles || x.role || x.Role || x.securityRole || x.Roles || x.Type || ''; return Array.isArray(r) ? r.join(', ') : r; }
  if (typeof x === 'string') {
    const r = /\broles?\s*:\s*\[?\s*"?([^"\],|]+)/i.exec(x); if (r) return r[1].trim();
    const dash = x.split(/\s+-\s+/); if (dash.length === 2) return dash[1];
    const p = x.split(/\s*:\s*/); return p.length >= 2 && !/name|user|email/i.test(p[p.length - 2]) ? p[p.length - 1] : '';
  }
  return '';
}
function label(x) {
  if (Array.isArray(x) && x.length && x.every(p => Array.isArray(p))) x = pairs(x);
  if (typeof x === 'string') { const ids = idsOf(x); return ids[0] || x; }
  if (x && typeof x === 'object') return x.DisplayName || x.name || x.Name || x.Account || x.Username || x.email || x.Email || x.identifier || JSON.stringify(x).slice(0, 60);
  return String(x);
}

// Which metric lists say what about people.
const LISTS = [
  { kind: 'admin', re: /admin|privileg|owner|roster|sysadmin|super ?user|global administrator/i, not: /without|\bno\b|\bnot\b|with a detected|enforces|stale|disabled|naming|roles list|administrative roles|enabled roles|wan zone|services|global catalog|polic|non-privileg|password|count|summary of|zone/i },
  { kind: 'nomfa', re: /without (mfa|2fa|multi)|\bno (mfa|2fa)\b|not registered for mfa|mfa (disabled|not)|not enrolled|without multi/i },
  { kind: 'disabled', re: /disabled (users?|accounts?)/i, not: /count|guest account disabled/i },
  { kind: 'stale', re: /stale|disused|inactive (users?|accounts?)|no recent (login|sign)/i, not: /count|password|privileged users with stale/i },
  { kind: 'stalepwd', re: /stale password|password (age|older)/i },
  { kind: 'neverexpires', re: /password never expires|pwd.*never/i, not: /count/i },
  { kind: 'guest', re: /guest users?|external users?/i, not: /count|guest account disabled/i },
  { kind: 'darkweb', re: /email list|breach/i, insp: /dark web/i },
  { kind: 'training', re: /past due|overdue/i, insp: /knowbe4|nimblr/i },
  { kind: 'present', re: /(users?|members?|accounts?) (list|summary)|active users?|user list/i, not: /count|privileg|admin|without|disabled|stale|guest|licen/i },
];

// Liongard's reconciled MFA status, in words.
const MFA_WORDS = { YES: 'MFA on', NO: 'No MFA', PARTIAL: 'MFA in some systems only' };

// A local account (no email, e.g. "adelev" on a workstation) with the same name as a directory identity whose email
// starts with that username (AdeleV@contoso.com) is the same person: fold it in, keeping its admin rights and tools.
function mergeLocal(rows) {
  const lc = v => String(v || '').toLowerCase();
  const byKey = new Map(rows.filter(r => r.email).map(r => [`${lc(r.name)}|${lc(r.email).split('@')[0]}`, r]));
  const out = [];
  for (const r of rows) {
    const main = !r.email && r.username && !/[@\\]/.test(r.username) ? byKey.get(`${lc(r.name)}|${lc(r.username)}`) : null;
    if (!main || main === r) { out.push(r); continue; }
    main.sources = [...new Set([...main.sources, ...r.sources])];
    main.sourceRefs = [...(main.sourceRefs || []), ...(r.sourceRefs || [])];
    main.privileged = main.privileged || r.privileged;
    main.admin = [...main.admin, ...r.admin];
    main.mfaMissingIn = [...new Set([...main.mfaMissingIn, ...r.mfaMissingIn])];
    main.devices = [...(main.devices || []), ...(r.devices || [])];
    main.alsoIds = [...(main.alsoIds || []), r.id];
    main.localAccounts = [...(main.localAccounts || []), `${r.username} (${r.sources.join(', ')})`];
  }
  return out;
}

function compute(input) {
  const STALE_DAYS = (input.thresholds && input.thresholds.account) || DEFAULT_STALE_DAYS;   // Settings › Defaults
  const now = input.pulledOn ? new Date(input.pulledOn) : new Date();
  const days = iso => iso ? Math.floor((now - new Date(iso)) / 864e5) : null;
  const msp = input.msp || { domains: [], names: [] };
  const isMsp = i => (msp.domains || []).some(d => d && lc(i.email).endsWith('@' + lc(d).replace(/^@/, ''))) || (msp.names || []).some(n => n && `${lc(i.name)} ${lc(i.username)} ${lc(i.email)}`.includes(lc(n)));
  const live = input.identities.filter(i => i.state !== 'Archive' && !i.deleted);

  // ---------- Index identities by every identifier we might see in a metric ----------
  const index = new Map();
  const key = v => lc(v).replace(/^.*\\/, '');
  for (const i of live) {
    const keys = [i.email, i.username, i.name, i.email && i.email.split('@')[0], i.username && String(i.username).split('@')[0], i.first && i.last && `${i.first}.${i.last}`, ...(String(i.related || '').split(/[,;\s]+/))].filter(Boolean).map(key);
    for (const k of keys) if (k.length > 1 && !index.has(k)) index.set(k, i);
  }
  const find = x => { for (const v of idsOf(x)) { const i = index.get(key(v)) || index.get(key(v).split('@')[0]); if (i) return i; } return null; };

  // ---------- What each system's metrics say about people ----------
  const st = input.stack;
  const per = new Map();   // identity id -> facts
  const facts = i => per.get(i.id) || per.set(i.id, { admin: [], nomfa: [], disabledIn: [], staleIn: [], stalePwd: false, neverExpires: false, darkweb: [], training: [], presentIn: [] }).get(i.id);
  const adminMap = new Map();   // system -> rows
  const tenant = [];
  if (st) {
    const sysById = new Map(st.systems.filter(s => s.systemId).map(s => [s.systemId, s]));
    for (const [sid, metrics] of st.metricsBySys) {
      const s = sysById.get(sid); if (!s || s.health === 'Inactive') continue;
      for (const m of metrics) {
        const n = m.n || '';
        // Tenant-level identity settings.
        if (/security defaults enabled/i.test(n) && typeof m.v !== 'object') tenant.push({ t: 'Security defaults', v: /true|yes|enabled/i.test(String(m.v)) ? 'On' : 'Off', system: s.name, inspector: s.inspector, systemId: s.systemId, systemDetailId: s.systemDetailId });
        if (/conditional access polic(y|ies) list/i.test(n) && Array.isArray(m.v)) tenant.push({ t: 'Conditional access policies', v: String(m.len || m.v.length), system: s.name, inspector: s.inspector, systemId: s.systemId, systemDetailId: s.systemDetailId });
        if (!Array.isArray(m.v)) continue;
        const L = LISTS.find(l => l.re.test(n) && (!l.not || !l.not.test(n)) && (!l.insp || l.insp.test(s.inspector)));
        if (!L) continue;
        for (const item of regroup(m.v)) {
          const who = find(item);
          if (L.kind === 'admin') {
            const rows = adminMap.get(s.name) || adminMap.set(s.name, { system: s.name, inspector: s.inspector, systemId: s.systemId, systemDetailId: s.systemDetailId, admins: new Map() }).get(s.name);
            const k = who ? who.id : lc(label(item));
            if (/^(builtin|nt service|nt authority)\\|^(sa|system)$|^api$/i.test(typeof item === 'string' ? item.trim() : label(item))) continue;   // built-in principals
            const prev = rows.admins.get(k);
            const role = String(roleOf(item) || '').slice(0, 60);
            rows.admins.set(k, { label: who ? who.name : label(item), role: prev && prev.role ? prev.role : role, personId: who ? who.id : null });
            if (who) { const f = facts(who); if (!f.admin.some(a => a.system === s.name)) f.admin.push({ system: s.name, inspector: s.inspector, role }); }
          } else if (who) {
            const f = facts(who);
            if (L.kind === 'nomfa' && !f.nomfa.includes(s.inspector)) f.nomfa.push(s.inspector);
            if (L.kind === 'disabled' && !f.disabledIn.includes(s.inspector)) f.disabledIn.push(s.inspector);
            if (L.kind === 'stale' && !f.staleIn.includes(s.inspector)) f.staleIn.push(s.inspector);
            if (L.kind === 'stalepwd') f.stalePwd = true;
            if (L.kind === 'neverexpires') f.neverExpires = true;
            if (L.kind === 'darkweb' && !(item && typeof item === 'object' && +item['Number of Breaches'] === 0)) f.darkweb.push(typeof item === 'string' ? 'Listed by dark web monitoring' : `${item['Number of Breaches'] ?? ''} breach${+item['Number of Breaches'] === 1 ? '' : 'es'}`.trim());
            if (L.kind === 'training') f.training.push(String(label(item)).replace(/,?\s*user:.*$/i, '').replace(/^module:\s*/i, '').slice(0, 80));
            if ((L.kind === 'present' || L.kind === 'guest') && !f.presentIn.includes(s.inspector)) f.presentIn.push(s.inspector);
          }
        }
      }
    }
  }

  // ---------- Duo ----------
  const duo = input.duo || {};
  const duoUsers = (duo.users || []).filter(u => u.u || u.e);
  const ts = v => typeof v === 'number' || /^\d+$/.test(String(v || '')) ? new Date(+v < 1e12 ? +v * 1000 : +v) : new Date(v);   // Duo uses epoch seconds
  const bypass = (duo.bypass || []).map(b => ({ ...b, daysLeft: b.exp ? Math.floor((ts(b.exp) - now) / 864e5) : null }));
  const longBypass = bypass.filter(b => b.daysLeft == null || b.daysLeft > 30);
  const duoOf = i => duoUsers.find(u => lc(u.e) === lc(i.email) || lc(u.u) === lc(i.username) || lc(u.u) === lc(i.name));

  // ---------- One row per account ----------
  const friendly = l => /^Microsoft_Teams_Enterprise/i.test(l) ? 'Microsoft Teams Enterprise' : String(l).replace(/_/g, ' ').replace(/\s+New$/i, '');
  const rows = mergeLocal(live.map(i => {
    const f = per.get(i.id) || { admin: [], nomfa: [], disabledIn: [], staleIn: [], stalePwd: false, neverExpires: false, darkweb: [], training: [], presentIn: [] };
    const d = duoOf(i);
    const duoState = d ? (d.enr === false || d.enr === 'false' ? 'not-enrolled' : 'enrolled') : '';
    const kind = kindOf(i);
    const lastLogin = i.lastLogin && new Date(i.lastLogin).getUTCFullYear() > 2000 ? i.lastLogin : null;   // 1970 means never
    const lastDays = days(lastLogin);
    const enabled = i.enabled !== false && !f.disabledIn.some(x => /active directory|microsoft 365/i.test(x));
    const privileged = yes(i.privileged) || f.admin.length > 0;
    // MFA by system: what each system says, so "partial" can say where it's missing.
    const mfaBy = [...new Set([...f.nomfa, ...(duoState === 'not-enrolled' ? ['Duo Security'] : [])])];
    // Stale on Liongard's sign-in date; a system calling someone stale who signed in last month is a disagreement, not a stale account.
    const recent = lastDays != null && lastDays <= 30;
    const stale = enabled && ((lastDays != null && lastDays > STALE_DAYS) || (f.staleIn.length > 0 && !recent) || /dormant|inactive|stale/i.test(i.activity || ''));
    const staleConflict = enabled && f.staleIn.length > 0 && recent;
    const otherAccess = !enabled && !BUILTIN.test(i.username || i.name || '') && ['Person', 'Admin account'].includes(kind) ? [...new Set([...i.sources, ...f.presentIn, ...f.admin.map(a => a.inspector)])].filter(x => !/active directory|microsoft 365|knowbe4|dark web/i.test(x) && !f.disabledIn.includes(x)) : [];
    const devs = (input.devices || []).filter(dv => { const u = lc(dv.user).replace(/^.*\\/, ''); return u && (u === lc(i.username).split('@')[0] || u === lc(i.email).split('@')[0] || u === lc(i.email) || lc(dv.user) === lc(i.name)); }).map(dv => ({ id: dv.id, host: String(dv.host || '').split('.')[0].toUpperCase() }));
    return {
      id: i.id, name: i.name, email: i.email, username: i.username, kind, msp: isMsp(i), department: i.department,
      sources: i.sources, sourceRefs: i.sourceRefs, licences: i.licences.map(friendly), mfa: i.mfa || '', mfaMissingIn: mfaBy, duo: duoState,
      privileged, admin: f.admin, enabled, disabledIn: f.disabledIn, otherAccess, activity: i.activity || '', lastLogin, days: lastDays,
      stale, staleConflict, staleIn: f.staleIn, stalePwd: f.stalePwd, neverExpires: f.neverExpires, darkweb: f.darkweb, training: [...new Set(f.training)], devices: devs, state: i.state,
    };
  })).sort((a, b) => (b.privileged - a.privileged) || ((a.mfa === 'NO' ? 0 : 1) - (b.mfa === 'NO' ? 0 : 1)) || a.name.localeCompare(b.name));

  const humans = rows.filter(r => r.kind === 'Person' || r.kind === 'Admin account');
  const enabledHumans = humans.filter(r => r.enabled);
  const withMfa = enabledHumans.filter(r => ['YES', 'NO', 'PARTIAL'].includes(r.mfa));
  const mfaYes = withMfa.filter(r => r.mfa === 'YES');   // Liongard's reconciled status (also used by Compliance)
  const gapSomewhere = enabledHumans.filter(r => r.mfaMissingIn.length);
  // Any admin with no MFA somewhere counts, even if Liongard's overall status says YES (MFA in one tool doesn't cover another).
  // ---------- People & devices ----------
  // Links from each tool's device list plus Liongard's Asset Inventory "last user", resolved to people with the same
  // matcher as everything else on this page. A local account folded into a person (mergeLocal) resolves to that person.
  const mainId = new Map(rows.flatMap(r => [[r.id, r.id], ...(r.alsoIds || []).map(a => [a, r.id])]));
  const invLinks = (input.devices || []).map(d => ({ host: d.host, user: d.user, seen: d.lastSeen, source: 'Liongard inventory', strength: 'last' }));
  const ud = UD.buildLinks({ links: [...(input.links || []), ...invLinks], inventory: input.inventory || [], rows, now,
    find: v => { const i = find(v); return i ? { id: mainId.get(i.id) || i.id } : null; } });
  for (const r of rows) r.devices = ud.byPerson.get(r.id) || [];
  const linked = ud.devices.filter(d => d.persons.length);
  const userDevices = {
    devices: ud.devices, sources: ud.sources, linked: linked.length, inventoryCount: (input.inventory || []).length,
    exceptions: {
      // Disabled accounts still signing in to (or assigned) a device.
      leavers: rows.filter(r => !r.enabled && r.devices.some(d => !d.shared)).map(r => r.id),
      // Licensed, enabled people no tool links to any device (only meaningful once some devices are linked).
      noDevice: linked.length ? rows.filter(r => r.enabled && r.kind === 'Person' && r.licences.length && !r.devices.length).map(r => r.id) : [],
      // Devices no person is linked to: only built-in or admin accounts sign in, or the users aren't in the identity data.
      noPerson: ud.devices.filter(d => d.noPerson).map(d => d.host),
      // Tools disagree on who uses the device.
      disagree: ud.devices.filter(d => d.disagree).map(d => d.host),
    },
  };

  const nAdmins = rows.filter(r => r.enabled && r.privileged).length;
  const adminsNoMfa = rows.filter(r => r.enabled && r.privileged && (r.mfa === 'NO' || r.mfa === 'PARTIAL' || r.mfaMissingIn.length));
  // People (not admins) with no MFA, or no MFA in at least one system. Cyber security shows these same people.
  const usersNoMfa = enabledHumans.filter(r => !r.privileged && (r.mfa === 'NO' || r.mfa === 'PARTIAL' || r.mfaMissingIn.length));
  // Tools that only report a count ("3 admins without 2FA") and can't be tied to a person. Shown beside the count, never added to it.
  const ADMIN_MFA = /(?<!non-?\s?)admin.*(mfa|2fa)|(mfa|2fa).*(?<!non-?\s?)admin/i;
  const USER_MFA = /without (mfa|2fa|multi)|no (mfa|2fa)|(mfa|2fa) (disabled|not)|not registered for mfa/i;
  // "MFA everywhere": people with MFA reported and no gap in any system. The rest are exactly the two lists above.
  const listed = new Set([...adminsNoMfa, ...usersNoMfa].map(r => r.id));
  const judged = enabledHumans.filter(r => listed.has(r.id) || r.mfa === 'YES');
  const everywhere = judged.filter(r => !listed.has(r.id));
  const toolMfa = st ? st.findings.filter(f => !f.old && !f.list && (ADMIN_MFA.test(f.label) || USER_MFA.test(f.label)) && +f.value > 0)
    .map(f => ({ admin: ADMIN_MFA.test(f.label), n: +f.value, label: f.label, inspector: f.inspector, system: f.system, systemId: f.systemId, systemDetailId: f.systemDetailId })) : [];
  const toolNote = list => list.length ? `Tools’ own counts (all account types): ${list.map(f => `${f.inspector} ${f.n}`).join(', ')}` : '';
  const leavers = rows.filter(r => !r.enabled && r.otherAccess.length);
  const stale = rows.filter(r => r.stale && r.kind !== 'Service');
  const licensed = rows.filter(r => r.licences.length);
  const licDisabled = licensed.filter(r => !r.enabled), licStale = licensed.filter(r => r.stale), licShared = licensed.filter(r => r.enabled && (r.kind === 'Shared' || r.kind === 'Admin account'));
  const mspNoMfa = rows.filter(r => r.msp && r.enabled && (r.mfa === 'NO' || r.mfaMissingIn.length));
  const notEnrolled = duoUsers.filter(u => u.enr === false || u.enr === 'false');

  // Admin map: who can administer what, across every system that lists admins.
  const admins = [...adminMap.values()].map(a => ({ ...a, admins: [...a.admins.values()].map(x => {
    const r = x.personId && rows.find(r => r.id === x.personId);
    return { ...x, mfa: r ? (r.mfaMissingIn.includes(a.inspector) || r.mfa === 'NO' ? 'no' : r.mfa === 'YES' ? 'yes' : r.mfa === 'PARTIAL' ? 'partial' : '') : '', enabled: r ? r.enabled : null, msp: r ? r.msp : false };
  }) })).sort((a, b) => b.admins.length - a.admins.length);

  // Needs attention, grouped and ranked.
  const groups = [];
  const G = (key, title, sev, items, why) => { if (items.length) groups.push({ key, title, sev, items, why }); };
  G('adminmfa', 'Admins without MFA', 'bad', adminsNoMfa.map(r => ({ t: r.name, d: r.mfaMissingIn.length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : MFA_WORDS[r.mfa] || 'MFA not reported', identityId: r.id, admin: r.admin.map(a => a.system).join(', ') })), 'Admin accounts are the ones attackers want.');
  G('leavers', 'Disabled but still has access elsewhere', 'bad', leavers.map(r => ({ t: r.name, d: `Disabled${r.disabledIn.length ? ` in ${r.disabledIn.join(', ')}` : ''}, still in ${r.otherAccess.join(', ')}`, identityId: r.id })), 'Remove leavers from every tool, not just the directory.');
  G('msp', 'MSP accounts without MFA', 'bad', mspNoMfa.map(r => ({ t: r.name, d: r.mfaMissingIn.length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : MFA_WORDS[r.mfa] || 'MFA not reported', identityId: r.id })), 'Your own accounts reach every client; they need MFA first.');
  G('bypass', 'Duo bypass codes and enrolment', 'warn', [...longBypass.map(b => ({ t: b.u || b.e, d: `Bypass code ${b.daysLeft != null ? `valid for ${b.daysLeft} more days` : 'with no expiry'}, created ${fmt(b.created)}${b.by ? ` by ${b.by}` : ''}` })), ...notEnrolled.map(u => ({ t: u.u || u.e, d: 'Not enrolled in Duo' }))], 'A long-lived bypass is an easy way around MFA.');
  G('stale', `No sign-in for ${STALE_DAYS}+ days, or reported stale`, 'warn', stale.map(r => ({ t: r.name, d: `${r.lastLogin ? `Last sign-in ${fmt(r.lastLogin)}` : 'No sign-in recorded'}${r.staleIn.length ? ` · reported stale by ${r.staleIn.join(', ')}` : ''}`, identityId: r.id })), 'Disable accounts nobody uses.');
  G('disagree', 'Sources disagree', 'warn', rows.filter(r => r.staleConflict).map(r => ({ t: r.name, d: `${r.staleIn.join(', ')} report${r.staleIn.length > 1 ? '' : 's'} this account as stale, but Liongard saw a sign-in ${fmt(r.lastLogin)}`, identityId: r.id })), 'Check which source is right before disabling anyone.');
  G('licence', 'Licences on accounts that don’t need them', 'warn', [...licDisabled.map(r => ({ t: r.name, d: `Disabled, holds ${r.licences.join(', ')}`, identityId: r.id, q: r.email })), ...licStale.map(r => ({ t: r.name, d: `Stale, holds ${r.licences.join(', ')}`, identityId: r.id, q: r.email })), ...licShared.map(r => ({ t: r.name, d: `${r.kind}, holds ${r.licences.join(', ')}`, identityId: r.id, q: r.email }))], 'See Licence reconciliation for seat counts and cost.');
  G('hygiene', 'Password and exposure hygiene', 'warn', rows.filter(r => r.enabled && (r.neverExpires || r.stalePwd || r.darkweb.length || r.training.length)).map(r => ({ t: r.name, d: [r.neverExpires && 'password never expires', r.stalePwd && 'privileged with a stale password', r.darkweb.length && `dark web: ${r.darkweb[0]}`, r.training.length && `${r.training.length} overdue training module${r.training.length > 1 ? 's' : ''}`].filter(Boolean).join(' · '), identityId: r.id })), '');

  const KIND_WORD = { Person: ['person', 'people'], 'Admin account': ['admin account', 'admin accounts'], Service: ['service account', 'service accounts'], Shared: ['shared mailbox', 'shared mailboxes'], Guest: ['guest', 'guests'] };
  const kindsCount = ['Person', 'Admin account', 'Service', 'Shared', 'Guest'].map(k => ({ k, n: rows.filter(r => r.kind === k).length, w: KIND_WORD[k] })).filter(x => x.n);
  const kw = k => `${k.n} ${k.w[k.n === 1 ? 0 : 1]}`;
  const summary = [
    `${humans.filter(r => r.enabled).length} active people and admin accounts${kindsCount.filter(k => !['Person', 'Admin account'].includes(k.k)).map(k => `, plus ${kw(k)}`).join('')}. ${judged.length ? `Of those ${enabledHumans.length}, ${everywhere.length} have MFA in every system, ${usersNoMfa.length + adminsNoMfa.length} don’t (${[...new Set([...adminsNoMfa, ...usersNoMfa].flatMap(r => r.mfaMissingIn))].slice(0, 3).join(', ') || 'no MFA at all'})${enabledHumans.length - judged.length ? ` and ${enabledHumans.length - judged.length} have no MFA data` : ''}` : 'No MFA data reported'}.`,
    adminsNoMfa.length ? `${adminsNoMfa.length} account${adminsNoMfa.length > 1 ? 's with admin rights lack' : ' with admin rights lacks'} MFA somewhere: ${adminsNoMfa.slice(0, 4).map(r => r.name).join(', ')}${adminsNoMfa.length > 4 ? ' and more' : ''}.` : nAdmins ? 'Every admin has MFA.' : 'No accounts with admin rights were found, so admin MFA can’t be checked.',
    admins.length ? `${new Set(admins.flatMap(a => a.admins.map(x => x.personId || x.label))).size} accounts can administer at least one of ${admins.length} systems.` : '',
    leavers.length ? `${leavers.length} disabled account${leavers.length > 1 ? 's are' : ' is'} still present in other tools.` : '',
    stale.length ? `${stale.length} enabled account${stale.length > 1 ? 's haven’t' : ' hasn’t'} signed in for ${STALE_DAYS}+ days or ${stale.length > 1 ? 'are' : 'is'} reported stale.` : '',
    !(msp.domains || []).length && !(msp.names || []).length ? 'Tell the app your MSP’s domains to see which accounts belong to you.' : `${rows.filter(r => r.msp).length} MSP account${rows.filter(r => r.msp).length === 1 ? '' : 's'}${mspNoMfa.length ? `, ${mspNoMfa.length} without MFA` : ''}.`,
  ].filter(Boolean);

  return {
    environment: input.environment, pulledOn: input.pulledOn, source: input.source, duoSys: input.duoSys, staleDays: STALE_DAYS, summary, msp,
    kpis: [
      { k: 'People', v: humans.filter(r => r.enabled).length, s: kindsCount.filter(k => k.k !== 'Person').map(kw).join(', ') || 'Active people', sev: 'info' },
      // One denominator for "people" on every tile: the active people and admin accounts on the People tile.
      { k: 'MFA everywhere', v: judged.length ? `${Math.round(everywhere.length / enabledHumans.length * 100)}%` : '—', s: `${everywhere.length} of ${enabledHumans.length} people have MFA in every system${enabledHumans.length - judged.length ? ` · ${enabledHumans.length - judged.length} with no MFA data` : ''}`, sev: judged.length && everywhere.length === enabledHumans.length ? 'ok' : 'warn' },
      // Nothing to judge is no evidence (—), never a green zero: 0 of 0 isn't "everyone has MFA".
      { k: 'Admins without MFA', v: nAdmins ? adminsNoMfa.length : '—', s: [nAdmins ? `of ${nAdmins} accounts with admin rights` : 'No accounts with admin rights found', toolNote(toolMfa.filter(f => f.admin))].filter(Boolean).join('. '), sev: adminsNoMfa.length ? 'bad' : nAdmins ? 'ok' : 'info' },
      { k: 'Users without MFA', v: judged.length || usersNoMfa.length ? usersNoMfa.length : '—', s: [usersNoMfa.length ? 'No MFA, or not in every system' : judged.length ? 'Every user has MFA' : 'No MFA data for any user', toolNote(toolMfa.filter(f => !f.admin))].filter(Boolean).join('. '), sev: usersNoMfa.length ? 'warn' : judged.length ? 'ok' : 'info' },
      { k: 'Leavers with access', v: leavers.length, s: 'Disabled but still in other tools', sev: leavers.length ? 'bad' : 'ok' },
      { k: 'Stale accounts', v: stale.length, s: `No sign-in for ${STALE_DAYS}+ days, or reported stale (licence use is counted on Licences)`, sev: stale.length ? 'warn' : 'ok' },
      { k: 'Duo bypass codes', v: bypass.length, s: input.duo ? `${longBypass.length} valid for more than 30 days` : 'No Duo inspector', sev: longBypass.length ? 'warn' : 'ok' },
    ],
    groups, rows, admins, tenant, kindsCount, bypass, userDevices,
    // One MFA answer shared with Cyber security and Compliance.
    mfa: { admins: adminsNoMfa.map(r => r.id), users: usersNoMfa.map(r => r.id), tools: toolMfa },
    // Kept for pages built on this one.
    attention: groups.flatMap(g => g.items.map(i => ({ sev: g.sev, t: `${i.t}: ${g.title.toLowerCase()}.`, d: i.d }))),
  };
}

function fmt(iso) { const d = new Date(typeof iso === 'number' || /^\d+$/.test(String(iso)) ? (+iso < 1e12 ? +iso * 1000 : +iso) : iso);   // Duo uses epoch seconds
  return isNaN(d) ? '' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }); }

module.exports = { id: 'identity', usesStack: true, collect, compute, kindOf, idsOf };
