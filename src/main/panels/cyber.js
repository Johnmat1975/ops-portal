// Cyber security: where this client is exposed right now, which security-relevant changes landed together, and which
// attack techniques Liongard can and can't see. Changes are classified against MITRE ATT&CK by keyword rules that read
// what was actually added, removed or changed (so removing a forwarding rule isn't treated like creating one).
// Counters, recurring timestamp churn and changes that flip back and forth are set aside as noise or data issues.
// These are leads for a human to check, not proof of an attack.
const changes = require('./changes');
const identity = require('./identity');
const { SIGNALS, current } = require('../stack');
const coverage = require('./coverage');
const inspectors = require('./inspectors');
const email = require('./email');
const network = require('./network');
const { TACTICS, TECH, MITIGATIONS, ATTACK_VERSION, ATTACK_TOTAL } = require('../catalog');
const { profileOf } = require('../stack-catalog');

// A part that fails becomes { error } (its tiles show "no evidence"); parts in `have` were already pulled (Refresh all).
const part = (have, key, p, api, env) => have[key] || p.collect(api, env).catch(e => ({ error: e.message }));
async function collect(api, env, have = {}) {
  const alerts = api.alerts(env.ID).then(rows => rows.map(a => ({ id: a.ID, name: a.Name, priority: a.Priority && a.Priority.Name, status: a.Status && a.Status.Name,
    inspector: a.Inspector && a.Inspector.Alias, created: a.CreatedOn }))).catch(e => ({ error: e.message }));
  const [chg, id, cov, insp, mail, net, al] = await Promise.all([part(have, 'chg', changes, api, env), part(have, 'id', identity, api, env), part(have, 'cov', coverage, api, env), part(have, 'insp', inspectors, api, env), part(have, 'mail', email, api, env), part(have, 'net', network, api, env), alerts]);
  return { environment: env, chg, id, cov, insp, mail, net, alerts: al };
}

// ---------- What a change actually did ----------
const clean = s => String(s).replace(/^[\s\[\]{},"]+|[\s\[\]{},"]+$/g, '').replace(/\\"/g, '"').replace(/"\s*:\s*/, ': ').replace(/^"/, '').trim();
const kv = x => { const m = /^([A-Za-z_][\w.\/]*(?: [A-Za-z_][\w.\/]*){0,6})\s*:\s*(.*)$/.exec(x); return m ? [m[1], m[2].replace(/^"|"$/g, '')] : null; };
const normNum = x => x.replace(/-?\d+(?:[.:T\-\/]\d+)*Z?/g, '#');
const bag = arr => arr.reduce((m, x) => m.set(x, (m.get(x) || 0) + 1), new Map());
const sameBag = (a, b) => { if (a.length !== b.length) return false; const m = bag(a); for (const x of b) { if (!m.get(x)) return false; m.set(x, m.get(x) - 1); } return true; };

function delta(patch) {
  // One item per line; long comma-separated lists (role or feature lists) are split into their items.
  const split = x => !kv(x) && x.split(', ').length >= 3 ? x.split(', ').map(clean) : [x];
  const lines = f => (patch || []).filter(f).flatMap(p => String(p.value || '').split('\n')).map(clean).flatMap(split).filter(x => x && !/^[\[\]{}]+$/.test(x))
    .map(x => /^(undefined|null)$/.test(x) ? '(no value)' : x);   // Liongard records an emptied value as the text "undefined"
  let removed = lines(p => p.removed), added = lines(p => p.added);
  // Only numbers moved: a countdown or counter. Not when an address changed (a DNS or gateway swap is a real change).
  const counterOnly = !!(removed.length || added.length) && sameBag(removed.map(normNum), added.map(normNum)) && !removed.concat(added).some(x => /\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){3,}/i.test(x));
  // Lines on both sides only moved.
  const a = bag(added); removed = removed.filter(x => { if (a.get(x)) { a.set(x, a.get(x) - 1); return false; } return true; });
  const r = bag(lines(p => p.removed)); added = added.filter(x => { if (r.get(x)) { r.set(x, r.get(x) - 1); return false; } return true; });
  // key: value settings that changed value.
  const rk = new Map(removed.map(kv).filter(Boolean)), ak = new Map(added.map(kv).filter(Boolean));
  const changed = [...rk.keys()].filter(k => ak.has(k) && rk.get(k) !== ak.get(k)).map(k => ({ key: k, from: rk.get(k), to: ak.get(k) }));
  const ck = new Set(changed.map(c => c.key));
  const notChanged = x => { const p = kv(x); return !(p && ck.has(p[0])); };
  return { added: added.filter(notChanged), removed: removed.filter(notChanged), changed, counterOnly };
}

// Settings whose change in one direction weakens security: [key pattern, weaker when, technique, label]
// 'on' rows are features that are risky when switched on (Liongard metric names such as "Windows Server: Is RDP Enabled?").
const WEAKEN = [
  [/max.?login.?attempts|lockout.?threshold|bad.?logon.?count|failed.?login/i, 'up', 'T1110', 'Login attempt limit raised'],
  [/min(imum)?.?password.?length|password.?history|password.?complexity/i, 'down', 'T1110', 'Password rule weakened'],
  [/security.?defaults/i, 'off', 'T1556.009', 'Security defaults turned off'],
  [/default (guest|administrator) account enabled|guest account enabled/i, 'on', 'T1078.001', 'Built-in account enabled'],
  [/guest account disabled/i, 'off', 'T1078.001', 'Built-in guest account re-enabled'],
  [/\brdp\b.*(enabled|allowed)|remote desktop.*enabled/i, 'on', 'T1021.001', 'Remote Desktop turned on'],
  [/remote (login|ssh)|ssh enabled/i, 'on', 'T1021.004', 'SSH remote login turned on'],
  [/remote management/i, 'on', 'T1021.005', 'Remote Management (screen sharing) turned on'],
  [/mfa|two.?factor|2fa|multi.?factor/i, 'off', 'T1556.006', 'MFA setting turned off'],
  [/\bips\b|intrusion|gateway.?av|anti.?(virus|spyware|malware)|botnet|geo.?ip|content.?filter|app(lication)?.?control|ssl.?inspect|dpi/i, 'off', 'T1686.002', 'Firewall security service turned off'],
  [/real.?time|tamper|defender|edr|sensor|protection/i, 'off', 'T1685', 'Endpoint protection turned off'],
  [/firewall/i, 'off', 'T1686.002', 'Firewall turned off'],
  [/audit|logging|syslog/i, 'off', 'T1685', 'Logging turned off'],
];
const isOn = v => /^(true|on|enabled?|yes|1|active|licensed)$/i.test(String(v).trim());
const isOff = v => /^(false|off|disabled?|no|0|inactive|not licensed|expired)$/i.test(String(v).trim());
// `inspector` (optional) places firewall and anti-malware settings: on a Windows, macOS or Linux agent or an EDR they are
// the host's own firewall or protection, not a network device's.
function weakenings(changed, inspector) {
  const out = [];
  const host = inspector && !profileOf(inspector).caps.includes('network') && profileOf(inspector).known;
  for (const c of changed) for (const [re, dir, tech0, label0] of WEAKEN) {
    if (!re.test(c.key)) continue;
    const f = parseFloat(c.from), t = parseFloat(c.to);
    if ((dir === 'up' && t > f) || (dir === 'down' && t < f) || (dir === 'off' && isOn(c.from) && isOff(c.to)) || (dir === 'on' && isOff(c.from) && isOn(c.to))) {
      let tech = tech0, label = label0;
      if (host && tech === 'T1686.002') {
        if (/firewall/i.test(c.key)) { tech = /^Windows (Workstation|Server)$/.test(inspector) ? 'T1686.003' : 'T1686'; label = 'Host firewall turned off'; }
        else { tech = 'T1685'; label = 'Endpoint protection turned off'; }
      }
      out.push({ tech, label, text: `${c.key} ${c.from} → ${c.to}` }); break;
    }
  }
  return out;
}

const AREAS = ['Identity & access', 'Email', 'Domain policy', 'Perimeter & network', 'Endpoints & assets', 'DNS & external'];
const areaOf = (insp, name) => {
  const s = `${insp} ${name}`;
  const caps = profileOf(insp).caps;
  // "Forwarding" on a firewall is port forwarding, not mail.
  const netOnly = caps.includes('network') && !caps.includes('email');
  if (!netOnly && /forward|inbox rule|mailbox|transport rule/i.test(s)) return 'Email';
  if (/gpo|group policy|password policy|account policy|lockout/i.test(s)) return 'Domain policy';
  if (caps.includes('identity') || /user|admin|group|mfa|bypass|role/i.test(name)) return 'Identity & access';
  if (caps.includes('network')) return 'Perimeter & network';
  if (caps.includes('email') || /dns|domain|tls|ssl|certificate/i.test(s)) return 'DNS & external';
  return 'Endpoints & assets';
};

const names = (list, n = 4) => { list = list.map(x => String(x).trim()).filter(Boolean); return list.length <= n ? list.join(', ') : `${list.slice(0, n).join(', ')} and ${list.length - n} more`; };
const uniqCount = arr => new Set(arr).size;
// Repeated items shown once with a count ("Sandbox Liongard ×9").
const counted = arr => [...bag(arr.map(x => itemName(x)))].map(([k, n]) => n > 1 ? `${k} ×${n}` : k);
const itemName = x => { const p = kv(x); return p ? `${p[0]}: ${p[1]}` : x; };

// [name regex, techniques, confidence when something was added, weight, note]
const RULES = [
  [/gpo|group policy/i, ['T1484.001'], 'Strong', 4, ''],
  [/bypass code|bypass/i, ['T1556.006'], 'Partial', 4, 'A new or changed MFA bypass is a way around MFA'],
  [/mfa|two.?factor|strong auth|enrol/i, ['T1556.006'], 'Partial', 3, ''],
  [/users? (added|created)|new users?|accounts? (added|created)/i, ['T1136.003'], 'Partial', 4, 'A new account also fits T1136.002 for Active Directory'],
  [/antivirus|gateway av|anti-?malware|sensor|edr policy|prevention policy|protection (disabled|off)/i, ['T1685'], 'Partial', 4, ''],
  [/firewall rule|access rule|nat polic|security service|\bips\b|intrusion prevention|dns server|primary dns/i, ['T1686.002'], 'Partial', 3, 'Closest fit. ATT&CK has no technique specifically for every firewall setting'],
  [/sign-?in|last.?login|last_login|logged in/i, ['T1078.004'], 'Contextual', 1, 'Normal sign-in activity, recorded because of its timing'],
  [/renamed|device (name|summary)|hostname|system name/i, ['T1036'], 'Contextual', 1, 'Renaming only fits masquerading if the hosts aren’t the expected ones'],
  [/firmware|software version|release/i, ['T1601'], 'Contextual', 1, ''],
  [/password (length|policy)|minimum password/i, [], 'Defensive', 0, 'Password policy change. Check the direction: stronger is mitigation M1027'],
  // Added for ATT&CK v20.0. Each names a Liongard metric that produces detections.
  // Direction is checked in classify(): these only count as Partial when something was added.
  [/conditional access|security defaults/i, ['T1556.009'], 'Partial', 4, 'Conditional access changed. Check no policy was turned off, put in report-only, or given new exclusions'],
  [/api keys?|api tokens?|access keys?/i, ['T1098.001'], 'Partial', 3, 'A new API key or token is a credential that works without MFA'],
  [/local users?|local accounts?/i, ['T1136.001'], 'Partial', 3, 'A new local account on a device sits outside the directory and its MFA'],
  [/guest users?|external users?/i, ['T1199'], 'Partial', 3, 'A new guest gives an outside organisation access (also fits T1136.003)'],
  [/terminal services|port forward|ports? open|open ports?|exposed .*rdp|remote access (profile|enabled)|\bvpn\b/i, ['T1133'], 'Partial', 3, 'A new way in from the internet. Check it was requested and is limited to known addresses'],
  [/weak encryption|without pre-?shared key/i, ['T1669'], 'Partial', 3, 'A Wi-Fi network without strong encryption lets nearby attackers join or listen'],
  [/unsupported protocols|supported protocols/i, ['T1689'], 'Partial', 2, 'An old TLS version enabled lets a client be pushed down to weaker encryption'],
  [/dmarc|\bspf\b|dkim/i, ['T1684.002'], 'Contextual', 1, 'Mail authentication record changed. Check it wasn’t weakened (p=none, ~all or a removed DKIM key)'],
  [/name ?servers?|registrar|domain status/i, ['T1584.001'], 'Partial', 3, 'A name-server or registrar change is how a domain is hijacked. Confirm the client asked for it'],
  [/usb/i, ['T1052.001'], 'Contextual', 1, 'A new USB storage device only matters if nobody expected it'],
];
// Rules that only count when something was added (an entry removed is cleanup, not exposure).
const ADD_ONLY = new Set(['T1098.001', 'T1136.001', 'T1199', 'T1133', 'T1669', 'T1689', 'T1584.001', 'T1052.001']);
const CONF = { Strong: 1, Partial: 0.7, Contextual: 0.4, Defensive: 0, None: 0 };

function classify(d) {
  const x = d.delta;
  // A change whose only difference is a sign-in timestamp is sign-in activity, not an account change.
  const diff = `${d.fullBefore || ''} ${d.fullAfter || ''}`;
  const rest = diff.replace(/(last_?login|last.?sign.?in|lastactive)\s*:\s*\S+/gi, '').replace(/[\s·:]/g, '');
  if (/last_?login|last.?sign|lastactive/i.test(diff) && !/added|removed|created|deleted/i.test(d.name) && rest.length < 4)
    return { tech: ['T1078.004'], conf: 'Contextual', weight: 1, note: 'Only a sign-in time changed: normal admin activity, recorded because of its timing' };
  // A weakened setting (login attempts raised, password length cut) counts even when only a number changed.
  // A metric that is a single on/off value ("Security Defaults Enabled Status: true → false") is read as a setting named after the metric.
  const flag = v => isOn(v) || isOff(v);
  const scalar = !x.changed.length && x.removed.length === 1 && x.added.length === 1 && flag(x.removed[0]) && flag(x.added[0]) ? [{ key: short(d.name), from: x.removed[0], to: x.added[0] }] : [];
  const weak = weakenings(x.changed.concat(scalar), d.inspector);
  if (weak.length) return { tech: [...new Set(weak.map(w => w.tech))], conf: 'Partial', weight: 4, note: `${weak.map(w => w.label).filter((v, i, a) => a.indexOf(v) === i).join('; ')}: ${weak.map(w => w.text).join(', ')}` };
  if (x.counterOnly) {
    if (/gpo|group policy/i.test(d.name)) {
      // A GPO edited after a long quiet spell is worth a look; one that changes every few days is churn (set aside later if it recurs).
      const dates = arr => arr.map(v => new Date((/\d{4}-\d{2}-\d{2}T[\d:]+/.exec(v) || [])[0])).filter(t => !isNaN(t));
      const was = dates(x.removed), now = dates(x.added);
      const gapDays = was.length && now.length ? Math.max(...now.map((t, i) => (t - (was[i] || was[0])) / 864e5)) : 0;
      const quiet = gapDays > 30;
      return { tech: ['T1484.001'], conf: quiet ? 'Partial' : 'Contextual', weight: quiet ? 4 : 1, noise: 'timestamp',
        note: quiet ? `GPO modified for the first time in ${Math.round(gapDays)} days (was ${was.map(t => t.toISOString().slice(0, 10)).join(', ')}). Liongard doesn’t show what changed inside the policy` : 'Only the GPO modification time changed. Liongard doesn’t show what changed inside the policy' };
    }
    return { tech: [], conf: 'None', weight: 0, noise: 'counter', note: 'Only numbers or dates changed (a countdown or counter)' };
  }
  // Direction matters for forwarding rules and admin lists.
  const pc = profileOf(d.inspector || '').caps;
  if (/forwarding rule|forward to/i.test(d.name) && !(pc.includes('network') && !pc.includes('email'))) {   // not firewall port forwarding
    const added = x.added.filter(a => /forward/i.test(a));
    if (added.length) return { tech: ['T1114.003'], conf: 'Strong', weight: 6, note: `${added.length} new forwarding rule${added.length > 1 ? 's' : ''}. Mail forwarded outside the organisation is a classic business email compromise step` };
    return { tech: [], conf: 'Defensive', weight: 0, note: `Forwarding removed${x.removed.length ? `: ${names(x.removed.filter(a => /forward/i.test(a)).map(itemName), 3)}` : ''}` };
  }
  if (/inbox rule|mailbox rule|hidden|move to rss|delete.*rule/i.test(d.name)) return x.added.length ? { tech: ['T1564.008'], conf: 'Partial', weight: 5, note: 'Rules that hide or delete replies are used to keep a victim from noticing' } : { tech: [], conf: 'Defensive', weight: 0, note: 'Mailbox rule removed' };
  // Lists of privileged users *with* a condition are hygiene lists: MFA enforced is good, no MFA is exposure, stale passwords are housekeeping.
  if (/privileg|admin/i.test(d.name) && /(no|without|not)\b.*(mfa|multifactor|2fa)/i.test(d.name))
    return x.added.length ? { tech: ['T1556.006'], conf: 'Partial', weight: 3, note: `Now without enforced MFA: ${names(x.added.map(itemName))}` } : { tech: [], conf: 'Defensive', weight: 0, note: `MFA now enforced for: ${names(x.removed.map(itemName))}` };
  if (/privileg|admin/i.test(d.name) && /enforces|stale|inactive|disabled|expir|password age|never expires/i.test(d.name))
    return { tech: [], conf: 'Contextual', weight: 0.5, note: `Hygiene list changed. ${x.added.length ? `Added: ${names(x.added.map(itemName))}` : ''}${x.removed.length ? ` Removed: ${names(x.removed.map(itemName))}` : ''}`.trim() };
  if (/admin|privileg|role members|administrative roles|active roles|role assignment|groups? added|group membership|members? (added|removed)/i.test(d.name) && !/installed roles|features|non-?privileg/i.test(d.name)) {
    if (x.added.length) return { tech: ['T1098'], conf: 'Strong', weight: 4, note: `${uniqCount(x.added)} added${x.removed.length ? `, ${uniqCount(x.removed)} removed` : ''}. New admin accounts or roles are how attackers keep access` };
    const real = x.changed.filter(c => !/last_?login|last.?sign|lastactive/i.test(c.key));
    if (real.length) {
      const ident = real.filter(c => /e-?mail|user.?name|upn|login|role|phone|name/i.test(c.key));   // an admin's identity or rights changed
      return { tech: ['T1098'], conf: ident.length ? 'Strong' : 'Partial', weight: ident.length ? 4 : 3, note: `Admin ${ident.length ? 'identity' : 'setting'} changed: ${names(real.map(c => `${c.key} ${c.from} → ${c.to}`), 3)}` };
    }
    return { tech: ['T1098'], conf: 'Contextual', weight: 1, note: `${uniqCount(x.removed)} removed, none added` };
  }
  // Mail authentication weakened: DMARC policy relaxed, or SPF moved off hard fail.
  if (/dmarc|\bspf\b/i.test(d.name)) {
    const was = x.removed.join(' '), now = x.added.join(' ');
    const rank = t => /p=reject/i.test(t) ? 3 : /p=quarantine/i.test(t) ? 2 : /p=none/i.test(t) ? 1 : /-all\b/.test(t) ? 3 : /~all\b/.test(t) ? 2 : /[?+]all\b/.test(t) ? 1 : 0;
    if (rank(was) && rank(now) && rank(now) < rank(was)) return { tech: ['T1684.002'], conf: 'Partial', weight: 4, note: `Mail authentication weakened: ${names(x.removed, 1)} → ${names(x.added, 1)}. Others can now send as this domain more easily` };
  }
  const r = RULES.find(([re]) => re.test(d.name));
  if (r && r[1].some(t => ADD_ONLY.has(t)) && !x.added.length) return { tech: [], conf: 'Defensive', weight: 0, note: x.removed.length ? `Removed: ${names(x.removed.map(itemName), 3)}` : 'Changed, nothing added' };
  return r ? { tech: r[1], conf: r[2], weight: r[3], note: r[4] } : { tech: [], conf: 'None', weight: 0.5, note: '' };
}

// Changes that undo an earlier change on the same system (A→B then B→A), and churn that recurs on many days.
function markHistory(dets) {
  const pairs = new Map();
  for (const d of dets) { const k = `${d.source}\u0000${d.name}`; (pairs.get(k) || pairs.set(k, []).get(k)).push(d); }
  const sig = (a, b) => JSON.stringify([[...a].sort(), [...b].sort()]);
  for (const list of pairs.values()) {
    list.sort((a, b) => a.at.localeCompare(b.at));
    const seen = new Map();
    for (const d of list) {
      const fwd = sig(d.delta.added, d.delta.removed), rev = sig(d.delta.removed, d.delta.added);
      if ((d.delta.added.length || d.delta.removed.length) && seen.has(rev)) { d.noise = d.noise || 'flipflop'; seen.get(rev).noise = seen.get(rev).noise || 'flipflop'; }
      seen.set(fwd, d);
    }
    const days = new Set(list.map(d => d.at.slice(0, 10))).size;
    if (days >= 4) for (const d of list) if (d.noise === 'timestamp') d.noise = 'recurring';
  }
}

// Alerts about security (the Action plan uses the same rule, so the two pages split alerts the same way).
const SEC = /mfa|admin|privileg|forward|threat|malware|virus|defender|firewall|bitlocker|encrypt|password|breach|dark web|risk|vulnerab|patch|bypass|lockout|intrusion|edr|sentinel|crowdstrike|huntress|expired cert/i;
function compute(input) {
  const P = input.pulledOn, now = new Date(P || Date.now());
  const ok = r => r && !r.error;
  const chg = ok(input.chg) ? changes.compute({ ...input.chg, pulledOn: P }) : null;
  // Identity, coverage and email get the same shared data and settings as their own pages, so the numbers match.
  const id = ok(input.id) ? identity.compute({ ...input.id, pulledOn: P, stack: input.stack, msp: input.msp, thresholds: input.thresholds }) : null;
  const cov = ok(input.cov) ? coverage.compute({ ...input.cov, pulledOn: P, stack: input.stack, policy: input.coveragePolicy, thresholds: input.thresholds }) : null;
  const ih = ok(input.insp) ? inspectors.compute({ ...input.insp, pulledOn: P }) : null;
  const em = ok(input.mail) ? email.compute({ ...input.mail, pulledOn: P, stack: input.stack }) : null;
  const st = input.stack || null;   // Liongard metric findings for every inspector (added by the main process)
  const alerts = Array.isArray(input.alerts) ? input.alerts : [];

  // Every non-routine detection, with what it actually did, classified.
  const all = ok(input.chg) ? input.chg.detections : [];
  const routine = new Set(chg ? chg.routineSources : []);
  const dets = all.map(d => { const full = changes.diffText(d.patch || [], true); return { ...d, source: d.system || d.inspector, fullBefore: full.before, fullAfter: full.after, delta: delta(d.patch) }; })
    .filter(d => !routine.has(`${d.source}: ${d.name}`) && !/count$|asset count|total .*count/i.test(d.name))
    .map(d => { const c = classify(d); return { ...d, area: areaOf(d.inspector, d.name), ...c }; })
    .sort((a, b) => a.at.localeCompare(b.at));
  markHistory(dets);
  // A strong match is never hidden: if it flips, it stays visible with a note to check the inspector first.
  for (const d of dets) if (d.noise === 'flipflop' && d.conf === 'Strong') { d.flipped = true; d.noise = null; d.note = `${d.note}. This keeps flipping back and forth, so check the inspector is pointed at the right tenant first`; }
  for (const d of dets) if (d.noise === 'timestamp') d.noise = null;   // one-off GPO edits stay; recurring ones were marked above
  const signal = dets.filter(d => !d.noise);
  const flip = dets.filter(d => d.noise === 'flipflop' || d.flipped);
  const quiet = dets.filter(d => d.noise && d.noise !== 'flipflop');

  // Windows: signal changes within 24 hours of the first in the window. Keep windows with security-relevant changes on 2+ systems, or a strong match.
  const windows = [];
  for (const d of signal) {
    const w = windows[windows.length - 1];
    if (w && new Date(d.at) - new Date(w.start) <= 864e5) w.items.push(d); else windows.push({ start: d.at, items: [d] });
  }
  const rel = d => CONF[d.conf] >= CONF.Partial;
  // The same change on the same system more than once in a window (often flipping back) is shown once, with a count.
  const once = items => { const m = new Map(); for (const d of items) { const k = `${d.source}\u0000${d.name}`; if (m.has(k)) m.get(k).repeats++; else m.set(k, Object.assign(d, { repeats: 1 })); } return [...m.values()]; };
  const clusters = windows.map(w => {
    const systems = [...new Set(w.items.map(d => d.source))];
    const key = w.items.filter(rel);
    const relevant = [...new Set(key.map(d => d.source))];
    const score = Math.round(w.items.reduce((s, d) => s + d.weight * CONF[d.conf], 0) * Math.max(1, relevant.length) * 10) / 10;
    const strongCollection = w.items.some(d => d.conf === 'Strong' && d.tech.some(t => /T1114|T1564/.test(t)));
    const level = strongCollection || score >= 12 ? 'High' : score >= 5 ? 'Elevated' : 'Low';
    const techs = [...new Set(w.items.flatMap(d => d.tech))];
    const strongT = new Set(), weakT = new Set();
    w.items.forEach(d => d.tech.forEach(t => TECH[t][1].forEach(tac => (rel(d) ? strongT : weakT).add(tac))));
    const row = d => ({ at: d.at, repeats: d.repeats || 1, flipped: !!d.flipped, system: d.source, inspector: d.inspector, area: d.area, name: d.name, tech: d.tech, conf: d.conf, note: d.note, systemId: d.systemId, systemDetailId: d.systemDetailId,
      added: counted(d.delta.added).slice(0, 12), removed: counted(d.delta.removed).slice(0, 12), more: Math.max(0, counted(d.delta.added).length - 12) + Math.max(0, counted(d.delta.removed).length - 12),
      changed: d.delta.changed.slice(0, 10) });
    return { start: w.start, end: w.items[w.items.length - 1].at, systems, relevant, level, techs, score,
      tactics: { strong: [...strongT], weak: [...weakT].filter(t => !strongT.has(t)) },
      title: titleFor(w.items, systems), reason: reasonFor([...key].sort((a, b) => CONF[b.conf] * b.weight - CONF[a.conf] * a.weight), relevant), why: whyFor(techs, relevant.length ? relevant : systems), check: checkFor(techs),
      key: once(key.sort((a, b) => CONF[b.conf] * b.weight - CONF[a.conf] * a.weight)).map(row), other: once(w.items.filter(d => !rel(d))).map(row) };
  }).filter(c => c.key.length && (c.relevant.length >= 2 || c.key.some(x => x.conf === 'Strong')))
    .sort((a, b) => b.start.localeCompare(a.start))
    .map((c, i) => ({ ...c, wid: `w${i}` }));

  // ---------- What's deployed, by capability (works for any vendor) ----------
  const live = st ? st.systems.filter(s => s.health !== 'Inactive') : (ih ? ih.rows.filter(r => r.health !== 'Inactive').map(r => ({ ...r, ...profileOf(r.inspector, r.category) })) : []);
  const tools = pred => [...new Set(live.filter(pred).map(s => s.inspector))];
  const failingTools = pred => [...new Set(live.filter(s => pred(s) && (s.health === 'Failing' || s.health === 'Stale')).map(s => s.inspector))];
  const role = re => s => re.test(s.role || '');
  const SUITE = tools(role(/Productivity suite/)), DIR = tools(role(/^Directory$/)), MFA = tools(role(/MFA|SSO/)).concat(tools(s => s.inspector === 'JumpCloud'));
  const EDR = tools(role(/EDR|MDR|Antivirus|Backup & protection/)), FW = tools(role(/Firewall/)), DNS = tools(role(/Domain & DNS/)), TRAIN = tools(role(/Security training/));
  const BACKUP = tools(s => (s.caps || []).includes('backup')), RMM = tools(role(/RMM|MDM/)), DARK = tools(role(/Dark web/)), NETDEV = tools(s => (s.caps || []).includes('network'));
  const M365 = SUITE.filter(t => /microsoft/i.test(t));
  const list = (a, none) => a.length ? names(a, 3).replace(/, (?!and)/g, ' · ') : none;
  const vis = (a, partialIf) => !a.length ? 'Blind' : partialIf ? 'Partial' : 'Visible';

  const idRows = ids => id ? id.rows.filter(r => ids.includes(r.id)) : [];
  const privNoMfa = id ? idRows(id.mfa.admins) : [];   // the same people as Identity's "Admins without MFA"
  const usersNoMfa = id ? idRows(id.mfa.users) : [];
  const fwdNow = st ? st.findings.filter(f => /external forward/i.test(f.label)) : [];
  const noEdr = cov ? cov.managed.filter(r => r.tools.edr === 'bad') : [];
  const fwdRules = signal.filter(d => d.tech.includes('T1114.003'));

  // ---------- What Liongard can see, per ATT&CK technique ----------
  // One row per technique Liongard data can speak to for *some* client. `by` is the client's own inspectors that give the evidence:
  //   Visible = Liongard data shows the exposure, or the change, directly;
  //   Partial = part of it (settings and posture, no sign-in or event logs);
  //   Blind   = this client runs no inspector that can see it. A row with no `by` is always Blind.
  const uniq = a => [...new Set(a)];
  const is = names => tools(s => names.includes(s.inspector));
  const AD = is(['Active Directory']), WIN_WS = is(['Windows Workstation']), WIN_SRV = is(['Windows Server']), MAC = is(['macOS']);
  const WIN = WIN_WS.concat(WIN_SRV), AGENTS = is(['Windows Workstation', 'Windows Server', 'macOS', 'Linux']);
  const AWS = is(['Amazon Web Services']), MERAKI = is(['Cisco Meraki']), S1 = is(['SentinelOne']);
  const SSHT = is(['macOS', 'Linux', 'Addigy', 'Domotz', 'Sophos SG']);   // inspectors with SSH status or open-port metrics
  const DISCO = tools(s => (s.caps || []).includes('monitoring')), DNSF = tools(role(/DNS filtering|Web security/)), APPCTL = tools(role(/Application control/));
  const AIP = tools(role(/AI platform/)), REG = tools(role(/Registrar|DNS & edge/)), TLS = tools(role(/Certificates/)), EXPOSE = tools(role(/External exposure|Vulnerability scanning|Public IP/));
  const failingDark = failingTools(role(/Dark web/));
  const found = re => st ? st.findings.filter(f => !f.old && re.test(f.label)) : [];
  const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
  const join = (...xs) => xs.filter(Boolean).join('. ');
  // Facts from the client's own data, shared with the Identity, Stack coverage, Email and Network pages.
  const rowsId = id ? id.rows : [];
  const staleAcc = rowsId.filter(r => r.stale && r.kind !== 'Service'), leaverAcc = rowsId.filter(r => !r.enabled && (r.otherAccess || []).length), neverAcc = rowsId.filter(r => r.enabled && r.neverExpires);
  const guests = rowsId.filter(r => r.enabled && r.kind === 'Guest'), mspAcc = rowsId.filter(r => r.enabled && r.msp), mspNoMfa = mspAcc.filter(r => r.mfa === 'NO' || r.mfaMissingIn.length);
  const builtin = rowsId.filter(r => r.enabled && /^(administrator|guest)$/i.test(r.username || ''));
  const localAcc = rowsId.flatMap(r => r.localAccounts || []);
  const darkPeople = rowsId.filter(r => r.enabled && r.darkweb.length), overdue = rowsId.filter(r => r.enabled && r.training.length);
  const tenant = id ? id.tenant : [];
  const rmmAdmins = id ? id.admins.filter(a => RMM.includes(a.inspector)) : [];
  const covRows = cov ? cov.rows.filter(r => !r.stale) : [];
  const eosWs = covRows.filter(r => r.eos && r.kind === 'Workstation'), eosSrv = covRows.filter(r => r.eos && r.kind === 'Server');
  const waiting = covRows.filter(r => r.pending > 0), hostFwOff = covRows.filter(r => r.firewall === 'bad');
  const net = ok(input.net) ? network.compute({ ...input.net, pulledOn: P, stack: input.stack }) : null;
  const netEnded = net ? net.cards.filter(c => c.rows.some(r => /subscription|security suite|support|licen[cs]e/i.test(r[0]) && r[2] === 'bad')) : [];
  const netSvcOff = net ? net.cards.filter(c => c.rows.some(r => /gateway anti|malware protection|\bips\b/i.test(r[0]) && ['bad', 'warn'].includes(r[2]))) : [];
  const drift = net ? net.firmware.filter(f => f.status === 'Drift') : [];
  const spoof = em ? em.domains.filter(d => d.spoofable) : [], unlocked = em ? em.domains.filter(d => d.lock === 'warn') : [];
  const regDue = em ? em.domains.filter(d => d.regDays != null && d.regDays <= 60) : [], oldTls = em ? em.certs.filter(c => (c.oldTls || []).length) : [];
  const exploitNote = list => list.length ? `Out-of-support OS on ${names(list.map(r => r.host), 3)}` : '';
  const EOL_F = /end of (life|os support)|unsupported operating|failed (os |software )?patch|patches? failed/i;
  const T = (t, by, status, evidence, finding, mit) => ({ t, by: uniq(by), status: uniq(by).length ? status : 'Blind', evidence, finding: uniq(by).length ? finding || '' : '', mit });
  const tier = (all, some) => all ? 'Visible' : some ? 'Partial' : 'Blind';   // two kinds of evidence: both = Visible, one = Partial
  const rows = [
    // Reconnaissance and resource development (before the attack: the client's own exposure)
    T('T1589.001', DARK, failingDark.length ? 'Partial' : 'Visible', list(DARK, 'No dark web monitoring'), failingDark.length ? 'Failing, so newly leaked credentials won’t show up' : darkPeople.length ? `${plural(darkPeople.length, 'person', 'people')} with credentials found on the dark web` : '', ['M1056']),
    T('T1584.001', DNS.concat(REG), 'Partial', DNS.length || REG.length ? `${list(DNS.concat(REG))} (registrar, expiry date and transfer lock; not the registrar account’s own MFA)` : 'Needs the Internet Domain/DNS inspector', em ? join(unlocked.length && `${plural(unlocked.length, 'domain')} without a registrar transfer lock`, regDue.length && `${plural(regDue.length, 'domain')} renewing within 60 days`) : '', ['M1056']),
    // Initial access
    T('T1566', DNS.concat(TRAIN), tier(DNS.length && TRAIN.length, DNS.length || TRAIN.length), list(DNS.concat(TRAIN), 'No DNS or security-training inspector'), em ? `${em.domains.filter(d => d.dmarc[0] !== 'pass').length} of ${em.domains.length} domains don’t enforce DMARC` : '', ['M1054', 'M1017']),
    T('T1133', FW.concat(WIN_SRV), 'Partial', `${list(FW.concat(WIN_SRV), 'No firewall or Windows Server inspector')} (VPN, NAT and port-forward rules, RDP settings; no sign-in logs)`, noEdr.length ? `No EDR on ${names(noEdr.map(r => r.host))}` : '', ['M1032', 'M1035']),
    T('T1190', FW.concat(EXPOSE), 'Partial', `${list(uniq(FW.concat(EXPOSE)), 'Needs a firewall or external-exposure inspector')} (firmware, support and security-subscription dates; no vulnerability matching)`, join(netEnded.length && `Support or subscription ended on ${names(netEnded.map(c => c.site || c.name), 3)}`, drift.length && `Firmware drift on ${names(drift.map(f => f.model), 3)}`), ['M1051', 'M1016', 'M1035']),
    T('T1189', DNSF.concat(WIN), 'Partial', `${list(DNSF.concat(WIN), 'No DNS filtering or Windows agent inspector')} (whether DNS filtering is deployed; not what users browsed)`, '', ['M1021', 'M1051']),
    T('T1199', SUITE.concat(DIR), 'Partial', `${list(SUITE.concat(DIR), 'Needs a directory or productivity suite')} (guest and MSP accounts; not what a partner did with them)`, id ? join(guests.length && plural(guests.length, 'guest account'), mspAcc.length ? `${plural(mspAcc.length, 'MSP account')}${mspNoMfa.length ? `, ${mspNoMfa.length} without MFA` : ''}` : !(input.msp && ((input.msp.domains || []).length || (input.msp.names || []).length)) && 'Set your MSP’s domains on the Identity page to see your own accounts') : '', ['M1032', 'M1018']),
    T('T1200', DISCO, 'Partial', `${list(DISCO, 'No discovery or network-monitoring inspector')} (devices on the network at each scan; not the moment one was plugged in)`, cov && cov.unmanaged.length ? `${plural(cov.unmanaged.length, 'computer')} on the network with no RMM, EDR or agent` : '', ['M1035', 'M1034']),
    T('T1669', MERAKI, 'Partial', MERAKI.length ? 'Cisco Meraki SSIDs with weak encryption or no pre-shared key' : tools(role(/Wi-Fi/)).length ? `${list(tools(role(/Wi-Fi/)))} report Wi-Fi devices but not how each network is secured` : 'Needs Cisco Meraki (SSID security)', '', ['M1041', 'M1030']),
    T('T1078.001', AD.concat(WIN_WS, AWS), 'Partial', `${list(AD.concat(WIN_WS, AWS), 'Needs Active Directory, the Windows Workstation agent or AWS')} (built-in Administrator and Guest, AWS root keys; not network devices’ factory accounts)`, join(builtin.length && `Built-in account${builtin.length > 1 ? 's' : ''} enabled: ${names(builtin.map(r => r.username))}`, ...found(/default (administrator|guest) account enabled/i).map(f => `${f.label} (${f.inspector})`)), ['M1027', 'M1032']),
    T('T1078.002', DIR, 'Visible', list(DIR, 'No directory inspector'), !id ? 'No identity data' : join(privNoMfa.length ? `${plural(privNoMfa.length, 'privileged account')} with no MFA` : 'Every privileged account has MFA', staleAcc.length && `${staleAcc.length} stale`, leaverAcc.length && `${leaverAcc.length} disabled but still present elsewhere`, neverAcc.length && `${neverAcc.length} with passwords that never expire`), ['M1032', 'M1026']),
    T('T1078.003', WIN_WS, 'Partial', WIN_WS.length ? 'Windows Workstation agent (local user list on each device; local admin rights aren’t reported)' : 'Needs the Liongard Windows Workstation agent', localAcc.length ? `${plural(localAcc.length, 'local account')} matched to people` : '', ['M1026', 'M1027']),
    T('T1078.004', SUITE.concat(MFA, AWS), SUITE.length ? 'Visible' : 'Partial', list(SUITE.concat(MFA, AWS), 'No cloud identity inspector'), id ? `MFA everywhere for ${(id.kpis.find(k => k.k === 'MFA everywhere') || {}).v} of people` : '', ['M1032', 'M1026']),
    // Execution
    T('T1203', WIN_WS.concat(MAC, RMM, AD), 'Partial', `${list(uniq(WIN_WS.concat(MAC, RMM, AD)), 'Needs an RMM, Liongard agent or Active Directory')} (OS support dates, waiting and failed patches; no vulnerability matching)`, join(exploitNote(eosWs), waiting.length && `${plural(waiting.length, 'device')} with updates waiting`), ['M1051', 'M1050']),
    T('T1204', TRAIN.concat(APPCTL), 'Partial', `${list(TRAIN.concat(APPCTL), 'No security-training or application-control inspector')} (training and phishing results, allow-listing in place)`, overdue.length ? `${plural(overdue.length, 'person', 'people')} with overdue training` : '', ['M1017', 'M1038']),
    T('T1072', RMM, 'Partial', `${list(RMM, 'No RMM inspector')} (who can administer the RMM; not the scripts it runs)`, rmmAdmins.length ? `${plural(rmmAdmins.reduce((s, a) => s + a.admins.length, 0), 'admin')} across ${list(uniq(rmmAdmins.map(a => a.inspector)))}` : '', ['M1026', 'M1032', 'M1018']),
    // Persistence and privilege escalation
    T('T1098', DIR.concat(SUITE, MFA), tier(DIR.length && SUITE.length, DIR.length || SUITE.length || MFA.length), list(DIR.concat(SUITE, MFA), 'Needs a directory, productivity suite or MFA inspector'), '', ['M1026', 'M1032']),
    T('T1098.001', AWS.concat(AIP, S1), 'Partial', `${list(AWS.concat(AIP, S1), 'Needs AWS, an AI platform or SentinelOne')} (API keys and tokens: who made them and how old they are; not Entra app secrets)`, '', ['M1026', 'M1032']),
    T('T1098.003', SUITE, 'Visible', list(SUITE, 'Needs Microsoft 365 or Google Workspace'), '', ['M1026', 'M1032']),
    T('T1136.001', WIN_WS, 'Partial', WIN_WS.length ? 'Windows Workstation agent (new names in each device’s local user list)' : 'Needs the Liongard Windows Workstation agent', '', ['M1032', 'M1026']),
    T('T1136.002', DIR, 'Visible', list(DIR, 'Needs Active Directory or another directory inspector'), '', ['M1026', 'M1032']),
    T('T1136.003', SUITE.concat(MFA), SUITE.length ? 'Visible' : 'Partial', list(SUITE.concat(MFA), 'Needs Microsoft 365, Google Workspace or an MFA/SSO inspector'), '', ['M1026', 'M1032']),
    T('T1068', AGENTS.concat(RMM), 'Partial', `${list(uniq(AGENTS.concat(RMM)), 'Needs an RMM or a Liongard agent')} (OS support dates and patch state; no vulnerability matching)`, join(exploitNote(eosWs.concat(eosSrv)), ...found(EOL_F).slice(0, 2).map(f => `${f.label}: ${f.value} (${f.inspector})`)), ['M1051', 'M1050']),
    // Stealth
    T('T1036', RMM.length && DIR.length ? RMM.concat(DIR) : [], 'Partial', RMM.length && DIR.length ? 'Device names across RMM, directory and monitoring' : 'Needs both an RMM and a directory inspector to compare device names', '', ['M1047']),
    T('T1564.008', M365, 'Partial', M365.length ? 'Microsoft 365 mailbox rules' : 'Needs Microsoft 365', '', ['M1047']),
    T('T1684.002', DNS, 'Visible', DNS.length ? `${list(DNS)} (SPF, DKIM and DMARC on every domain)` : 'Needs the Internet Domain/DNS inspector', em ? `${spoof.length} of ${em.domains.length} domains can be spoofed${spoof.length ? `: ${names(spoof.map(d => d.name), 3)}` : ''}` : '', ['M1054']),
    // Defense impairment
    T('T1556.006', MFA.concat(SUITE), tier(MFA.length && SUITE.length, MFA.length || SUITE.length), list(MFA.concat(SUITE), 'Needs an MFA/SSO inspector or a productivity suite'), id ? (id.bypass.length ? `${plural(id.bypass.length, 'Duo bypass code')}, longest valid ${Math.max(...id.bypass.map(b => b.daysLeft || 0))} days` : '') : '', ['M1032', 'M1047']),
    T('T1556.009', M365, 'Visible', M365.length ? 'Microsoft 365 (conditional access policy list and security defaults; changes show in Liongard detections)' : 'Needs Microsoft 365', tenant.map(x => `${x.t}: ${x.v}`).join(' · '), ['M1018']),
    T('T1484.001', AD, 'Visible', AD.length ? `${list(AD)} (GPO modification times)` : 'Needs Active Directory', '', ['M1047', 'M1018']),
    T('T1685', EDR, 'Visible', list(EDR, 'No EDR or antivirus inspector'), noEdr.length ? `${plural(noEdr.length, 'managed endpoint')} with no EDR` : '', ['M1018', 'M1047']),
    T('T1686.002', FW, 'Visible', list(FW, 'No firewall inspector'), netSvcOff.length ? `Security service off or not active on ${names(netSvcOff.map(c => c.site || c.name), 3)}` : '', ['M1018', 'M1047', 'M1051']),
    T('T1686.003', WIN, 'Visible', WIN.length ? 'Windows agents (Windows Firewall state per profile: domain, private, public)' : 'Needs the Liongard Windows Workstation or Server agent', cov ? (hostFwOff.length ? `Windows Firewall off on a profile on ${names(hostFwOff.map(r => r.host), 3)}` : '') : '', ['M1018', 'M1047']),
    T('T1601', NETDEV, 'Partial', list(NETDEV.slice(0, 5), 'No network-device inspector') + ' (firmware versions)', drift.length ? `${plural(drift.length, 'model')} running more than one firmware version` : '', ['M1046', 'M1045']),
    T('T1689', TLS, 'Partial', TLS.length ? 'TLS/SSL (protocol versions each site still accepts)' : 'Needs the TLS/SSL inspector', em ? (oldTls.length ? `TLS 1.0 or 1.1 still on ${names(oldTls.map(c => c.name), 3)}` : '') : '', ['M1054', 'M1042']),
    // Credential access
    T('T1110', DIR.concat(FW), 'Partial', `${list(DIR.concat(FW), 'Needs a directory or firewall inspector')} (lockout and login-attempt settings, no sign-in logs)`, '', ['M1027', 'M1036']),
    T('T1110.004', DARK, 'Partial', DARK.length ? `${list(DARK)} (breached passwords for the client’s people; not the attempts)` : 'No dark web monitoring', failingDark.length ? 'Failing, so newly breached passwords won’t show up' : '', ['M1027', 'M1032']),
    // Lateral movement
    T('T1021.001', WIN, 'Partial', WIN.length ? 'Windows agents (RDP enabled) and the AD Remote Desktop Users group' : 'Needs the Liongard Windows Workstation or Server agent', '', ['M1032', 'M1035']),
    T('T1021.004', SSHT, 'Partial', SSHT.length ? `${list(SSHT)} (SSH enabled or port 22 open)` : 'Needs the macOS or Linux agent, Addigy, Domotz or Sophos SG', '', ['M1042', 'M1032']),
    T('T1021.005', MAC, 'Partial', MAC.length ? 'macOS agent (Remote Management / screen sharing status)' : 'Needs the Liongard macOS agent', '', ['M1042', 'M1047']),
    T('T1210', WIN_SRV.concat(AD), 'Partial', `${list(WIN_SRV.concat(AD), 'Needs the Windows Server agent or Active Directory')} (server OS support, named CVE checks such as CVE-2024-49113; no full vulnerability scan)`, exploitNote(eosSrv), ['M1051', 'M1042', 'M1016']),
    T('T1091', WIN_WS, 'Partial', WIN_WS.length ? 'Windows Workstation agent (external USB devices seen on each device)' : 'Needs the Liongard Windows Workstation agent', '', ['M1042', 'M1034']),
    // Collection, exfiltration and impact
    T('T1114.003', SUITE, 'Visible', SUITE.length ? `${list(SUITE)} forwarding rules` : 'Needs Microsoft 365 or Google Workspace', fwdRules.length ? `${plural(fwdRules.length, 'new forwarding rule')} in 90 days, latest ${fmtD(fwdRules[fwdRules.length - 1].at)}` : '', ['M1047']),
    T('T1052.001', WIN_WS, 'Partial', WIN_WS.length ? 'Windows Workstation agent (external USB devices; not what was copied)' : 'Needs the Liongard Windows Workstation agent', '', ['M1034', 'M1057']),
    T('T1490', BACKUP, 'Visible', list(BACKUP, 'No backup inspector deployed'), '', ['M1053']),
    T('T1486', BACKUP, 'Partial', BACKUP.length ? `${list(BACKUP)} (whether you could recover: backup success and recency; the encryption itself shows only as EDR threats)` : 'No backup inspector deployed', '', ['M1053', 'M1040']),
    T('T1485', BACKUP, 'Partial', BACKUP.length ? `${list(BACKUP)} (whether you could recover; not the deletion)` : 'No backup inspector deployed', '', ['M1053']),
  ];
  // Techniques a Liongard change can be classified as (the rules above), so the table can say "changes are watched".
  const DETECTS = new Set([...RULES.flatMap(r => r[1]), ...WEAKEN.map(w => w[2]), 'T1114.003', 'T1564.008', 'T1098', 'T1078.004', 'T1484.001', 'T1556.006', 'T1684.002', 'T1686.003', 'T1685']);
  const tacIdx = k => TACTICS.findIndex(x => x[0] === k);
  const cover = rows.map(r => ({ ...r, name: TECH[r.t][0], tactics: TECH[r.t][1], tactic: [...TECH[r.t][1]].sort((a, b) => tacIdx(a) - tacIdx(b))[0],
    detects: DETECTS.has(r.t), changes: signal.filter(d => rel(d) && d.tech.includes(r.t)).length, mit: r.mit.map(m => ({ id: m, name: MITIGATIONS[m] })) }))
    .sort((a, b) => tacIdx(a.tactic) - tacIdx(b.tactic));
  const countBy = list => ({ n: list.length, Visible: list.filter(r => r.status === 'Visible').length, Partial: list.filter(r => r.status === 'Partial').length, Blind: list.filter(r => r.status === 'Blind').length });
  const coverSummary = { ...countBy(cover), evidenced: cover.filter(r => r.status !== 'Blind').length, attackTotal: ATTACK_TOTAL, version: ATTACK_VERSION };
  // ATT&CK counts a technique under every tactic it serves; so does this.
  const coverTactics = TACTICS.map(([k, name, tid]) => ({ k, name, id: tid, ...countBy(cover.filter(r => r.tactics.includes(k))) }));

  // ---------- Posture right now ----------
  const F = re => st ? st.findings.filter(f => !f.old && re.test(f.label)) : [];   // current evidence only; older findings are listed separately
  // One line per system (for tiles that count systems), with every finding on that system.
  const bySystem = list => [...new Set(list.map(f => f.system))].map(sys => { const g = list.filter(f => f.system === sys); return { ...ref(g[0]), sub: g.map(f => `${f.label}: ${f.value}`).join(' · '), list: g.flatMap(f => f.list || []) }; });
  const ref = f => ({ t: f.system, sub: `${f.label}: ${f.value}`, systemId: f.systemId, systemDetailId: f.systemDetailId, lpId: f.lpId, inspectorId: f.inspectorId, inspector: f.inspector, list: f.list });
  const posture = [];
  const SEC_F = /mfa|2fa|admin|threat|malware|virus|infect|encrypt|bitlocker|forward|breach|dark web|patch|firewall|edr|unprotected|exposure/i;
  // "Non-Admin Users with MFA Disabled" is about users, not admins.
  const ADMIN_MFA = /(?<!non-?\s?)admin.*(mfa|2fa)|(mfa|2fa).*(?<!non-?\s?)admin/i;
  // Fail closed: a tile whose source couldn't be read is "no evidence" (grey, —), never a green all-clear.
  const noMetrics = !st && 'No Liongard metric data for this client (couldn’t read it, or none collected yet)';
  const NO = { threats: noMetrics, encrypt: noMetrics, patch: noMetrics, dark: noMetrics, fwd: noMetrics,
    privmfa: !id && 'Couldn’t read identity data from Liongard', mfa: !id && 'Couldn’t read identity data from Liongard',
    edr: !cov && 'Couldn’t read device coverage from Liongard', alerts: !Array.isArray(input.alerts) && 'Couldn’t read alerts from Liongard',
    blind: !st && !ih && 'Couldn’t read inspector health' };
  // Not covered: no tool of that kind is connected for this client, so a zero would be silence, not an all-clear.
  // Only checked when the metric data was read (otherwise NO already says "couldn't read").
  const AGENT = tools(s => /^Windows (Workstation|Server)$|^macOS$/.test(s.inspector || ''));
  const NONE = st ? {
    threats: !EDR.length && 'Not covered: no EDR or antivirus tool is connected for this client',
    edr: !EDR.length && 'Not covered: no EDR or antivirus tool is connected for this client',
    patch: !RMM.length && !EDR.length && !AGENT.length && 'Not covered: no RMM, endpoint or Liongard agent reports patching for this client',
    encrypt: !RMM.length && !EDR.length && !AGENT.length && 'Not covered: no RMM, endpoint or Liongard agent reports disk encryption for this client',
    dark: !DARK.length && 'Not covered: no dark web monitoring is connected for this client',
    fwd: !SUITE.length && 'Not covered: no Microsoft 365 or Google Workspace is connected for this client',
    privmfa: !SUITE.length && !DIR.length && !MFA.length && 'Not covered: no directory, productivity suite or MFA tool is connected for this client',
    mfa: !SUITE.length && !DIR.length && !MFA.length && 'Not covered: no directory, productivity suite or MFA tool is connected for this client',
  } : {};
  const add = (key, title, sev, count, detail, items, page) => posture.push(NO[key]
    ? { key, title, sev: 'none', count: null, detail: NO[key], items: [], page, unknown: true }
    : NONE[key] && !count ? { key, title, sev: 'none', count: null, detail: NONE[key], items: [], page: 'stack', unknown: true, notCovered: true }
    : { key, title, sev: count ? sev : 'ok', count, detail: count ? detail : detailOk[key], items: items || [], page });
  const detailOk = { threats: 'No active threats reported by the security tools', privmfa: 'Every privileged account has MFA', mfa: 'No users without MFA reported', fwd: 'No external forwarding rules', edr: 'Every managed endpoint has EDR', patch: 'No failed or missing patches reported', encrypt: 'No unencrypted drives reported', alerts: 'No open security alerts', dark: 'No exposed credentials reported', blind: 'Every security inspector is returning data' };
  const threats = F(/threat|infect|compromis|incident|ransom|malware (detected|found)/i).filter(f => f.sev === 'bad' && !/quarantin|without|enabled|protection|polic/i.test(f.label));
  add('threats', 'Active threats', 'bad', threats.reduce((s, f) => s + (+f.value || 1), 0), names(threats.map(f => `${f.value} on ${f.inspector}`)), threats.map(ref), 'stack');
  // MFA: the people Identity names. Counts a tool reports without names are shown, not added.
  const toolMfa = admin => (id ? id.mfa.tools : []).filter(f => f.admin === admin);
  const toolLine = admin => toolMfa(admin).length ? `Tools’ own counts (all account types): ${toolMfa(admin).map(f => `${f.inspector} ${f.n}`).join(', ')}` : '';
  const toolRefs = admin => toolMfa(admin).map(f => ({ t: f.system, sub: `${f.label}: ${f.n} (the tool’s own count, not added)`, systemId: f.systemId, systemDetailId: f.systemDetailId }));
  add('privmfa', 'Admins without MFA', 'bad', privNoMfa.length, [names(privNoMfa.map(r => r.name)), toolLine(true)].filter(Boolean).join('. '), privNoMfa.map(r => ({ t: r.name, sub: r.mfaMissingIn.length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : r.email, identityId: r.id })).concat(toolRefs(true)), 'identity');
  add('mfa', 'Users without MFA', 'warn', usersNoMfa.length, [names(usersNoMfa.map(r => r.name)), toolLine(false)].filter(Boolean).join('. '), usersNoMfa.map(r => ({ t: r.name, sub: r.mfaMissingIn.length ? `No MFA in ${r.mfaMissingIn.join(', ')}` : r.email, identityId: r.id })).concat(toolRefs(false)), 'identity');
  add('fwd', 'External mail forwarding', 'bad', fwdNow.reduce((s, f) => s + (+f.value || 1), 0), names(fwdNow.map(f => `${f.value} rule${+f.value > 1 ? 's' : ''} in ${f.inspector}`)), fwdNow.map(ref), 'identity');
  add('edr', 'Endpoints without EDR', 'bad', noEdr.length, names(noEdr.map(r => r.host)), noEdr.map(r => ({ t: r.host, sub: r.os, deviceId: r.id })), 'coverage');
  const patch = F(/failed patch|missing .*update|patches? failed/i);
  const patchSys = [...new Set(patch.map(f => f.system))];
  add('patch', 'Systems with failed or missing patches', 'warn', patchSys.length, names(patchSys), bySystem(patch), 'coverage');
  const enc = F(SIGNALS.encrypt);
  add('encrypt', 'Disk encryption off', 'warn', new Set(enc.map(f => f.system)).size, names([...new Set(enc.map(f => f.system))]), bySystem(enc), 'coverage');
  const openSec = alerts.filter(a => !/clos|resolv|complete|silenc/i.test(a.status || '') && SEC.test(`${a.name} ${a.inspector}`)).sort((a, b) => String(b.created).localeCompare(String(a.created)));
  add('alerts', 'Open security alerts', 'warn', openSec.length, names(openSec.map(a => short(a.name)), 2), openSec.slice(0, 25).map(a => ({ t: short(a.name), sub: `${a.priority || ''} · ${fmtD(a.created)}`, alertId: a.id })), 'wallboard');
  const dark = F(/breach|stealer|exposure/i).filter(f => /dark web/i.test(f.inspector));
  // Dark web tools report several overlapping counts (sources, users, breaches): take the largest per system, don't add them up.
  const darkN = [...new Set(dark.map(f => f.systemId))].reduce((s, sid) => s + Math.max(...dark.filter(f => f.systemId === sid).map(f => +f.value || 1)), 0);
  add('dark', 'Exposed credentials', 'bad', darkN, `Up to ${darkN} exposed record${darkN === 1 ? '' : 's'} found by ${[...new Set(dark.map(f => f.inspector))].join(', ')}`, dark.map(ref), 'identity');
  const secBlind = live.filter(s => (s.caps || []).some(c => ['security', 'identity'].includes(c)) && (s.health === 'Failing' || s.health === 'Stale'));
  add('blind', 'Security tools not reporting', 'warn', secBlind.length, names(secBlind.map(s => s.inspector)), secBlind.map(s => ({ t: s.name, sub: `${s.inspector} · ${s.health}${s.why ? `: ${s.why}` : ''}`, systemId: s.systemId, systemDetailId: s.systemDetailId, lpId: s.lpId, inspectorId: s.inspectorId })), 'inspectors');

  // Data issues: changes that flip back and forth usually mean an inspector sees two tenants or a sync problem.
  const flipPairs = [...new Set(flip.map(d => `${d.source}\u0000${d.name}`))].map(k => { const [system, name] = k.split('\u0000'); const g = flip.filter(d => d.source === system && d.name === name); return { system, name, count: g.length, systemId: g[0].systemId, systemDetailId: g[g.length - 1].systemDetailId }; });

  const last7 = once(signal.filter(d => (now - new Date(d.at)) / 864e5 <= 7 && rel(d)).map(d => ({ ...d })));
  const order = { High: 0, Elevated: 1, Low: 2 };
  const top = [...clusters].sort((a, b) => order[a.level] - order[b.level] || b.score - a.score)[0];
  const n = l => clusters.filter(c => c.level === l).length;
  const bad = posture.filter(p => p.sev === 'bad'), warn = posture.filter(p => p.sev === 'warn');
  const blindT = cover.filter(c => c.status === 'Blind');

  const summary = [
    bad.length ? `${bad.length} exposure${bad.length > 1 ? 's' : ''} need action now: ${bad.map(p => `${p.title.replace(/^./, c => c.toLowerCase()).replace(/\b(Mfa|Edr)\b/gi, w => w.toUpperCase())} (${p.count})`).join(', ')}.` : posture.some(p => p.unknown) ? 'No urgent exposures found by the tools Liongard can read.' : 'No urgent exposures right now.',
    posture.some(p => p.notCovered) ? `Not covered, because no tool of that kind is connected: ${posture.filter(p => p.notCovered).map(p => p.title.replace(/^./, c => c.toLowerCase()).replace(/\b(Mfa|Edr)\b/gi, w => w.toUpperCase())).join(', ')}.` : '',
    top ? `${top.level === 'Low' ? 'Highest' : `${top.level}-risk`} change window ${fmtD(top.start)}: ${top.reason}.` : 'No correlated security changes in 90 days.',
    `Liongard evidences ${coverSummary.evidenced} of ${cover.length} mapped attack techniques for this client (${coverSummary.Visible} visible, ${coverSummary.Partial} partly)${blindT.length ? ` and can’t see ${blindT.length}` : ''}. ATT&CK Enterprise v${ATTACK_VERSION} has ${ATTACK_TOTAL} techniques and sub-techniques in all; most need endpoint or log telemetry Liongard doesn’t collect.`,
    flipPairs.length ? `${flipPairs.length} setting${flipPairs.length > 1 ? 's keep' : ' keeps'} flipping back and forth, which usually means an inspector problem.` : '',
  ].filter(Boolean);

  // The exact changes behind the 7-day tile, so its drill-down lists the same ones.
  const recent = last7.map(d => ({ system: d.source, name: d.name, at: d.at, conf: d.conf, tech: d.tech || [], note: d.note, systemId: d.systemId, systemDetailId: d.systemDetailId }));
  // Findings from evidence older than two weeks, or from inspectors that stopped reporting: listed, not counted as "now".
  const older = st ? st.findings.filter(f => f.old && f.sev === 'bad' && SEC_F.test(`${f.label} ${f.inspector}`)).map(f => ({ ...ref(f), age: f.age, health: f.health })) : [];
  return {
    recent, older,
    environment: input.environment, pulledOn: P, source: input.source, windowDays: changes.WINDOW_DAYS, summary,
    kpis: [
      { k: 'Exposures now', v: bad.length + warn.length, s: [bad.length ? `${bad.length} need action now` : warn.length ? 'To review' : 'None found', posture.some(p => p.unknown && !p.notCovered) ? `${posture.filter(p => p.unknown && !p.notCovered).length} couldn’t be checked` : '', posture.some(p => p.notCovered) ? `${posture.filter(p => p.notCovered).length} not covered` : ''].filter(Boolean).join(' · '), sev: bad.length ? 'bad' : warn.length ? 'warn' : 'ok' },
      { k: 'Changes to review, 7 days', v: last7.length, s: last7.length ? `${last7.filter(d => d.conf === 'Strong').length} strong match${last7.filter(d => d.conf === 'Strong').length === 1 ? '' : 'es'}` : 'Quiet week', sev: last7.some(d => d.conf === 'Strong') ? 'bad' : last7.length ? 'warn' : 'ok' },
      { k: `Highest in ${changes.WINDOW_DAYS} days`, v: top ? top.level : 'None', s: top ? `${fmtD(top.start)} · ${n('High')} high, ${n('Elevated')} elevated` : 'No correlated windows', sev: top ? (top.level === 'High' ? 'bad' : top.level === 'Elevated' ? 'warn' : 'info') : 'ok' },
      { k: 'Techniques Liongard can’t see', v: blindT.length, s: `of ${cover.length} mapped${cover.length - blindT.length - cover.filter(c => c.status === 'Visible').length ? `, ${cover.length - blindT.length - cover.filter(c => c.status === 'Visible').length} only partly visible` : ''}`, sev: blindT.length ? 'bad' : 'ok' },
      { k: 'Noise set aside', v: flipPairs.length, s: `flip-flopping setting${flipPairs.length === 1 ? '' : 's'}; ${quiet.length} counter or recurring change${quiet.length === 1 ? '' : 's'} also set aside`, sev: 'info' },
    ],
    posture, areas: AREAS, clusters, flipPairs,
    dots: signal.filter(d => d.conf !== 'None').map(d => ({ at: d.at, area: d.area, conf: d.conf, label: `${fmtD(d.at)} · ${d.source} · ${d.name}`, wid: (clusters.find(c => d.at >= c.start && d.at <= c.end) || {}).wid || null })),
    cover, coverSummary, coverTactics, tacticsList: TACTICS,
  };
}

function titleFor(items, systems) {
  const top = [...items].sort((a, b) => b.weight * CONF[b.conf] - a.weight * CONF[a.conf])[0];
  return systems.length > 1 ? `${short(top.name)} and ${items.length - 1} more change${items.length > 2 ? 's' : ''} across ${systems.length} systems` : short(top.name);
}
function reasonFor(key, relevant) {
  const what = [...new Set(key.map(d => d.tech[0] ? TECH[d.tech[0]][0].replace(/^.*?: /, '') : short(d.name)))].slice(0, 3).map(s => s.toLowerCase());
  return `${what.join(', ')}${relevant.length > 1 ? ` across ${relevant.length} systems` : ` on ${relevant[0]}`}`;
}
function short(n) { return String(n).replace(/^[^|:]+[|:]\s*/, '').replace(/\s*\|\s*/g, ': '); }
function whyFor(techs, systems) {
  const bits = [];
  if (techs.includes('T1114.003')) bits.push('Mail forwarding to an outside address is one of the first things an attacker sets up after taking over a mailbox (T1114.003).');
  if (techs.includes('T1484.001')) bits.push('Changing domain policy (T1484.001) can push settings to every machine.');
  if (techs.includes('T1098')) bits.push('Changes to admin accounts or roles (T1098) are how access is kept.');
  if (techs.includes('T1556.006')) bits.push('MFA changes or bypass codes (T1556.006) can open a way around MFA.');
  if (techs.includes('T1110')) bits.push('Raising login-attempt limits or weakening password rules (T1110) makes brute-force attacks easier.');
  const fwT = techs.filter(t => /^T1686|^T1685$/.test(t));
  if (fwT.length) bits.push(`Weakening a firewall or security tool (${fwT.join(', ')}) reduces what would catch the next step.`);
  if (techs.includes('T1556.009')) bits.push('Conditional access changes (T1556.009) can quietly exempt an account from MFA or location checks.');
  if (techs.includes('T1098.001')) bits.push('A new API key or token (T1098.001) keeps working after a password reset.');
  if (techs.includes('T1136.001')) bits.push('A new local account (T1136.001) sits outside the directory and its MFA.');
  if (techs.includes('T1199')) bits.push('A new guest account (T1199) gives an outside organisation a way in.');
  if (techs.includes('T1133')) bits.push('A new port forward, VPN or remote-access rule (T1133) opens a way in from the internet.');
  const remote = techs.filter(t => /^T1078\.001|^T1021\./.test(t));
  if (remote.length) bits.push(`Turning on built-in accounts or remote access (${remote.join(', ')}) widens the ways in.`);
  if (techs.includes('T1684.002')) bits.push('Weaker SPF or DMARC (T1684.002) lets others send mail as this client.');
  if (techs.includes('T1584.001')) bits.push('Name-server or registrar changes (T1584.001) are how domains are hijacked.');
  if (techs.includes('T1669') || techs.includes('T1689')) bits.push('Weaker Wi-Fi or TLS settings (T1669, T1689) make it easier to listen in.');
  if (systems.length > 1) bits.push(`${systems.length} systems changed within 24 hours, which is worth matching to a change ticket.`);
  return bits.join(' ') || 'Several systems changed close together. Usually planned work, but worth matching to a change record.';
}
function checkFor(techs) {
  const c = [];
  if (techs.includes('T1114.003')) c.push('Confirm who created the forwarding rule and whether the destination address is approved. If not, remove it, reset the user’s password and revoke sessions');
  if (techs.includes('T1484.001')) c.push('Confirm who edited the GPOs and what settings changed');
  if (techs.includes('T1098')) c.push('Confirm any new or changed admin accounts are known and approved');
  if (techs.includes('T1556.006')) c.push('Confirm MFA and bypass-code changes were requested');
  if (techs.includes('T1110')) c.push('Put login-attempt and password limits back unless the change was approved');
  if (techs.some(t => /^T1686|^T1685$/.test(t))) c.push('Check the firewall or security tool’s admin log for who made the change');
  if (techs.includes('T1556.009')) c.push('Compare conditional access with the last approved set: look for new exclusions, or policies switched off or to report-only');
  if (techs.includes('T1098.001')) c.push('Confirm who created each new API key or token, and revoke any nobody asked for');
  if (techs.includes('T1136.001')) c.push('Confirm each new local account is expected; remove it if not');
  if (techs.includes('T1199')) c.push('Confirm each new guest was invited for a reason and has an expiry');
  if (techs.includes('T1133')) c.push('Confirm the new remote-access rule was requested and is limited to known addresses');
  if (techs.some(t => /^T1078\.001|^T1021\./.test(t))) c.push('Turn the built-in account or remote-access setting back off unless it was approved');
  if (techs.includes('T1684.002')) c.push('Put the SPF or DMARC record back to its stricter setting');
  if (techs.includes('T1584.001')) c.push('Confirm the registrar or name-server change with the domain owner, and that the registrar account has MFA');
  c.push('Match the window to a change ticket or planned work');
  return c;
}
function fmtD(iso) { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' }); }

module.exports = { id: 'cyber', collect, compute, usesStack: true, delta, weakenings, classify, SEC };
